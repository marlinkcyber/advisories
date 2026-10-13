# Linux kernel: ppp_async Frame-Error Path Resets skb Headroom leading to Remote Kernel Panic (Denial of Service)

- **Advisory ID:** MCSAID-2026-009
- **CVE ID:** [CVE-2026-98158](https://www.cve.org/CVERecord?id=CVE-2026-98158)
- **Reported:** 2026-09-02
- **Published:** 2026-10-13
- **Severity:** Medium (CVSS 5.3 – CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **Vulnerability type:** Buffer underwrite (`skb_under_panic`), Out-of-bounds read, Denial of Service (DoS), Kernel panic
- **Current state:** Fix released in Linux kernel stable trees (5.10.271, 5.15.222, 6.1.189, 6.6.158, 6.12.111, 6.18.53, 7.2.7) and mainline 7.3-rc3
- **Exploitation:** Easy, deterministic, two frames from the PPP peer, not seen in the wild
- **Software:** [Linux kernel](https://www.kernel.org/) – PPP (`drivers/net/ppp/ppp_async.c`)
- **CWE:** [CWE-124: Buffer Underwrite ('Buffer Underflow')](https://cwe.mitre.org/data/definitions/124.html), [CWE-125: Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

The frame-error path in `process_input_packet()` in `ppp_async` resets a reused socket buffer's headroom to zero, while claiming to restore it to a freshly allocated state. A fresh skb from `dev_alloc_skb()` carries `NET_SKB_PAD` of headroom, and the rest of the PPP receive path relies on it.

Because `ap->rpkt` keeps pointing at that skb, the next frame is reassembled into it with no headroom at all. A PPP peer that sends a frame with a bad FCS followed by a frame beginning `ff 03` with a PFC-compressed protocol byte leaves only one byte of headroom by the time `ppp_receive_nonmp_frame()` pushes the two-byte `PPP_FILTER_INBOUND_TAG`. The push lands one byte below `skb->head`, triggering `skb_under_panic()` and a kernel panic in softirq context.

The same headroom reset also causes an out-of-bounds read before `skb->head` when CCP compression is enabled, because `ppp_decompress_frame()` hands `skb->data - 2` to the decompressor.

---

## Affected Versions

| Version | Status |
|---------|--------|
| Linux kernel 2.6.15 and later, prior to the fixed releases below | Vulnerable |
| 5.10.271, 5.15.222, 6.1.189, 6.6.158, 6.12.111, 6.18.53, 7.2.7 and later in each stable series | Fixed |
| 7.3-rc3 and later | Fixed |

Reproduced on pristine Linux v7.2.2.

The flaw was introduced by commit `6722e78c9005` ("[PPP]: handle misaligned accesses").

---

## Impact

A PPP peer can crash the whole machine with two crafted frames. The panic happens in softirq context (`ppp_async_process` tasklet), so it takes down the host rather than just the link.

Exploitation requires:

- a kernel built with `CONFIG_PPP_FILTER`;
- an asynchronous PPP link (`ppp_async`, e.g. serial, modem or pty) with a pass or active filter applied (`PPPIOCSPASS` / `PPPIOCSACTIVE`). This is what `pppd` does for demand-dialling and for the `active-filter` option.

Configuring the link requires root, but the frames that trigger the crash come from the tty side, i.e. from the remote peer. On a configured link this is therefore reachable remotely by the peer, not a local privilege escalation.

When CCP compression is enabled, the same zeroed headroom also causes the decompressor to read before `skb->head` (out-of-bounds read).

---

## Exploitation

The peer sends two frames:

1. **Frame 1 – bad FCS.** `process_input_packet()` takes its `err:` path, trims the skb and sets its headroom to zero, and leaves it in `ap->rpkt` for reuse.
2. **Frame 2 – starts `ff 03`, followed by a PFC-compressed odd protocol byte (`0x21`, PPP_IP).**
   - The frame starts with `0xff` (`PPP_ALLSTATIONS`), so `ppp_async_input()` reserves no headroom.
   - `process_input_packet()` pulls the two-byte address/control field → headroom 2.
   - `__ppp_decompress_proto()` pushes one byte back for the compressed protocol → headroom 1.
   - `PPP_IP` maps to a real NP index, so the filter branch runs and pushes 2 bytes → one byte below `skb->head` → `BUG()`.

Resulting crash:

```
skbuff: skb_under_panic: len:49 put:2 head:ffff888003c10000
        data:ffff888003c0ffff tail:0x30 end:0x640 dev:<NULL>
kernel BUG at net/core/skbuff.c:214!
RIP: 0010:skb_panic+0x13e/0x230
Call Trace:
 skb_push+0xbd/0x100
 ppp_receive_nonmp_frame+0x48a/0x1d10
 ppp_input+0x4e9/0x2f80
 ppp_async_process+0x2a/0xe0
 tasklet_action_common+0x20f/0x8a0
 handle_softirqs+0x18e/0x590
Kernel panic - not syncing: Fatal exception in interrupt
```

### Reproducer

A working reproducer is available: [MCSAID-2026-009-repro-ppp-skb.c](./MCSAID-2026-009-repro-ppp-skb.c) (also posted to [netdev](https://lore.kernel.org/netdev/CAPAw8HE6QgnePG=UUfU2d9mYXNpY2O_kp5v0J82VuVoR6gwWOg@mail.gmail.com/)).

It creates a pty pair, attaches the `N_PPP` line discipline to the slave, creates a PPP unit with a pass filter, and writes the two frames from the master side, which plays the role of the remote peer.

```
gcc -O1 -static -o repro-ppp-skb MCSAID-2026-009-repro-ppp-skb.c
./repro-ppp-skb     # as root, in a disposable VM - panics within about a second
```

Root is needed only because `/dev/ppp` is mode 0600 by default.

---

## Details

### Affected code

- **File:** `drivers/net/ppp/ppp_async.c`
- **Function:** `process_input_packet()`

```c
 err:
	/* frame had an error, remember that, reset SC_TOSS & SC_ESCAPE */
	ap->state = SC_PREV_ERROR;
	if (skb) {
		/* make skb appear as freshly allocated */
		skb_trim(skb, 0);
		skb_reserve(skb, - skb_headroom(skb));
	}
```

### Root cause

`skb_reserve(skb, - skb_headroom(skb))` sets the headroom to zero, while a freshly allocated skb from `dev_alloc_skb()` has `NET_SKB_PAD` of headroom. Since `ap->rpkt` still references the skb, the next frame is reassembled into it.

The headroom for a new frame is chosen in `ppp_async_input()` from a single byte, and the existing comment already notes the test is incomplete:

```c
	if (skb->len == 0) {
		/* Try to get the payload 4-byte aligned. This should match
		 * the PPP_ALLSTATIONS/PPP_UI/compressed tests in
		 * process_input_packet, but we do not have enough chars here
		 * to test buf[1] and buf[2].
		 */
		if (buf[0] != PPP_ALLSTATIONS)
			skb_reserve(skb, 2 + (buf[0] & 1));
	}
```

A frame beginning `0xff` reserves nothing. `ppp_receive_nonmp_frame()` in `ppp_generic.c` then prepends a two-byte direction tag before running the pass/active BPF filters, assuming headroom that the receive path no longer guarantees:

```c
	*(__be16 *)skb_push(skb, 2) = htons(PPP_FILTER_INBOUND_TAG);
```

---

## Indicators

**On host:**

- Kernel panic with `skb_under_panic` and `kernel BUG at net/core/skbuff.c` with `ppp_receive_nonmp_frame` / `ppp_async_process` in the call trace.

**On the PPP link:**

- A frame with a bad FCS immediately followed by a frame starting `ff 03` with a compressed (single-byte) protocol field.

---

## Mitigations

The fix drops the errored frame instead of resetting its headroom - as `ppp_synctty` already does on its error path - and clears `ap->rpkt`, so the next frame is reassembled into a fresh skb with proper headroom. This fixes both the filter under-panic and the CCP out-of-bounds read.

```diff
--- a/drivers/net/ppp/ppp_async.c
+++ b/drivers/net/ppp/ppp_async.c
@@ -812,9 +812,6 @@ process_input_packet(struct asyncppp *ap)
  err:
 	/* frame had an error, remember that, reset SC_TOSS & SC_ESCAPE */
 	ap->state = SC_PREV_ERROR;
-	if (skb) {
-		/* make skb appear as freshly allocated */
-		skb_trim(skb, 0);
-		skb_reserve(skb, - skb_headroom(skb));
-	}
+	kfree_skb(skb);
+	ap->rpkt = NULL;
 }
```

- Fixed releases: 5.10.271, 5.15.222, 6.1.189, 6.6.158, 6.12.111, 6.18.53, 7.2.7, 7.3-rc3
- Fix commit (stable): [0c53eb14975f](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=0c53eb14975f029abd6b26896a460f0d2aaefe6b)

---

## Recommendations

- Upgrade to a fixed kernel release from your distribution or the stable series listed above.
- If you cannot patch, avoid installing PPP pass/active filters (`pppd` `active-filter`, demand-dialling) on asynchronous PPP links with untrusted peers.
- Unload the `ppp_async` module where asynchronous PPP is not needed.

---

## Timeline

- 2026-09-02 – Vulnerability reported to the Linux PPP / netdev maintainers with a reproducer and initial patch (v1)
- 2026-09-02 – Eric Dumazet suggested fixing the root cause in the transport
- 2026-09-03 – Patch v2 ("ppp_async: drop the errored frame instead of resetting its headroom") submitted
- 2026-09-08 – Patch applied to the `net` tree
- 2026-09-25 – CVE-2026-98158 published
- 2026-10-13 – Public advisory released

---

## References

- CVE record: [CVE-2026-98158](https://www.cve.org/CVERecord?id=CVE-2026-98158)
- CVE tracker: [linuxcvetracker.com/cve/CVE-2026-98158](https://linuxcvetracker.com/cve/CVE-2026-98158/)
- Fix commit: [0c53eb14975f029abd6b26896a460f0d2aaefe6b](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=0c53eb14975f029abd6b26896a460f0d2aaefe6b)
- Patch v1 and reproducer: [lore.kernel.org/netdev](https://lore.kernel.org/netdev/CAPAw8HE6QgnePG=UUfU2d9mYXNpY2O_kp5v0J82VuVoR6gwWOg@mail.gmail.com/)
- Marlink Cyber Security Advisory: [MCSAID-2026-009](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-009-linux-kernel-ppp_async-skb-headroom-reset-panic.md)
- Software: [Linux kernel](https://www.kernel.org/)
