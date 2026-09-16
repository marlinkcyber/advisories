# Unbound: Heap Buffer Overflow during DNSSEC Canonicalization leads to Denial of Service

- **Advisory ID:** MCSAID-2026-006
- **CVE ID:** [CVE-2026-81634](https://www.cve.org/CVERecord?id=CVE-2026-81634)
- **Reported:** 2026-07-31
- **Published:** 2026-09-16
- **Severity:** High (CVSS 7.5 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **Vulnerability type:** Heap-based buffer overflow, Denial of Service (DoS), Service crash
- **Current state:** Fix released by vendor in Unbound 1.26.1
- **Exploitation:** Easy, deterministic, not seen in the wild
- **Software:** [NLnet Labs Unbound](https://nlnetlabs.nl/projects/unbound/)
- **CWE:** [CWE-122: Heap-based Buffer Overflow](https://cwe.mitre.org/data/definitions/122.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

A 255-byte query name combined with a large TCP response can trigger a heap buffer overflow in Unbound's DNSSEC RRset canonicalization routine. The capacity check in `rrset_canonical()` omits the canonical owner name on the loop's first iteration, so `insert_can_owner()` — which performs no bounds check of its own — writes up to 255 bytes past the end of the scratch buffer.

Canonicalization happens **before** the DNSSEC signature is verified, so the overflow is reachable with attacker-supplied, structurally valid but unauthenticated data. A malicious actor operating a name server that Unbound queries (or able to tamper with an incoming response) can crash the resolver over the network with a single protocol-legal DNS response. The crash was proven against a stock, assert-disabled (production) build; code execution was not demonstrated.

---

## Affected Versions

| Version | Status |
|---------|--------|
| Unbound <= 1.26.0 (all versions up to and including 1.26.0) | Vulnerable |
| Unbound 1.26.1 and later | Fixed |

Reproduced on Unbound 1.25.2 (release) and git master `79b84bbc91a24e5e6fa555acc61961b1f8f6a171`, built with standard production flags (`./configure && make unbound`, `NDEBUG` defined) on Ubuntu 24.04 LTS.

---

## Impact

A remote attacker can crash a validating Unbound resolver with a single, protocol-legal (≤ 65,535-byte) TCP DNS response. The attack requires no authentication, no privileged network position and no valid DNSSEC signature, and is deterministic rather than racy. Since DNS resolution is a critical dependency for most enterprise and Internet services, loss of the resolver has broad operational impact. Memory beyond the scratch buffer is overwritten with attacker-influenced bytes, so code execution cannot be ruled out, although it was not demonstrated.

---

## Exploitation

The attacker must get Unbound to resolve a name under a zone they control, or be able to tamper with a response in transit. The resolver is then handed a large `SIG`/`RRSIG` answer for a 255-byte query name; because the overflow occurs in the canonicalization step that precedes cryptographic validation, no valid key or signature is needed.

---

## Details

### Root cause

`rrset_canonical()` (`validator/val_sigcrypt.c:1282-1352`) canonicalizes an RRset into a scratch buffer:

```c
uint8_t* can_owner = NULL;
size_t can_owner_len = 0;
...
RBTREE_FOR(walk, struct canon_rr*, (*sortree)) {
    /* see if there is enough space left in the buffer */
    if(sldns_buffer_remaining(buf) < can_owner_len + 2 + 2 + 4
        + d->rr_len[walk->rr_idx]) {
        log_err("verify: failed to canonicalize, "
            "rrset too big");
        return 0;
    }
    /* determine canonical owner name */
    if(can_owner)
        sldns_buffer_write(buf, can_owner, can_owner_len);
    else
        insert_can_owner(buf, k, sig, &can_owner,
            &can_owner_len);
    sldns_buffer_write(buf, &k->rk.type, 2);
    sldns_buffer_write(buf, &k->rk.rrset_class, 2);
    sldns_buffer_write(buf, sig+4, 4);
    sldns_buffer_write(buf, d->rr_data[walk->rr_idx],
        d->rr_len[walk->rr_idx]);
    ...
```
(`validator/val_sigcrypt.c:1310-1333`)

On the first loop iteration `can_owner_len` is still `0` (initialized at `val_sigcrypt.c:1290`), so the capacity check accounts only for `type(2) + class(2) + ttl(4) + rdata(rr_len)` — not the canonical owner name that `insert_can_owner()` writes on the very next line. `insert_can_owner()` (`val_sigcrypt.c:1055-1084`) writes up to 255 bytes (a full wire-format domain name) with no bounds check of its own, relying entirely on the caller's incorrect check.

`sldns_buffer_write()` → `sldns_buffer_write_at()` (`sldns/sbuffer.h:432-437`) guards the copy with a plain `assert()`, which compiles to nothing when `NDEBUG` is defined — i.e. in any standard, non-`--enable-debug` build (`configure.ac` defines `NDEBUG` unless `UNBOUND_DEBUG` is set). The `memcpy()` at `sldns/sbuffer.h:436` therefore runs unconditionally in production builds.

### Reaching the overflow within the 65,535-byte message limit

A naive byte budget suggests the overflow window (up to ~255 bytes) is a few dozen bytes short of what a single 65,535-byte TCP message can supply on top of the 65,552-byte scratch buffer. DNS name compression closes that gap:

- `calc_size()` (`util/data/msgparse.c:657-693`) adds the fully **decompressed** length of any RDATA-embedded dname to the record's stored `rr_len`, regardless of how compactly it was encoded on the wire (`util/data/msgparse.c:662-667`).
- `SIG`/`RRSIG` RDATA is shaped as `[18 fixed bytes][domain name][trailing bytes]` (`sldns/rrdef.c`, `type_sig_wireformat` / `type_rrsig_wireformat`).

An attacker can therefore place a 2-byte compression pointer where the embedded name goes and gain up to 253 bytes of "free" in-memory inflation per record — more than enough to overflow the buffer from a single legal message.

### Call chain

`dnskey_verify_rrset_sig()` (`val_sigcrypt.c:1555`) is invoked from `dnskeyset_verify_rrset()` / `dnskey_verify_rrset()` during normal DNSSEC answer validation and calls `rrset_canonical()` at `val_sigcrypt.c:1721-1728` **before** the cryptographic signature check.

---

## Proof of Concept

Run against a stock, unmodified, production-flags `unbound` daemon (no debug flags, no sanitizers). Tested on Ubuntu 24.04 LTS.

1. Start Unbound with the test configuration:

```bash
./unbound -c /tmp/unbound.conf
```

2. Start the malicious authoritative name server:

```bash
python evil_ns_dnssec.py
```

3. Query the offending domain:

```bash
dig @127.0.0.1 -p 15353 +time=5 +tries=1 \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.z. SIG
```

The malicious server forces a TCP retry and returns an oversized answer:

```
[evil_ns] listening on 0.0.0.0:15390 (udp+tcp)
[evil_ns] query id=5304 qname_len=255 qtype=24 via=udp
[evil_ns]  -> answer is 65437 bytes, truncating over UDP (TC=1) to force TCP retry
[evil_ns] query id=18943 qname_len=255 qtype=24 via=tcp
[evil_ns]  -> sending 65437 byte answer over TCP
```

Unbound crashes:

```
$ ./unbound -c unbound.conf
[1785512276] unbound[381055:0] debug: creating udp4 socket 127.0.0.1 15353
[1785512276] unbound[381055:0] debug: creating tcp4 socket 127.0.0.1 15353
[1785512276] unbound[381055:0] debug: module config: "validator iterator"
[1785512276] unbound[381055:0] debug: chdir to /tmp
[1785512276] unbound[381055:0] debug: switching log to /tmp/unbound.log
Segmentation fault
```

---

## Indicators

**On host:**

- Unexpected termination (`Segmentation fault`) of the `unbound` process, typically shortly after a large TCP response is validated.

**On network:**

- Queries with a 255-byte QNAME for `SIG` (type 24) / `RRSIG` (type 46) records.
- Large (near 64 KB) DNS responses delivered over TCP after a truncated (TC=1) UDP answer, containing `SIG`/`RRSIG` records whose RDATA embeds a compression pointer in place of the signer's name.

---

## Mitigations

Unbound 1.26.1 adds the first owner name into the canonicalization length check and validates the buffer length before writing.

- Fixed release: [unbound-1.26.1.tar.gz](https://nlnetlabs.nl/downloads/unbound/unbound-1.26.1.tar.gz)
- Full patch for 1.26.0: [patch_CVE-2026-81634_with.diff](https://nlnetlabs.nl/downloads/unbound/patch_CVE-2026-81634_with.diff)
- Minimal patch for 1.26.0 (vulnerability fix only): [patch_CVE-2026-81634.diff](https://nlnetlabs.nl/downloads/unbound/patch_CVE-2026-81634.diff)

Apply a patch with:

```bash
patch -p1 < patch_CVE-2026-81634_with.diff
make install
```

### Recommended code-level remediation (as reported)

Compute — or reserve worst-case space for — the canonical owner name and its length **before** entering the record loop, so the very first capacity check already accounts for it:

```c
/* before the RBTREE_FOR loop in rrset_canonical() */
uint8_t owner_scratch[LDNS_MAX_DOMAINLEN + 2 /* possible "*." wildcard prefix */];
size_t max_can_owner_len = 0;
/* compute once, using the same logic as insert_can_owner(), or simply
 * reserve LDNS_MAX_DOMAINLEN + 2 as a fixed upper bound */
...
if(sldns_buffer_remaining(buf) < max_can_owner_len + 2 + 2 + 4
    + d->rr_len[walk->rr_idx]) { ... }
```

As defense in depth, `sldns_buffer_write()` / `sldns_buffer_write_at()` should fail closed on overflow in **all** builds rather than relying solely on `assert()`, since `NDEBUG` is the default for production builds of this project.

---

## Recommendations

- Upgrade to Unbound 1.26.1 or later, or apply one of the vendor patches to 1.26.0.
- Until patched, restrict which clients can drive recursion on the resolver; note that this does not fully mitigate the issue, since any resolution towards attacker-controlled zones can trigger it.

---

## Timeline

- 2026-07-31 – Vulnerability reported to NLnet Labs
- 2026-08-03 – NLnet Labs shared a patch
- 2026-08-04 – Patch verified by the reporter
- 2026-09-07 – CVE-2026-81634 reserved
- 2026-09-16 – Unbound 1.26.1 released, vendor advisory and CVE published
- 2026-09-16 – Public advisory released

---

## References

- Vendor advisory: [NLnet Labs CVE-2026-81634](https://nlnetlabs.nl/downloads/unbound/CVE-2026-81634.txt)
- CVE record: [CVE-2026-81634](https://www.cve.org/CVERecord?id=CVE-2026-81634)
- Marlink Cyber Security Advisory: [MCSAID-2026-006](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-006-unbound-dnssec-canonicalization-heap-buffer-overflow.md)
- Software: [NLnet Labs Unbound](https://nlnetlabs.nl/projects/unbound/)
