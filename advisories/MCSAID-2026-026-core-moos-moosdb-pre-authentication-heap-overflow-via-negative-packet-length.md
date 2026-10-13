# MOOS core-moos: MOOSDB Pre-Authentication Heap Overflow via Negative Packet Length

- **Advisory ID:** MCSAID-2026-026
- **CVE ID:** [CVE-2026-85440](https://www.cve.org/CVERecord?id=CVE-2026-85440)
- **Published:** 2026-09-01
- **Severity:** Critical (CVSS 9.8 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **CVSS 4.0:** 9.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Out-of-bounds Write
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #82](https://github.com/themoos/core-moos/pull/82) (not merged)
- **Software:** [MOOS core-moos](https://github.com/themoos/core-moos)
- **CWE:** [CWE-787: Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

A declared outer packet length of `0xFFFFFFFF` is read into a signed `int`, so `InflateTo(-1)` leaves the receive buffer at its constructor size of four bytes and reports success. `GetBytesRequired()` then returns a negative byte count which `ReadPkt` passes to `recv()`, whose length parameter is `size_t` - so the kernel copies as many attacker bytes as are available into a four-byte heap allocation. Pre-authentication, in the process every other MOOS process depends on. Not in an earlier assessment.

---

## Affected Versions

| Version | Status |
|---------|--------|
| core-moos <= 10.4.0 | Vulnerable |

Tested against: core-moos `v10.4.0-49-gec9c77c` (commit `ec9c77c68fcbdef8f5e4c60fe243acd223433f0c`), latest master; and MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master, which bundles the same code.

---

## Impact

A pre-authentication, remotely triggered heap buffer overflow with
attacker-controlled contents and length, in the process that is the single point
of failure for the whole autonomy bus.  Confirmed impact is denial of service:
on a stock hardened build the overflow lands on the server's own socket
bookkeeping and glibc's `fd_set` FORTIFY check aborts the process.  The
primitive itself is memory corruption, so the ceiling is higher than DoS,
although MOOS offers no remote memory-disclosure primitive with which to defeat
ASLR.

---

## Exploitation

An unauthenticated TCP peer.

Preconditions:

* TCP reachability to the MOOSDB port, or to any MOOS client's socket - the same code runs in every MOOS process.
* The path executes inside CMOOSCommServer::HandShake(), before a client name is accepted, so it is pre-authentication.

---

## Details

### Affected code

Each affected file is listed twice: first at its path in **core-moos** git master (commit `ec9c77c`), which is where a fix has to land, then at its path inside the copy bundled in MOOS-IvP under `MOOS_Jul2724/MOOSCore`. The two copies are byte-identical unless stated otherwise.

* **`Core/libMOOS/Comms/MOOSCommPkt.cpp`** - lines 48-56: the constructor allocates exactly sizeof(int) == 4 bytes
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/MOOSCommPkt.cpp`** - lines 48-56: the constructor allocates exactly sizeof(int) == 4 bytes
* **`Core/libMOOS/Comms/MOOSCommPkt.cpp`** - lines 65-79: InflateTo(): `if (nNewStreamSize <= m_nStreamSpace) return true;` - a signed comparison, so a negative size silently skips the reallocation
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/MOOSCommPkt.cpp`** - lines 65-79: InflateTo(): `if (nNewStreamSize <= m_nStreamSpace) return true;` - a signed comparison, so a negative size silently skips the reallocation
* **`Core/libMOOS/Comms/MOOSCommPkt.cpp`** - lines 81-101: OnBytesWritten(): m_nMsgLen is taken from the wire and passed straight to InflateTo()
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/MOOSCommPkt.cpp`** - lines 81-101: OnBytesWritten(): m_nMsgLen is taken from the wire and passed straight to InflateTo()
* **`Core/libMOOS/Comms/MOOSCommPkt.cpp`** - lines 110-115: GetBytesRequired(): returns m_nMsgLen - m_nByteCount, i.e. -5 when the declared length is -1
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/MOOSCommPkt.cpp`** - lines 110-115: GetBytesRequired(): returns m_nMsgLen - m_nByteCount, i.e. -5 when the declared length is -1
* **`Core/libMOOS/Comms/MOOSCommObject.cpp`** - lines 165-195: ReadPkt(): `if(nRqd<CHUNK_READ)` is true for a negative nRqd, which is then handed to the socket read
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/MOOSCommObject.cpp`** - lines 165-195: ReadPkt(): `if(nRqd<CHUNK_READ)` is true for a negative nRqd, which is then handed to the socket read
* **`Core/libMOOS/Comms/XPCTcpSocket.cpp`** - lines 211-223: iRecieveMessage(): recv(iSocket, buf, _iMessageSize, _iOption) - the int becomes a ~2^64 size_t
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/XPCTcpSocket.cpp`** - lines 211-223: iRecieveMessage(): recv(iSocket, buf, _iMessageSize, _iOption) - the int becomes a ~2^64 size_t

### Root cause

Declare an outer packet length of `0xFFFFFFFF`.  `OnBytesWritten` reads it into
the signed `m_nMsgLen` as `-1` and calls `InflateTo(-1)`, whose first line is
`if (nNewStreamSize <= m_nStreamSpace) return true;` - `-1 <= 4`, so the buffer
is left at its constructor size of four bytes and the function reports success.

`GetBytesRequired()` then returns `m_nMsgLen - m_nByteCount` = `-1 - 4` = `-5`.
`ReadPkt` compares that against `CHUNK_READ` (a signed comparison, which
`-5` passes) and calls `iRecieveMessage(PktRx.NextWrite(), -5)`, which is
`recv(fd, buf, (size_t)-5, 0)`.  `recv()` does not know or check the size of the
destination buffer, so the kernel copies as many bytes as the peer has sent into
a four-byte heap allocation.

This is a **different defect from [MCSAID-2026-028](./MCSAID-2026-028-core-moos-moosdb-denial-of-service-via-unbounded-packet-allocation.md), [MCSAID-2026-041](./MCSAID-2026-041-core-moos-moosdb-out-of-bounds-read-via-short-packet.md) and [MCSAID-2026-022](./MCSAID-2026-022-essential-moos-pmoosbridge-heap-corruption-via-negative-udp-length.md)**, which is why it is
tracked separately:

| Advisory | Declared length | What happens |
| --- | --- | --- |
| [MCSAID-2026-028](./MCSAID-2026-028-core-moos-moosdb-denial-of-service-via-unbounded-packet-allocation.md) | large positive | unbounded `new[]`, then possible uncaught `std::bad_alloc` |
| [MCSAID-2026-041](./MCSAID-2026-041-core-moos-moosdb-out-of-bounds-read-via-short-packet.md) | 4..7 | packet declared complete too early; 4-byte out-of-bounds **read** |
| this advisory | negative | no allocation at all; out-of-bounds **write** of attacker bytes via `recv()` |
| [MCSAID-2026-022](./MCSAID-2026-022-essential-moos-pmoosbridge-heap-corruption-via-negative-udp-length.md) | negative, UDP path | `memcpy` with a negative size in pMOOSBridge |

**Correction to this assessment's own earlier note.** The write-up for [MCSAID-2026-028](./MCSAID-2026-028-core-moos-moosdb-denial-of-service-via-unbounded-packet-allocation.md)
originally stated that a negative length was contained because `recv()` would
fail with `EINVAL`. That is wrong: `recv()` accepts the huge `size_t` and
performs the copy. The [MCSAID-2026-028](./MCSAID-2026-028-core-moos-moosdb-denial-of-service-via-unbounded-packet-allocation.md) analysis has been corrected accordingly.

---

## Reproduction

### Test environment

Ubuntu 24.04, x86-64, gcc 13.3.0, cmake 3.28.3, FLTK 1.3.8, Python 3.14.

All four MOOS repositories were built from source with their default settings -
Release `-O2`, and every resulting binary is a hardened PIE with a stack canary,
FORTIFY, NX and full RELRO:

| Repository | Version | Built with |
| --- | --- | --- |
| core-moos | `v10.4.0-49-gec9c77c` (`ec9c77c`) | `cmake .. && make` |
| essential-moos | `10.0.1-release-22-gb897ea8` (`b897ea8`) | `cmake -DMOOS_DIR=<core-moos build> .. && make` |
| ui-moos | commit `50b9c6c` | `cmake -DBUILD_GRAPHICAL_TOOLS=ON -DBUILD_UMS=ON -DMOOS_DIR=<core-moos build> .. && make` |
| MOOS-IvP | `1de9ae146cd63c209e8c3fd81611a4ed2472971b` | `./build-moos.sh && ./build-ivp.sh` |

The affected code lives in **core-moos** (`v10.4.0-49-gec9c77c`, commit `ec9c77c`) and is also bundled inside MOOS-IvP under `MOOS_Jul2724/MOOSCore`. Both copies were checked; unless noted otherwise in the text they are byte-identical, so a fix belongs in core-moos and MOOS-IvP needs to pick it up.

#### Tested / reproduced

Yes - reproduced against standalone core-moos `v10.4.0-49-gec9c77c` (commit `ec9c77c`), default production build (`cmake .. && make`, Release -O2, hardened PIE), and against the copy bundled in MOOS-IvP.

### Steps and results

*Stock build* (`-O2`, PIE, canary, FORTIFY): after a handful of shots the
MOOSDB aborts with exit `-6` and

    *** bit out of range 0 - FD_SETSIZE on fd_set ***: terminated

which is glibc detecting that the server's own `fd_set` has been scribbled over.

*ASan build*, one shot:

    ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000001034
    WRITE of size 32768 at 0x502000001034 thread T5
        #0 in recv
        #2 in XPCTcpSocket::iRecieveMessage(void*, int, int)  XPCTcpSocket.cpp:223
        #4 in CMOOSCommObject::ReadPkt(...)                   MOOSCommObject.cpp:182
        #6 in CMOOSCommServer::HandShake(XPCTcpSocket*)       MOOSCommServer.cpp
    SUMMARY: AddressSanitizer: heap-buffer-overflow ... in recv

32 KB written into a 4-byte allocation, from inside the handshake.

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #82](https://github.com/themoos/core-moos/pull/82)
- Proposed fix commit: [96c49c5cdda6](https://github.com/themoos/core-moos/commit/96c49c5cdda6e07ee734a5324e8d25ba5a7f2d7a)

### Recommended fix

* Treat the packet length as unsigned and validate it before use: reject
  anything below the 9-byte structural header or above a documented protocol
  maximum, in `OnBytesWritten`, before calling `InflateTo`.
* Make `InflateTo` reject negative and over-limit sizes instead of returning
  `true`.
* Never pass a non-positive length to `recv()`: in `ReadPkt`, treat
  `GetBytesRequired() <= 0` as a protocol error and drop the connection.
* Change `XPCTcpSocket::iRecieveMessage` to take a `size_t`, or assert
  `_iMessageSize > 0`, so the sign error cannot recur.

A single range check on the declared length in `OnBytesWritten` fixes findings
8, 34 and 35 together, and the same shape of check fixes 12 in the UDP path.

---

## Recommendations

- Apply the proposed fix from [Pull Request #82](https://github.com/themoos/core-moos/pull/82) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-01 – CVE-2026-85440 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85440](https://www.cve.org/CVERecord?id=CVE-2026-85440)
- VulnCheck advisory: [MOOS core-moos through 10.4.0 MOOSDB Pre-Authentication Heap Overflow via Negative Packet Length](https://www.vulncheck.com/advisories/moos-core-moos-through-10.4.0-moosdb-pre-authentication-heap-overflow-via-negative-packet-length)
- Upstream pull request: [Pull Request #82](https://github.com/themoos/core-moos/pull/82)
- Proposed fix commit: [96c49c5cdda6e07ee734a5324e8d25ba5a7f2d7a](https://github.com/themoos/core-moos/commit/96c49c5cdda6e07ee734a5324e8d25ba5a7f2d7a)
- Marlink Cyber Security Advisory: [MCSAID-2026-026](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-026-core-moos-moosdb-pre-authentication-heap-overflow-via-negative-packet-length.md)
- Software: [MOOS core-moos](https://github.com/themoos/core-moos)
