# MOOS core-moos: MOOSDB Denial of Service via Unbounded Packet Allocation

- **Advisory ID:** MCSAID-2026-028
- **CVE ID:** [CVE-2026-85442](https://www.cve.org/CVERecord?id=CVE-2026-85442)
- **Published:** 2026-09-01
- **Severity:** High (CVSS 7.5 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **CVSS 4.0:** 8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Memory Allocation with Excessive Size Value
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #81](https://github.com/themoos/core-moos/pull/81) (not merged)
- **Software:** [MOOS core-moos](https://github.com/themoos/core-moos)
- **CWE:** [CWE-789: Memory Allocation with Excessive Size Value](https://cwe.mitre.org/data/definitions/789.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

The first four bytes of a MOOS packet are the declared total length, and `CMOOSCommPkt::OnBytesWritten` hands them straight to `new unsigned char[...]` with no protocol maximum. Thirty-six bytes on the wire request a 2 GiB allocation, and because `std::bad_alloc` is not caught anywhere on the handshake path, a failed allocation aborts the whole MOOSDB.

---

## Affected Versions

| Version | Status |
|---------|--------|
| core-moos <= 10.4.0 | Vulnerable |

Tested against: core-moos `v10.4.0-49-gec9c77c` (commit `ec9c77c68fcbdef8f5e4c60fe243acd223433f0c`), latest master; and MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master, which bundles the same code.

---

## Impact

Memory pressure on the autonomy computer from trivially small inputs, and - on
any host where the allocation can fail (a memory-constrained payload computer,
a cgroup/rlimit, or simply a big enough declared size) - an unauthenticated
remote abort of the entire MOOSDB, taking the whole mission bus with it.

---

## Exploitation

An unauthenticated TCP peer that can reach the MOOSDB listener.

Preconditions:

* Nothing beyond TCP reachability. The path runs inside HandShake(), before any client name is accepted.

---

## Details

### Affected code

Each affected file is listed twice: first at its path in **core-moos** git master (commit `ec9c77c`), which is where a fix has to land, then at its path inside the copy bundled in MOOS-IvP under `MOOS_Jul2724/MOOSCore`. The two copies are byte-identical unless stated otherwise.

* **`Core/libMOOS/Comms/MOOSCommPkt.cpp`** - lines 81-101: OnBytesWritten(): after 4 bytes, m_nMsgLen = *(int*)m_pStream; InflateTo(m_nMsgLen) with no maximum
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/MOOSCommPkt.cpp`** - lines 81-101: OnBytesWritten(): after 4 bytes, m_nMsgLen = *(int*)m_pStream; InflateTo(m_nMsgLen) with no maximum
* **`Core/libMOOS/Comms/MOOSCommPkt.cpp`** - lines 65-79: InflateTo(): unsigned char * t = new unsigned char[nNewStreamSize]
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/MOOSCommPkt.cpp`** - lines 65-79: InflateTo(): unsigned char * t = new unsigned char[nNewStreamSize]
* **`Core/libMOOS/Comms/MOOSCommObject.cpp`** - lines 159-219: ReadPkt() drives the loop from GetBytesRequired()
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/MOOSCommObject.cpp`** - lines 159-219: ReadPkt() drives the loop from GetBytesRequired()
* **`Core/libMOOS/Comms/MOOSCommServer.cpp`** - lines 944-1005: HandShake() catches only CMOOSException, so std::bad_alloc escapes
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/MOOSCommServer.cpp`** - lines 944-1005: HandShake() catches only CMOOSException, so std::bad_alloc escapes
* **`Core/libMOOS/Comms/MOOSCommServer.cpp`** - lines 505-509: the accept loop catches only XPCException
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/MOOSCommServer.cpp`** - lines 505-509: the accept loop catches only XPCException

### Root cause

The first four bytes of a MOOS packet are the total packet length.
`OnBytesWritten` copies them into `m_nMsgLen` and immediately calls
`InflateTo(m_nMsgLen)`, which does `new unsigned char[nNewStreamSize]`.  There
is no protocol maximum, no comparison against a configured limit, and no
`size_t` conversion check.  36 bytes on the wire (32-byte protocol string plus
the length field) request an allocation of up to 2 GiB.

If the allocation fails, `std::bad_alloc` is thrown.  `HandShake()` catches only
`CMOOSException` and the accept loop only `XPCException`, so the exception
escapes every handler and `std::terminate()` kills the MOOSDB.

**Correction.** An earlier version of this analysis stated that a *negative*
declared length was contained, on the assumption that `recv()` would reject the
resulting huge `size_t` with `EINVAL`.  That is wrong: `recv()` accepts it and
performs the copy, which is a heap buffer overflow.  That case is tracked
separately as **[MCSAID-2026-026](./MCSAID-2026-026-core-moos-moosdb-pre-authentication-heap-overflow-via-negative-packet-length.md)**, because the mechanism and the outcome are
different (no allocation happens at all, and the result is an out-of-bounds
write rather than memory pressure).

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

* 8 peers x 36 bytes each inflated the MOOSDB's address space past 2.3 GB.
  (The allocations are serialised because the accept loop is single-threaded -
  see [MCSAID-2026-029](./MCSAID-2026-029-core-moos-moosdb-accept-loop-denial-of-service.md) - so they do not stack, but each is transient and repeatable.)
* With `RLIMIT_AS` set to 1.5 GB, a single 36-byte connection declaring
  `0x7FFFFFFF` produced:

      terminate called after throwing an instance of 'std::bad_alloc'
        what():  std::bad_alloc

  and the MOOSDB exited with signal 6.

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #81](https://github.com/themoos/core-moos/pull/81)
- Proposed fix commit: [e7ea624a7b78](https://github.com/themoos/core-moos/commit/e7ea624a7b7828b47fcd35fc43feec1f5cfbbe21)

### Recommended fix

Validate the declared length before allocating: require
`sizeof(int)*2 + 1 <= len <= MAX_PACKET_SIZE` for a documented maximum, and
reject the connection otherwise.  Do the arithmetic in `size_t` after the range
check.  Add `catch(const std::exception&)` (and ideally `catch(...)`) at the
handshake and per-client thread boundaries so a single malformed peer can never
abort the process.

---

## Recommendations

- Apply the proposed fix from [Pull Request #81](https://github.com/themoos/core-moos/pull/81) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-01 – CVE-2026-85442 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85442](https://www.cve.org/CVERecord?id=CVE-2026-85442)
- VulnCheck advisory: [MOOS core-moos through 10.4.0 MOOSDB Denial of Service via Unbounded Packet Allocation](https://www.vulncheck.com/advisories/moos-core-moos-through-10.4.0-moosdb-denial-of-service-via-unbounded-packet-allocation)
- Upstream pull request: [Pull Request #81](https://github.com/themoos/core-moos/pull/81)
- Proposed fix commit: [e7ea624a7b7828b47fcd35fc43feec1f5cfbbe21](https://github.com/themoos/core-moos/commit/e7ea624a7b7828b47fcd35fc43feec1f5cfbbe21)
- Marlink Cyber Security Advisory: [MCSAID-2026-028](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-028-core-moos-moosdb-denial-of-service-via-unbounded-packet-allocation.md)
- Software: [MOOS core-moos](https://github.com/themoos/core-moos)
