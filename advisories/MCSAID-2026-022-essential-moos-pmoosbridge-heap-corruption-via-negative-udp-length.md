# MOOS essential-moos: pMOOSBridge Heap Corruption via Negative UDP Length

- **Advisory ID:** MCSAID-2026-022
- **CVE ID:** [CVE-2026-85436](https://www.cve.org/CVERecord?id=CVE-2026-85436)
- **Published:** 2026-09-02
- **Severity:** High (CVSS 7.5 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **CVSS 4.0:** 8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Integer Underflow (Wrap or Wraparound)
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #21](https://github.com/themoos/essential-moos/pull/21) (not merged)
- **Software:** [MOOS essential-moos](https://github.com/themoos/essential-moos)
- **CWE:** [CWE-191: Integer Underflow (Wrap or Wraparound)](https://cwe.mitre.org/data/definitions/191.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

pMOOSBridge's UDP reassembly loop compares a signed byte count against the datagram size, so a declared packet length below four produces a negative requirement that passes the check and reaches `memcpy` as a huge `size_t`. A large declared length instead reaches an unbounded `new[]` before the consistency check runs. Both are triggered by a 4-byte unauthenticated datagram.

---

## Affected Versions

| Version | Status |
|---------|--------|
| essential-moos <= 10.0.1 | Vulnerable |

Tested against: essential-moos `10.0.1-release-22-gb897ea8` (commit `b897ea86dba8b61412dc48ac0cfb5ff34cdaf5f6`), latest master; and MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master, which bundles the same code.

---

## Impact

Remote memory corruption and process abort of the community bridge from a
4-byte unauthenticated datagram.  A wild `memcpy` of that size is a crash in
practice, but it is a genuine out-of-bounds write, so a hardened or
differently-laid-out build could behave worse.

---

## Exploitation

Anyone who can send UDP to a configured pMOOSBridge `UDPListen` port.

Preconditions:

* pMOOSBridge running with `UDPListen = <port>` (the configuration required for any UDP bridging).

---

## Details

### Affected code

Each affected file is listed twice: first at its path in **essential-moos** git master (commit `b897ea8`), which is where a fix has to land, then at its path inside the copy bundled in MOOS-IvP under `MOOS_Jul2724/MOOSEssentials`. The two copies are byte-identical unless stated otherwise.

* **`Essentials/pMOOSBridge/MOOSUDPLink.cpp`** - lines 163-180: ReadPktFromArray(): `if(q+nRqd<=nBytes)` is a signed comparison, and nRqd comes from GetBytesRequired(); memcpy(dst, src, nRqd) converts a negative nRqd to a huge size_t
* **`MOOS_Jul2724/MOOSEssentials/Essentials/pMOOSBridge/MOOSUDPLink.cpp`** - lines 163-180: ReadPktFromArray(): `if(q+nRqd<=nBytes)` is a signed comparison, and nRqd comes from GetBytesRequired(); memcpy(dst, src, nRqd) converts a negative nRqd to a huge size_t
* **`Core/libMOOS/Comms/MOOSCommPkt.cpp`** _(core-moos)_ - lines 83-115: GetBytesRequired() returns m_nMsgLen - m_nByteCount, which is negative when the declared length is under 4; OnBytesWritten() allocates the declared length before it is validated
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/MOOSCommPkt.cpp`** - lines 83-115: GetBytesRequired() returns m_nMsgLen - m_nByteCount, which is negative when the declared length is under 4; OnBytesWritten() allocates the declared length before it is validated
* **`Essentials/pMOOSBridge/MOOSUDPLink.cpp`** - lines 146-150: catch (CMOOSException e) cannot catch a SIGSEGV or a std::bad_alloc
* **`MOOS_Jul2724/MOOSEssentials/Essentials/pMOOSBridge/MOOSUDPLink.cpp`** - lines 146-150: catch (CMOOSException e) cannot catch a SIGSEGV or a std::bad_alloc

### Root cause

Two distinct defects in the same loop.

*Underflow.*  Declare an outer packet length below 4, say 2.  The first
iteration copies 4 bytes and sets `m_nMsgLen = 2`.  `GetBytesRequired()` then
returns `2 - 4 = -2`, which is non-zero, so the loop continues; `q + nRqd` is
`4 + (-2) = 2`, which passes `<= nBytes`; and `memcpy(dst, src, -2)` is executed
with a size of `0xFFFFFFFFFFFFFFFE`.

*Oversize.*  Declare a large positive length.  `OnBytesWritten` calls
`InflateTo(m_nMsgLen)` - an unbounded `new[]` - on the very first iteration.
The consistency check against the datagram size only happens on the *next*
iteration, after the allocation has already been made.  `std::bad_alloc` is not
a `CMOOSException`, so the `catch` in `ListenLoop` does not catch it.

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

The affected code lives in **essential-moos** (`10.0.1-release-22-gb897ea8`, commit `b897ea8`) and is also bundled inside MOOS-IvP under `MOOS_Jul2724/MOOSEssentials`. Both copies were checked; unless noted otherwise in the text they are byte-identical, so a fix belongs in essential-moos and MOOS-IvP needs to pick it up.

#### Tested / reproduced

Yes - reproduced against essential-moos `10.0.1-release-22-gb897ea8`: AddressSanitizer reports `negative-size-param: (size=-2)` at `essential-moos/Essentials/pMOOSBridge/MOOSUDPLink.cpp:173`, and on the stock build under an address-space limit the oversize case aborts with an uncaught `std::bad_alloc`.

### Steps and results

*Underflow*, 4 bytes `02000000`, ASan build:

    ==...==ERROR: AddressSanitizer: negative-size-param: (size=-2)
        #2 in CMOOSUDPLink::ReadPktFromArray(...) MOOSUDPLink.cpp:173

The stock build survived this particular datagram, which is exactly why it needs
a sanitiser to see.

*Oversize*, 4 bytes `0000ff7f` (0x7FFF0000 = 2 GiB), stock build under a 1.2 GB
`RLIMIT_AS`:

    terminate called after throwing an instance of 'std::bad_alloc'
    pMOOSBridge exit code: -6

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #21](https://github.com/themoos/essential-moos/pull/21)
- Proposed fix commit: [613175fcf63f](https://github.com/themoos/essential-moos/commit/613175fcf63fb9c6c5329c4ec57c2d18588b33e2)

### Recommended fix

Parse the length as a fixed-width unsigned quantity, require it to be at least
the 9-byte structural header and at most a documented protocol maximum *and* no
larger than the datagram actually received, before constructing or inflating
anything.  Do all cursor arithmetic in `size_t`.  Catch `std::exception` in the
listener thread and drop the datagram instead of dying.

---

## Recommendations

- Apply the proposed fix from [Pull Request #21](https://github.com/themoos/essential-moos/pull/21) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85436 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85436](https://www.cve.org/CVERecord?id=CVE-2026-85436)
- VulnCheck advisory: [MOOS essential-moos through 10.0.1 pMOOSBridge Heap Corruption via Negative UDP Length](https://www.vulncheck.com/advisories/moos-essential-moos-through-10.0.1-pmoosbridge-heap-corruption-via-negative-udp-length)
- Upstream pull request: [Pull Request #21](https://github.com/themoos/essential-moos/pull/21)
- Proposed fix commit: [613175fcf63fb9c6c5329c4ec57c2d18588b33e2](https://github.com/themoos/essential-moos/commit/613175fcf63fb9c6c5329c4ec57c2d18588b33e2)
- Marlink Cyber Security Advisory: [MCSAID-2026-022](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-022-essential-moos-pmoosbridge-heap-corruption-via-negative-udp-length.md)
- Software: [MOOS essential-moos](https://github.com/themoos/essential-moos)
