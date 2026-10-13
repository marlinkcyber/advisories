# MOOS core-moos: MOOSDB Denial of Service via Negative Serialized String Length

- **Advisory ID:** MCSAID-2026-027
- **CVE ID:** [CVE-2026-85441](https://www.cve.org/CVERecord?id=CVE-2026-85441)
- **Published:** 2026-09-01
- **Severity:** High (CVSS 7.5 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **CVSS 4.0:** 8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Signed to Unsigned Conversion Error
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #74](https://github.com/themoos/core-moos/pull/74) (not merged)
- **Software:** [MOOS core-moos](https://github.com/themoos/core-moos)
- **CWE:** [CWE-195: Signed to Unsigned Conversion Error](https://cwe.mitre.org/data/definitions/195.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

`CMOOSMsg::CanSerialiseN` is a signed comparison with no non-negative check, so a negative field length passes the bounds test and is then converted to `size_type` for `std::string::assign`. The resulting `std::length_error` is not caught by any handler on the handshake path, so 55 unauthenticated bytes abort the entire MOOSDB.

---

## Affected Versions

| Version | Status |
|---------|--------|
| core-moos <= 10.4.0 | Vulnerable |

Tested against: core-moos `v10.4.0-49-gec9c77c` (commit `ec9c77c68fcbdef8f5e4c60fe243acd223433f0c`), latest master; and MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master, which bundles the same code.

---

## Impact

Unauthenticated remote denial of service of the entire MOOS community: 55 bytes
kill the MOOSDB, and every autonomy process loses its database at once.  The
same primitive also kills pShare ([MCSAID-2026-016](./MCSAID-2026-016-essential-moos-pshare-unauthenticated-udp-datagram-republishing.md)) and pMOOSBridge, because they use
the same deserialiser behind an even weaker exception boundary.

---

## Exploitation

An unauthenticated TCP peer.

Preconditions:

* TCP reachability to the MOOSDB port. Nothing else - the crash happens inside HandShake().

---

## Details

### Affected code

Each affected file is listed twice: first at its path in **core-moos** git master (commit `ec9c77c`), which is where a fix has to land, then at its path inside the copy bundled in MOOS-IvP under `MOOS_Jul2724/MOOSCore`. The two copies are byte-identical unless stated otherwise.

* **`Core/libMOOS/Comms/MOOSMsg.cpp`** - lines 453-456: bool CanSerialiseN(int N) { return (cursor)+N <= m_nSerializeBufferLen; } - no N >= 0 test
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/MOOSMsg.cpp`** - lines 453-456: bool CanSerialiseN(int N) { return (cursor)+N <= m_nSerializeBufferLen; } - no N >= 0 test
* **`Core/libMOOS/Comms/MOOSMsg.cpp`** - lines 217-234: operator>>(string&): sVal.assign((const char*)m_pSerializeBuffer, nSize) with nSize negative
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/MOOSMsg.cpp`** - lines 217-234: operator>>(string&): sVal.assign((const char*)m_pSerializeBuffer, nSize) with nSize negative
* **`Core/libMOOS/Comms/MOOSCommServer.cpp`** - line 1004: HandShake() catches only CMOOSException
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/MOOSCommServer.cpp`** - line 1004: HandShake() catches only CMOOSException
* **`Core/libMOOS/Comms/MOOSCommServer.cpp`** - lines 505-509: the accept loop catches only XPCException
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/MOOSCommServer.cpp`** - lines 505-509: the accept loop catches only XPCException

### Root cause

`CanSerialiseN` is a signed comparison with no lower bound, so a negative field
length passes it.  `operator>>(string&)` then converts that negative `int` to
`std::string::size_type`, producing a value near `SIZE_MAX`, and libstdc++
throws `std::length_error`.  Neither `CMOOSMsg::Serialize`,
`CMOOSCommPkt::Serialize`, `CMOOSCommServer::HandShake` nor the accept loop
catches `std::exception`, so the exception escapes the thread and
`std::terminate()` aborts the process.

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

One 55-byte write (32-byte protocol string + a 23-byte packet whose first string
field declares length `-1`):

    packet hex: 1700000001000000000e000000000000006953ffffffff
    terminate called after throwing an instance of 'std::length_error'
      what():  basic_string::_M_replace

MOOSDB exited with signal 6 and stopped listening.

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #74](https://github.com/themoos/core-moos/pull/74)
- Proposed fix commit: [04c92981091f](https://github.com/themoos/core-moos/commit/04c92981091fdaa2ff85e2ba7eff94f6288bdbaf)

### Recommended fix

Add `if (N < 0) return false;` to `CanSerialiseN` - a one-line fix that closes
this instance.  Then do the structural work: track the cursor in `size_t`,
validate every field length against the remaining buffer *and* a per-field
maximum, and add `catch(const std::exception&)` at the handshake and per-client
thread boundaries so no single peer can abort the server.

---

## Recommendations

- Apply the proposed fix from [Pull Request #74](https://github.com/themoos/core-moos/pull/74) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-01 – CVE-2026-85441 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85441](https://www.cve.org/CVERecord?id=CVE-2026-85441)
- VulnCheck advisory: [MOOS core-moos through 10.4.0 MOOSDB Denial of Service via Negative Serialized String Length](https://www.vulncheck.com/advisories/moos-core-moos-through-10.4.0-moosdb-denial-of-service-via-negative-serialized-string-length)
- Upstream pull request: [Pull Request #74](https://github.com/themoos/core-moos/pull/74)
- Proposed fix commit: [04c92981091fdaa2ff85e2ba7eff94f6288bdbaf](https://github.com/themoos/core-moos/commit/04c92981091fdaa2ff85e2ba7eff94f6288bdbaf)
- Marlink Cyber Security Advisory: [MCSAID-2026-027](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-027-core-moos-moosdb-denial-of-service-via-negative-serialized-string-length.md)
- Software: [MOOS core-moos](https://github.com/themoos/core-moos)
