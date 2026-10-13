# MOOS core-moos: MOOSDB Out-of-Bounds Read via Short Packet

- **Advisory ID:** MCSAID-2026-041
- **CVE ID:** [CVE-2026-85455](https://www.cve.org/CVERecord?id=CVE-2026-85455)
- **Published:** 2026-09-01
- **Severity:** High (CVSS 8.2 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H)
- **CVSS 4.0:** 8.8 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Out-of-bounds Read
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #75](https://github.com/themoos/core-moos/pull/75) (not merged)
- **Software:** [MOOS core-moos](https://github.com/themoos/core-moos)
- **CWE:** [CWE-125: Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS core-moos through 10.4.0 contains a buffer over-read vulnerability in CMOOSCommPkt where a four-byte packet triggers out-of-bounds memory access during deserialization. Attackers can open a TCP connection to the MOOSDB port and send a crafted short packet to read memory before authentication.

---

## Affected Versions

| Version | Status |
|---------|--------|
| core-moos <= 10.4.0 | Vulnerable |

---

## Details

### Affected code

- **Repository:** [core-moos](https://github.com/themoos/core-moos)
- **Location:** [`Core/libMOOS/Comms/MOOSCommPkt.cpp#L228`](https://github.com/themoos/core-moos/blob/ec9c77c68fcbdef8f5e4c60fe243acd223433f0c/Core/libMOOS/Comms/MOOSCommPkt.cpp#L228)

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #75](https://github.com/themoos/core-moos/pull/75)
- Proposed fix commit: [d30c14585753](https://github.com/themoos/core-moos/commit/d30c14585753f9ae39749d9628ed15c8383f0568)

---

## Recommendations

- Apply the proposed fix from [Pull Request #75](https://github.com/themoos/core-moos/pull/75) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-01 – CVE-2026-85455 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85455](https://www.cve.org/CVERecord?id=CVE-2026-85455)
- VulnCheck advisory: [MOOS core-moos through 10.4.0 MOOSDB Out-of-Bounds Read via Short Packet](https://www.vulncheck.com/advisories/moos-core-moos-through-10.4.0-moosdb-out-of-bounds-read-via-short-packet)
- Upstream pull request: [Pull Request #75](https://github.com/themoos/core-moos/pull/75)
- Proposed fix commit: [d30c14585753f9ae39749d9628ed15c8383f0568](https://github.com/themoos/core-moos/commit/d30c14585753f9ae39749d9628ed15c8383f0568)
- Marlink Cyber Security Advisory: [MCSAID-2026-041](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-041-core-moos-moosdb-out-of-bounds-read-via-short-packet.md)
- Software: [MOOS core-moos](https://github.com/themoos/core-moos)
