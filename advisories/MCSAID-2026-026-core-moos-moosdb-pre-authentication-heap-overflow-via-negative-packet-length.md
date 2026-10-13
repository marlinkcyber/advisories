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

MOOS core-moos through 10.4.0 contains a pre-authentication heap overflow vulnerability in MOOSCommPkt packet handling that allows remote attackers to write arbitrary data by declaring a negative packet length. Attackers can exploit the signed integer check in InflateTo() and negative size conversion in recv() to overflow a four-byte heap buffer during the HandShake phase before authentication.

---

## Affected Versions

| Version | Status |
|---------|--------|
| core-moos <= 10.4.0 | Vulnerable |

---

## Details

### Affected code

- **Repository:** [core-moos](https://github.com/themoos/core-moos)
- **Location:** [`Core/libMOOS/Comms/MOOSCommPkt.cpp#L67`](https://github.com/themoos/core-moos/blob/ec9c77c68fcbdef8f5e4c60fe243acd223433f0c/Core/libMOOS/Comms/MOOSCommPkt.cpp#L67)

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #82](https://github.com/themoos/core-moos/pull/82)
- Proposed fix commit: [96c49c5cdda6](https://github.com/themoos/core-moos/commit/96c49c5cdda6e07ee734a5324e8d25ba5a7f2d7a)

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
