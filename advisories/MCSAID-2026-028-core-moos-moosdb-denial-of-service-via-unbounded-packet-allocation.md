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

MOOS core-moos through 10.4.0 fails to validate packet length declarations in CMOOSCommPkt::OnBytesWritten(), allowing unauthenticated attackers to trigger unbounded buffer allocation by sending crafted wire packets. Attackers can send packets with large declared lengths to exhaust server memory and cause denial of service before client authentication completes.

---

## Affected Versions

| Version | Status |
|---------|--------|
| core-moos <= 10.4.0 | Vulnerable |

---

## Details

### Affected code

- **Repository:** [core-moos](https://github.com/themoos/core-moos)
- **Location:** [`Core/libMOOS/Comms/MOOSCommPkt.cpp#L99`](https://github.com/themoos/core-moos/blob/ec9c77c68fcbdef8f5e4c60fe243acd223433f0c/Core/libMOOS/Comms/MOOSCommPkt.cpp#L99)

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #81](https://github.com/themoos/core-moos/pull/81)
- Proposed fix commit: [e7ea624a7b78](https://github.com/themoos/core-moos/commit/e7ea624a7b7828b47fcd35fc43feec1f5cfbbe21)

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
