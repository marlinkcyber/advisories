# MOOS core-moos: MOOSDB Accept Loop Denial of Service

- **Advisory ID:** MCSAID-2026-029
- **CVE ID:** [CVE-2026-85443](https://www.cve.org/CVERecord?id=CVE-2026-85443)
- **Published:** 2026-09-01
- **Severity:** High (CVSS 7.5 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **CVSS 4.0:** 8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Uncontrolled Resource Consumption
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #83](https://github.com/themoos/core-moos/pull/83) (not merged)
- **Software:** [MOOS core-moos](https://github.com/themoos/core-moos)
- **CWE:** [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS core-moos through 10.4.0 contains a denial of service vulnerability in MOOSCommServer::ListenLoop() where the accept thread performs a blocking receive without timeout during the wire-protocol handshake. An attacker can open a TCP connection to the MOOSDB port and send no data, causing the accept thread to block indefinitely while holding the socket-list lock, preventing all subsequent client connections.

---

## Affected Versions

| Version | Status |
|---------|--------|
| core-moos <= 10.4.0 | Vulnerable |

---

## Details

### Affected code

- **Repository:** [core-moos](https://github.com/themoos/core-moos)
- **Location:** [`Core/libMOOS/Comms/MOOSCommServer.cpp#L922`](https://github.com/themoos/core-moos/blob/ec9c77c68fcbdef8f5e4c60fe243acd223433f0c/Core/libMOOS/Comms/MOOSCommServer.cpp#L922)

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #83](https://github.com/themoos/core-moos/pull/83)
- Proposed fix commit: [8d940303949a](https://github.com/themoos/core-moos/commit/8d940303949a850d4625eca2a60f27adee9c3ec4)

---

## Recommendations

- Apply the proposed fix from [Pull Request #83](https://github.com/themoos/core-moos/pull/83) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-01 – CVE-2026-85443 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85443](https://www.cve.org/CVERecord?id=CVE-2026-85443)
- VulnCheck advisory: [MOOS core-moos through 10.4.0 MOOSDB Accept Loop Denial of Service](https://www.vulncheck.com/advisories/moos-core-moos-through-10.4.0-moosdb-accept-loop-denial-of-service)
- Upstream pull request: [Pull Request #83](https://github.com/themoos/core-moos/pull/83)
- Proposed fix commit: [8d940303949a850d4625eca2a60f27adee9c3ec4](https://github.com/themoos/core-moos/commit/8d940303949a850d4625eca2a60f27adee9c3ec4)
- Marlink Cyber Security Advisory: [MCSAID-2026-029](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-029-core-moos-moosdb-accept-loop-denial-of-service.md)
- Software: [MOOS core-moos](https://github.com/themoos/core-moos)
