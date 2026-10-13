# MOOS core-moos: MOOSDB HTTP Server Unauthenticated Variable Write

- **Advisory ID:** MCSAID-2026-014
- **CVE ID:** [CVE-2026-85428](https://www.cve.org/CVERecord?id=CVE-2026-85428)
- **Published:** 2026-09-01
- **Severity:** Critical (CVSS 9.8 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **CVSS 4.0:** 9.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Missing Authentication for Critical Function
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #77](https://github.com/themoos/core-moos/pull/77) (not merged)
- **Software:** [MOOS core-moos](https://github.com/themoos/core-moos)
- **CWE:** [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS core-moos through 10.4.0 contains an authentication bypass vulnerability in the optional MOOSDB HTTP server that allows unauthenticated clients to write variables. Attackers can send HTTP requests with variable names and values to the MOOSDB HTTP server port to modify MOOS variables including actuator and override commands without authentication.

---

## Affected Versions

| Version | Status |
|---------|--------|
| core-moos <= 10.4.0 | Vulnerable |

---

## Details

### Affected code

- **Repository:** [core-moos](https://github.com/themoos/core-moos)
- **Location:** [`Core/libMOOS/DB/HTTPConnection.cpp#L196`](https://github.com/themoos/core-moos/blob/ec9c77c68fcbdef8f5e4c60fe243acd223433f0c/Core/libMOOS/DB/HTTPConnection.cpp#L196)

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #77](https://github.com/themoos/core-moos/pull/77)
- Proposed fix commit: [7e3aecdbf5fe](https://github.com/themoos/core-moos/commit/7e3aecdbf5fe47980ea9399340c77940991a6fa5)

---

## Recommendations

- Apply the proposed fix from [Pull Request #77](https://github.com/themoos/core-moos/pull/77) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-01 – CVE-2026-85428 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85428](https://www.cve.org/CVERecord?id=CVE-2026-85428)
- VulnCheck advisory: [MOOS core-moos through 10.4.0 MOOSDB HTTP Server Unauthenticated Variable Write](https://www.vulncheck.com/advisories/moos-core-moos-through-10.4.0-moosdb-http-server-unauthenticated-variable-write)
- Upstream pull request: [Pull Request #77](https://github.com/themoos/core-moos/pull/77)
- Proposed fix commit: [7e3aecdbf5fe47980ea9399340c77940991a6fa5](https://github.com/themoos/core-moos/commit/7e3aecdbf5fe47980ea9399340c77940991a6fa5)
- Marlink Cyber Security Advisory: [MCSAID-2026-014](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-014-core-moos-moosdb-http-server-unauthenticated-variable-write.md)
- Software: [MOOS core-moos](https://github.com/themoos/core-moos)
