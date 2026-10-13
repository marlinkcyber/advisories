# MOOS core-moos: MOOSDB HTTP Pages Stored Cross-Site Scripting

- **Advisory ID:** MCSAID-2026-039
- **CVE ID:** [CVE-2026-85453](https://www.cve.org/CVERecord?id=CVE-2026-85453)
- **Published:** 2026-09-01
- **Severity:** Medium (CVSS 6.1 – CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)
- **CVSS 4.0:** 5.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N)
- **Vulnerability type:** Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #78](https://github.com/themoos/core-moos/pull/78) (not merged)
- **Software:** [MOOS core-moos](https://github.com/themoos/core-moos)
- **CWE:** [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS core-moos through 10.4.0 fails to escape database contents when rendering MOOSDB HTTP pages, allowing attackers to inject malicious scripts. Any MOOS publisher can set variable values containing script payloads that execute in the browser of operators viewing the web interface.

---

## Affected Versions

| Version | Status |
|---------|--------|
| core-moos <= 10.4.0 | Vulnerable |

---

## Details

### Affected code

- **Repository:** [core-moos](https://github.com/themoos/core-moos)
- **Location:** [`Core/libMOOS/DB/HTTPConnection.cpp#L460`](https://github.com/themoos/core-moos/blob/ec9c77c68fcbdef8f5e4c60fe243acd223433f0c/Core/libMOOS/DB/HTTPConnection.cpp#L460)

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #78](https://github.com/themoos/core-moos/pull/78)
- Proposed fix commit: [a3f26f099bb0](https://github.com/themoos/core-moos/commit/a3f26f099bb08decb143f704d8b1ca16ae405b44)

---

## Recommendations

- Apply the proposed fix from [Pull Request #78](https://github.com/themoos/core-moos/pull/78) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.
- Treat MOOS variable contents and client names as untrusted in operator tools.

---

## Timeline

- 2026-09-01 – CVE-2026-85453 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85453](https://www.cve.org/CVERecord?id=CVE-2026-85453)
- VulnCheck advisory: [MOOS core-moos through 10.4.0 MOOSDB HTTP Pages Stored Cross-Site Scripting](https://www.vulncheck.com/advisories/moos-core-moos-through-10.4.0-moosdb-http-pages-stored-cross-site-scripting)
- Upstream pull request: [Pull Request #78](https://github.com/themoos/core-moos/pull/78)
- Proposed fix commit: [a3f26f099bb08decb143f704d8b1ca16ae405b44](https://github.com/themoos/core-moos/commit/a3f26f099bb08decb143f704d8b1ca16ae405b44)
- Marlink Cyber Security Advisory: [MCSAID-2026-039](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-039-core-moos-moosdb-http-pages-stored-cross-site-scripting.md)
- Software: [MOOS core-moos](https://github.com/themoos/core-moos)
