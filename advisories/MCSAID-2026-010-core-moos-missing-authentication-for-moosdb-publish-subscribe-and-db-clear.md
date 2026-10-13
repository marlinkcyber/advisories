# MOOS core-moos: Missing Authentication for MOOSDB Publish, Subscribe and DB_CLEAR

- **Advisory ID:** MCSAID-2026-010
- **CVE ID:** [CVE-2026-85424](https://www.cve.org/CVERecord?id=CVE-2026-85424)
- **Published:** 2026-09-02
- **Severity:** Critical (CVSS 9.8 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **CVSS 4.0:** 9.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Missing Authentication for Critical Function
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #84](https://github.com/themoos/core-moos/pull/84) (not merged)
- **Software:** [MOOS core-moos](https://github.com/themoos/core-moos)
- **CWE:** [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS core-moos through 10.4.0 lacks authentication in the wire protocol, allowing unauthenticated clients to connect with full publish, subscribe, and database clear privileges. Attackers can bypass the compile-time protocol string check and connect with arbitrary client names to execute privileged operations including DB_CLEAR which resets all variables and clears client mail queues.

---

## Affected Versions

| Version | Status |
|---------|--------|
| core-moos <= 10.4.0 | Vulnerable |

---

## Details

### Affected code

- **Repository:** [core-moos](https://github.com/themoos/core-moos)
- **Location:** [`Core/libMOOS/DB/MOOSDB.cpp#L1163`](https://github.com/themoos/core-moos/blob/ec9c77c68fcbdef8f5e4c60fe243acd223433f0c/Core/libMOOS/DB/MOOSDB.cpp#L1163)

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #84](https://github.com/themoos/core-moos/pull/84)
- Proposed fix commit: [5ff5cdec4424](https://github.com/themoos/core-moos/commit/5ff5cdec44242156a168cc1a545a6a21357bd3ac)

---

## Recommendations

- Apply the proposed fix from [Pull Request #84](https://github.com/themoos/core-moos/pull/84) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85424 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85424](https://www.cve.org/CVERecord?id=CVE-2026-85424)
- VulnCheck advisory: [MOOS core-moos through 10.4.0 Missing Authentication for MOOSDB Publish, Subscribe and DB_CLEAR](https://www.vulncheck.com/advisories/moos-core-moos-through-10.4.0-missing-authentication-for-moosdb-publish-subscribe-and-db-clear)
- Upstream pull request: [Pull Request #84](https://github.com/themoos/core-moos/pull/84)
- Proposed fix commit: [5ff5cdec44242156a168cc1a545a6a21357bd3ac](https://github.com/themoos/core-moos/commit/5ff5cdec44242156a168cc1a545a6a21357bd3ac)
- Marlink Cyber Security Advisory: [MCSAID-2026-010](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-010-core-moos-missing-authentication-for-moosdb-publish-subscribe-and-db-clear.md)
- Software: [MOOS core-moos](https://github.com/themoos/core-moos)
