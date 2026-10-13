# MOOS core-moos: MOOSDB HTTP Server Resource Exhaustion

- **Advisory ID:** MCSAID-2026-036
- **CVE ID:** [CVE-2026-85450](https://www.cve.org/CVERecord?id=CVE-2026-85450)
- **Published:** 2026-09-01
- **Severity:** High (CVSS 7.5 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **CVSS 4.0:** 8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Allocation of Resources Without Limits or Throttling
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #79](https://github.com/themoos/core-moos/pull/79) (not merged)
- **Software:** [MOOS core-moos](https://github.com/themoos/core-moos)
- **CWE:** [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS core-moos through 10.4.0 contains a denial of service vulnerability in the MOOSDB HTTP server that creates unbounded connections and threads without limits. Attackers can open many connections and send endless header data to exhaust server threads and memory, causing service unavailability.

---

## Affected Versions

| Version | Status |
|---------|--------|
| core-moos <= 10.4.0 | Vulnerable |

---

## Details

### Affected code

- **Repository:** [core-moos](https://github.com/themoos/core-moos)
- **Location:** [`Core/libMOOS/DB/HTTPConnection.cpp#L167`](https://github.com/themoos/core-moos/blob/ec9c77c68fcbdef8f5e4c60fe243acd223433f0c/Core/libMOOS/DB/HTTPConnection.cpp#L167)

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #79](https://github.com/themoos/core-moos/pull/79)
- Proposed fix commit: [dfef92b3bc31](https://github.com/themoos/core-moos/commit/dfef92b3bc31886bc47e4d680aef583b78cb8d72)

---

## Recommendations

- Apply the proposed fix from [Pull Request #79](https://github.com/themoos/core-moos/pull/79) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-01 – CVE-2026-85450 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85450](https://www.cve.org/CVERecord?id=CVE-2026-85450)
- VulnCheck advisory: [MOOS core-moos through 10.4.0 MOOSDB HTTP Server Resource Exhaustion](https://www.vulncheck.com/advisories/moos-core-moos-through-10.4.0-moosdb-http-server-resource-exhaustion)
- Upstream pull request: [Pull Request #79](https://github.com/themoos/core-moos/pull/79)
- Proposed fix commit: [dfef92b3bc31886bc47e4d680aef583b78cb8d72](https://github.com/themoos/core-moos/commit/dfef92b3bc31886bc47e4d680aef583b78cb8d72)
- Marlink Cyber Security Advisory: [MCSAID-2026-036](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-036-core-moos-moosdb-http-server-resource-exhaustion.md)
- Software: [MOOS core-moos](https://github.com/themoos/core-moos)
