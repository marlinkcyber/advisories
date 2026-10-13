# MOOS core-moos: MOOSDB Message Source Spoofing via Wire Identity

- **Advisory ID:** MCSAID-2026-018
- **CVE ID:** [CVE-2026-85432](https://www.cve.org/CVERecord?id=CVE-2026-85432)
- **Published:** 2026-09-01
- **Severity:** High (CVSS 8.2 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L)
- **CVSS 4.0:** 8.8 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:L/SC:N/SI:N/SA:N)
- **Vulnerability type:** Authentication Bypass by Spoofing
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #76](https://github.com/themoos/core-moos/pull/76) (not merged)
- **Software:** [MOOS core-moos](https://github.com/themoos/core-moos)
- **CWE:** [CWE-290: Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS core-moos through 10.4.0 fails to validate client identity in MOOSDB message processing, allowing authenticated attackers to attribute writes to other clients by supplying arbitrary source identifiers in serialized messages. Attackers can forge message origins and cancel third-party subscriptions by exploiting the disconnect between authenticated connection identity and wire-supplied source attribution.

---

## Affected Versions

| Version | Status |
|---------|--------|
| core-moos <= 10.4.0 | Vulnerable |

---

## Details

### Affected code

- **Repository:** [core-moos](https://github.com/themoos/core-moos)
- **Location:** [`Core/libMOOS/DB/MOOSDB.cpp#L748`](https://github.com/themoos/core-moos/blob/ec9c77c68fcbdef8f5e4c60fe243acd223433f0c/Core/libMOOS/DB/MOOSDB.cpp#L748)

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #76](https://github.com/themoos/core-moos/pull/76)
- Proposed fix commit: [26308f0e393f](https://github.com/themoos/core-moos/commit/26308f0e393f0e80bfa09b275891e776b8dbf522)

---

## Recommendations

- Apply the proposed fix from [Pull Request #76](https://github.com/themoos/core-moos/pull/76) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-01 – CVE-2026-85432 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85432](https://www.cve.org/CVERecord?id=CVE-2026-85432)
- VulnCheck advisory: [MOOS core-moos through 10.4.0 MOOSDB Message Source Spoofing via Wire Identity](https://www.vulncheck.com/advisories/moos-core-moos-through-10.4.0-moosdb-message-source-spoofing-via-wire-identity)
- Upstream pull request: [Pull Request #76](https://github.com/themoos/core-moos/pull/76)
- Proposed fix commit: [26308f0e393f0e80bfa09b275891e776b8dbf522](https://github.com/themoos/core-moos/commit/26308f0e393f0e80bfa09b275891e776b8dbf522)
- Marlink Cyber Security Advisory: [MCSAID-2026-018](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-018-core-moos-moosdb-message-source-spoofing-via-wire-identity.md)
- Software: [MOOS core-moos](https://github.com/themoos/core-moos)
