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

MOOS core-moos through 10.4.0 fails to validate that serialized string lengths are non-negative in CMOOSMsg::operator>>. Unauthenticated attackers can send a crafted message with a negative length value to the MOOSDB port, causing an unhandled exception that terminates the database process.

---

## Affected Versions

| Version | Status |
|---------|--------|
| core-moos <= 10.4.0 | Vulnerable |

---

## Details

### Affected code

- **Repository:** [core-moos](https://github.com/themoos/core-moos)
- **Location:** [`Core/libMOOS/Comms/MOOSMsg.cpp#L453`](https://github.com/themoos/core-moos/blob/ec9c77c68fcbdef8f5e4c60fe243acd223433f0c/Core/libMOOS/Comms/MOOSMsg.cpp#L453)

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #74](https://github.com/themoos/core-moos/pull/74)
- Proposed fix commit: [04c92981091f](https://github.com/themoos/core-moos/commit/04c92981091fdaa2ff85e2ba7eff94f6288bdbaf)

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
