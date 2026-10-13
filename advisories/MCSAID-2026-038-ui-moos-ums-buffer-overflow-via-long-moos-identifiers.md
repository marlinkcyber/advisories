# MOOS ui-moos: uMS Buffer Overflow via Long MOOS Identifiers

- **Advisory ID:** MCSAID-2026-038
- **CVE ID:** [CVE-2026-85452](https://www.cve.org/CVERecord?id=CVE-2026-85452)
- **Published:** 2026-09-02
- **Severity:** High (CVSS 8.8 – CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **CVSS 4.0:** 8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Out-of-bounds Write
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #5](https://github.com/themoos/ui-moos/pull/5) (not merged)
- **Software:** [MOOS ui-moos](https://github.com/themoos/ui-moos)
- **CWE:** [CWE-787: Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS ui-moos through 50b9c6c contains a buffer overflow vulnerability in ScopeTabPane.cpp and ScopeGrid.cpp where client and variable names are formatted into fixed 1024-byte buffers using sprintf without length validation. Attackers can supply arbitrarily long MOOS identifiers that overflow the buffers when an operator selects process list entries or pokes variables, enabling code execution.

---

## Affected Versions

| Version | Status |
|---------|--------|
| ui-moos up to and including commit `50b9c6c` (no tagged release exists; master also affected) | Vulnerable |

---

## Details

### Affected code

- **Repository:** [ui-moos](https://github.com/themoos/ui-moos)
- **Location:** [`Tools/Graphical/uMS/ScopeTabPane.cpp#L243`](https://github.com/themoos/ui-moos/blob/50b9c6c65169c501f746cfef1e167f74a7735e74/Tools/Graphical/uMS/ScopeTabPane.cpp#L243)

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #5](https://github.com/themoos/ui-moos/pull/5)
- Proposed fix commit: [a6ebc0bc6cb3](https://github.com/themoos/ui-moos/commit/a6ebc0bc6cb360315ce620e865f996d189cddb0e)

---

## Recommendations

- Apply the proposed fix from [Pull Request #5](https://github.com/themoos/ui-moos/pull/5) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.
- Treat MOOS variable contents and client names as untrusted in operator tools.

---

## Timeline

- 2026-09-02 – CVE-2026-85452 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85452](https://www.cve.org/CVERecord?id=CVE-2026-85452)
- VulnCheck advisory: [MOOS ui-moos through 50b9c6c uMS Buffer Overflow via Long MOOS Identifiers](https://www.vulncheck.com/advisories/moos-ui-moos-through-50b9c6c-ums-buffer-overflow-via-long-moos-identifiers)
- Upstream pull request: [Pull Request #5](https://github.com/themoos/ui-moos/pull/5)
- Proposed fix commit: [a6ebc0bc6cb360315ce620e865f996d189cddb0e](https://github.com/themoos/ui-moos/commit/a6ebc0bc6cb360315ce620e865f996d189cddb0e)
- Marlink Cyber Security Advisory: [MCSAID-2026-038](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-038-ui-moos-ums-buffer-overflow-via-long-moos-identifiers.md)
- Software: [MOOS ui-moos](https://github.com/themoos/ui-moos)
