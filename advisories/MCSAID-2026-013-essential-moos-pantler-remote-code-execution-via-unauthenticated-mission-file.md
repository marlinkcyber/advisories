# MOOS essential-moos: pAntler Remote Code Execution via Unauthenticated MISSION_FILE

- **Advisory ID:** MCSAID-2026-013
- **CVE ID:** [CVE-2026-85427](https://www.cve.org/CVERecord?id=CVE-2026-85427)
- **Published:** 2026-09-02
- **Severity:** High (CVSS 8.1 – CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **CVSS 4.0:** 9.2 (CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Download of Code Without Integrity Check
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #17](https://github.com/themoos/essential-moos/pull/17) (not merged)
- **Software:** [MOOS essential-moos](https://github.com/themoos/essential-moos)
- **CWE:** [CWE-494: Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS essential-moos pAntler through 10.0.1 contains a remote code execution vulnerability that allows unauthenticated attackers to execute arbitrary programs by publishing a crafted MISSION_FILE message to the MOOSDB. Attackers can publish a mission file containing malicious Run entries that pAntler parses and executes via execvp() without authentication validation.

---

## Affected Versions

| Version | Status |
|---------|--------|
| essential-moos <= 10.0.1 | Vulnerable |

---

## Details

### Affected code

- **Repository:** [essential-moos](https://github.com/themoos/essential-moos)
- **Location:** [`Essentials/pAntler/Antler.cpp#L95`](https://github.com/themoos/essential-moos/blob/b897ea86dba8b61412dc48ac0cfb5ff34cdaf5f6/Essentials/pAntler/Antler.cpp#L95)

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #17](https://github.com/themoos/essential-moos/pull/17)
- Proposed fix commit: [e219f2671092](https://github.com/themoos/essential-moos/commit/e219f26710927f9c155a6b0dc11e3bd5f3da6730)

---

## Recommendations

- Apply the proposed fix from [Pull Request #17](https://github.com/themoos/essential-moos/pull/17) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85427 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85427](https://www.cve.org/CVERecord?id=CVE-2026-85427)
- VulnCheck advisory: [MOOS essential-moos through 10.0.1 pAntler Remote Code Execution via Unauthenticated MISSION_FILE](https://www.vulncheck.com/advisories/moos-essential-moos-through-10.0.1-pantler-remote-code-execution-via-unauthenticated-mission-file)
- Upstream pull request: [Pull Request #17](https://github.com/themoos/essential-moos/pull/17)
- Proposed fix commit: [e219f26710927f9c155a6b0dc11e3bd5f3da6730](https://github.com/themoos/essential-moos/commit/e219f26710927f9c155a6b0dc11e3bd5f3da6730)
- Marlink Cyber Security Advisory: [MCSAID-2026-013](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-013-essential-moos-pantler-remote-code-execution-via-unauthenticated-mission-file.md)
- Software: [MOOS essential-moos](https://github.com/themoos/essential-moos)
