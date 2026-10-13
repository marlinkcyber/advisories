# MOOS-IvP: alogsplit Command Injection via Input Pathname

- **Advisory ID:** MCSAID-2026-025
- **CVE ID:** [CVE-2026-85439](https://www.cve.org/CVERecord?id=CVE-2026-85439)
- **Published:** 2026-09-02
- **Severity:** High (CVSS 7.8 – CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **CVSS 4.0:** 8.5 (CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- **Current state:** Fixed upstream in `main` by [Pull Request #127](https://github.com/moos-ivp/moos-ivp/pull/127) (merged 2026-09-05); not yet in a tagged release (latest release is v24.8.1)
- **Software:** [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
- **CWE:** [CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS-IvP through 24.8.1 contains a remote code execution vulnerability in alogsplit's SplitHandler::handlePreCheckSplitDir() function that fails to sanitize shell metacharacters in log file pathnames. Attackers can embed shell syntax in log file names or the --dir parameter to execute arbitrary commands with the privileges of the operator running alogsplit.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |
| moos-ivp `main` from commit [`5b054c36f5a4`](https://github.com/moos-ivp/moos-ivp/commit/5b054c36f5a4a6d37b3bc0c010e42080a822d399) | Fixed |

---

## Details

### Affected code

- **Repository:** [moos-ivp](https://github.com/moos-ivp/moos-ivp)
- **Location:** [`ivp/src/lib_logutils/SplitHandler.cpp#L608`](https://github.com/moos-ivp/moos-ivp/blob/1de9ae146cd63c209e8c3fd81611a4ed2472971b/ivp/src/lib_logutils/SplitHandler.cpp#L608)

---

## Mitigations

Fixed upstream in the `main` branch; no tagged release containing the fix exists yet.

- Pull request: [Pull Request #127](https://github.com/moos-ivp/moos-ivp/pull/127) (merged 2026-09-05)
- Fix commit: [5b054c36f5a4](https://github.com/moos-ivp/moos-ivp/commit/5b054c36f5a4a6d37b3bc0c010e42080a822d399)

---

## Recommendations

- Upgrade to a moos-ivp release that includes commit [`5b054c36f5a4`](https://github.com/moos-ivp/moos-ivp/commit/5b054c36f5a4a6d37b3bc0c010e42080a822d399) once available, or build from `main` at or after that commit.
- Do not process alog files or pathnames from untrusted sources with the affected tools.

---

## Timeline

- 2026-09-02 – CVE-2026-85439 published
- 2026-09-05 – Fix merged upstream in [Pull Request #127](https://github.com/moos-ivp/moos-ivp/pull/127)
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85439](https://www.cve.org/CVERecord?id=CVE-2026-85439)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 alogsplit Command Injection via Input Pathname](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-alogsplit-command-injection-via-input-pathname)
- Upstream pull request: [Pull Request #127](https://github.com/moos-ivp/moos-ivp/pull/127)
- Fix commit (PR head): [f684d77d9d6e9e96dbfce46f05988d5a643f2b60](https://github.com/moos-ivp/moos-ivp/commit/f684d77d9d6e9e96dbfce46f05988d5a643f2b60)
- Marlink Cyber Security Advisory: [MCSAID-2026-025](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-025-moos-ivp-alogsplit-command-injection-via-input-pathname.md)
- Merge commit: [5b054c36f5a4a6d37b3bc0c010e42080a822d399](https://github.com/moos-ivp/moos-ivp/commit/5b054c36f5a4a6d37b3bc0c010e42080a822d399)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
