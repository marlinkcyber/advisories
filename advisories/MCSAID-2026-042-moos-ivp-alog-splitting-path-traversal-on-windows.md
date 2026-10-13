# MOOS-IvP: alog Splitting Path Traversal on Windows

- **Advisory ID:** MCSAID-2026-042
- **CVE ID:** [CVE-2026-85456](https://www.cve.org/CVERecord?id=CVE-2026-85456)
- **Published:** 2026-09-02
- **Severity:** Medium (CVSS 5.5 – CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N)
- **CVSS 4.0:** 6.8 (CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N)
- **Vulnerability type:** Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- **Current state:** Fixed upstream in `main` by [Pull Request #137](https://github.com/moos-ivp/moos-ivp/pull/137) (merged 2026-09-11); not yet in a tagged release (latest release is v24.8.1)
- **Software:** [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
- **CWE:** [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS-IvP through 24.8.1 fails to properly validate variable names extracted from alog files in the SplitHandler, allowing attackers to write files outside the split directory. Attackers can supply crafted alog files with backslash sequences in variable names to escape the output directory and append to arbitrary files on Windows systems.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |
| moos-ivp `main` from commit [`dcfad8c3380d`](https://github.com/moos-ivp/moos-ivp/commit/dcfad8c3380dac4ea48e3cd7ec65271b11aaf70d) | Fixed |

---

## Details

### Affected code

- **Repository:** [moos-ivp](https://github.com/moos-ivp/moos-ivp)
- **Location:** [`ivp/src/lib_logutils/SplitHandler.cpp#L189`](https://github.com/moos-ivp/moos-ivp/blob/1de9ae146cd63c209e8c3fd81611a4ed2472971b/ivp/src/lib_logutils/SplitHandler.cpp#L189)

---

## Mitigations

Fixed upstream in the `main` branch; no tagged release containing the fix exists yet.

- Pull request: [Pull Request #137](https://github.com/moos-ivp/moos-ivp/pull/137) (merged 2026-09-11)
- Fix commit: [dcfad8c3380d](https://github.com/moos-ivp/moos-ivp/commit/dcfad8c3380dac4ea48e3cd7ec65271b11aaf70d)

---

## Recommendations

- Upgrade to a moos-ivp release that includes commit [`dcfad8c3380d`](https://github.com/moos-ivp/moos-ivp/commit/dcfad8c3380dac4ea48e3cd7ec65271b11aaf70d) once available, or build from `main` at or after that commit.
- Do not process alog files or pathnames from untrusted sources with the affected tools.

---

## Timeline

- 2026-09-02 – CVE-2026-85456 published
- 2026-09-11 – Fix merged upstream in [Pull Request #137](https://github.com/moos-ivp/moos-ivp/pull/137)
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85456](https://www.cve.org/CVERecord?id=CVE-2026-85456)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 alog Splitting Path Traversal on Windows](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-alog-splitting-path-traversal-on-windows)
- Upstream pull request: [Pull Request #137](https://github.com/moos-ivp/moos-ivp/pull/137)
- Fix commit (PR head): [6f0619e905b325d6b88f76425673045c6e4f6f94](https://github.com/moos-ivp/moos-ivp/commit/6f0619e905b325d6b88f76425673045c6e4f6f94)
- Marlink Cyber Security Advisory: [MCSAID-2026-042](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-042-moos-ivp-alog-splitting-path-traversal-on-windows.md)
- Merge commit: [dcfad8c3380dac4ea48e3cd7ec65271b11aaf70d](https://github.com/moos-ivp/moos-ivp/commit/dcfad8c3380dac4ea48e3cd7ec65271b11aaf70d)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
