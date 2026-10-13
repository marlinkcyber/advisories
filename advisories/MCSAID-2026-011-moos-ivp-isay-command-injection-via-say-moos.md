# MOOS-IvP: iSay Command Injection via SAY_MOOS

- **Advisory ID:** MCSAID-2026-011
- **CVE ID:** [CVE-2026-85425](https://www.cve.org/CVERecord?id=CVE-2026-85425)
- **Published:** 2026-09-02
- **Severity:** Critical (CVSS 9.8 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **CVSS 4.0:** 9.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- **Current state:** Fixed upstream in `main` by [Pull Request #141](https://github.com/moos-ivp/moos-ivp/pull/141) (merged 2026-09-11); not yet in a tagged release (latest release is v24.8.1)
- **Software:** [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
- **CWE:** [CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS-IvP iSay through 24.8.1 contains a remote code execution vulnerability in the SAY_MOOS variable handler that passes unsanitized text to a shell command. Attackers can publish SAY_MOOS messages containing backticks or command substitution syntax to execute arbitrary commands as the iSay process user.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |
| moos-ivp `main` from commit [`f56c6907aed8`](https://github.com/moos-ivp/moos-ivp/commit/f56c6907aed8b1c4b35b4b7b94593876dfa95646) | Fixed |

---

## Details

### Affected code

- **Repository:** [moos-ivp](https://github.com/moos-ivp/moos-ivp)
- **Location:** [`ivp/src/iSay/Sayer.cpp#L416`](https://github.com/moos-ivp/moos-ivp/blob/1de9ae146cd63c209e8c3fd81611a4ed2472971b/ivp/src/iSay/Sayer.cpp#L416)

---

## Mitigations

Fixed upstream in the `main` branch; no tagged release containing the fix exists yet.

The upstream maintainers implemented their own fix in [Pull Request #141](https://github.com/moos-ivp/moos-ivp/pull/141), which supersedes the originally proposed [Pull Request #120](https://github.com/moos-ivp/moos-ivp/pull/120) (closed without merge).

- Pull request: [Pull Request #141](https://github.com/moos-ivp/moos-ivp/pull/141) (merged 2026-09-11)
- Fix commit: [f56c6907aed8](https://github.com/moos-ivp/moos-ivp/commit/f56c6907aed8b1c4b35b4b7b94593876dfa95646)

---

## Recommendations

- Upgrade to a moos-ivp release that includes commit [`f56c6907aed8`](https://github.com/moos-ivp/moos-ivp/commit/f56c6907aed8b1c4b35b4b7b94593876dfa95646) once available, or build from `main` at or after that commit.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85425 published
- 2026-09-11 – Fix merged upstream in [Pull Request #141](https://github.com/moos-ivp/moos-ivp/pull/141)
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85425](https://www.cve.org/CVERecord?id=CVE-2026-85425)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 iSay Command Injection via SAY_MOOS](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-isay-command-injection-via-say-moos)
- Originally proposed pull request: [Pull Request #120](https://github.com/moos-ivp/moos-ivp/pull/120)
- Upstream fix: [Pull Request #141](https://github.com/moos-ivp/moos-ivp/pull/141), commit [f56c6907aed8b1c4b35b4b7b94593876dfa95646](https://github.com/moos-ivp/moos-ivp/commit/f56c6907aed8b1c4b35b4b7b94593876dfa95646)
- Originally proposed fix commit: [ed3a44131fd3e5528602f20adc37ba82273c1cd8](https://github.com/moos-ivp/moos-ivp/commit/ed3a44131fd3e5528602f20adc37ba82273c1cd8)
- Marlink Cyber Security Advisory: [MCSAID-2026-011](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-011-moos-ivp-isay-command-injection-via-say-moos.md)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
