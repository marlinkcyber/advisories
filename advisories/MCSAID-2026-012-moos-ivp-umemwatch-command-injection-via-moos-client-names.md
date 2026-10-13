# MOOS-IvP: uMemWatch Command Injection via MOOS Client Names

- **Advisory ID:** MCSAID-2026-012
- **CVE ID:** [CVE-2026-85426](https://www.cve.org/CVERecord?id=CVE-2026-85426)
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

MOOS-IvP uMemWatch through 24.8.1 constructs shell commands from attacker-chosen MOOS client names without sanitization. Attackers can inject shell metacharacters into client names to execute arbitrary commands as the uMemWatch process user through unquoted redirection targets in system calls.

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
- **Location:** [`ivp/src/uMemWatch/MemWatch.cpp#L182`](https://github.com/moos-ivp/moos-ivp/blob/1de9ae146cd63c209e8c3fd81611a4ed2472971b/ivp/src/uMemWatch/MemWatch.cpp#L182)

---

## Mitigations

Fixed upstream in the `main` branch; no tagged release containing the fix exists yet.

The upstream maintainers implemented their own fix in [Pull Request #141](https://github.com/moos-ivp/moos-ivp/pull/141), which supersedes the originally proposed [Pull Request #121](https://github.com/moos-ivp/moos-ivp/pull/121) (closed without merge).

- Pull request: [Pull Request #141](https://github.com/moos-ivp/moos-ivp/pull/141) (merged 2026-09-11)
- Fix commit: [f56c6907aed8](https://github.com/moos-ivp/moos-ivp/commit/f56c6907aed8b1c4b35b4b7b94593876dfa95646)

---

## Recommendations

- Upgrade to a moos-ivp release that includes commit [`f56c6907aed8`](https://github.com/moos-ivp/moos-ivp/commit/f56c6907aed8b1c4b35b4b7b94593876dfa95646) once available, or build from `main` at or after that commit.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85426 published
- 2026-09-11 – Fix merged upstream in [Pull Request #141](https://github.com/moos-ivp/moos-ivp/pull/141)
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85426](https://www.cve.org/CVERecord?id=CVE-2026-85426)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 uMemWatch Command Injection via MOOS Client Names](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-umemwatch-command-injection-via-moos-client-names)
- Originally proposed pull request: [Pull Request #121](https://github.com/moos-ivp/moos-ivp/pull/121)
- Upstream fix: [Pull Request #141](https://github.com/moos-ivp/moos-ivp/pull/141), commit [f56c6907aed8b1c4b35b4b7b94593876dfa95646](https://github.com/moos-ivp/moos-ivp/commit/f56c6907aed8b1c4b35b4b7b94593876dfa95646)
- Originally proposed fix commit: [0b2bd991b0ca7139b1edcf271473d33e7eccfc20](https://github.com/moos-ivp/moos-ivp/commit/0b2bd991b0ca7139b1edcf271473d33e7eccfc20)
- Marlink Cyber Security Advisory: [MCSAID-2026-012](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-012-moos-ivp-umemwatch-command-injection-via-moos-client-names.md)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
