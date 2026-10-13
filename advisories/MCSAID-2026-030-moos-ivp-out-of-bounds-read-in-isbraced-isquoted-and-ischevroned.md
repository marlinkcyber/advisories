# MOOS-IvP: Out-of-Bounds Read in isBraced, isQuoted and isChevroned

- **Advisory ID:** MCSAID-2026-030
- **CVE ID:** [CVE-2026-85444](https://www.cve.org/CVERecord?id=CVE-2026-85444)
- **Published:** 2026-09-02
- **Severity:** High (CVSS 7.5 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **CVSS 4.0:** 8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Out-of-bounds Read
- **Current state:** Fixed upstream in `main` by [Pull Request #128](https://github.com/moos-ivp/moos-ivp/pull/128) (merged 2026-09-11); not yet in a tagged release (latest release is v24.8.1)
- **Software:** [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
- **CWE:** [CWE-125: Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS-IvP through 24.8.1 contains a buffer over-read vulnerability in isQuoted(), isBraced(), and isChevroned() functions that strip whitespace but index using the original string length. Attackers can send NODE_REPORT messages with leading or trailing whitespace to read past buffer bounds and access adjacent memory.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |
| moos-ivp `main` from commit [`f2f8cbebb59b`](https://github.com/moos-ivp/moos-ivp/commit/f2f8cbebb59b048b931f46a511b61df5388e079b) | Fixed |

---

## Details

### Affected code

- **Repository:** [moos-ivp](https://github.com/moos-ivp/moos-ivp)
- **Location:** [`ivp/src/lib_mbutil/MBUtils.cpp#L1710`](https://github.com/moos-ivp/moos-ivp/blob/1de9ae146cd63c209e8c3fd81611a4ed2472971b/ivp/src/lib_mbutil/MBUtils.cpp#L1710)

---

## Mitigations

Fixed upstream in the `main` branch; no tagged release containing the fix exists yet.

- Pull request: [Pull Request #128](https://github.com/moos-ivp/moos-ivp/pull/128) (merged 2026-09-11)
- Fix commit: [f2f8cbebb59b](https://github.com/moos-ivp/moos-ivp/commit/f2f8cbebb59b048b931f46a511b61df5388e079b)

---

## Recommendations

- Upgrade to a moos-ivp release that includes commit [`f2f8cbebb59b`](https://github.com/moos-ivp/moos-ivp/commit/f2f8cbebb59b048b931f46a511b61df5388e079b) once available, or build from `main` at or after that commit.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85444 published
- 2026-09-11 – Fix merged upstream in [Pull Request #128](https://github.com/moos-ivp/moos-ivp/pull/128)
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85444](https://www.cve.org/CVERecord?id=CVE-2026-85444)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 Out-of-Bounds Read in isBraced, isQuoted and isChevroned](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-out-of-bounds-read-in-isbraced-isquoted-and-ischevroned)
- Upstream pull request: [Pull Request #128](https://github.com/moos-ivp/moos-ivp/pull/128)
- Fix commit (PR head): [faff8adfa1a69d68614461f679ebbc1d741c51aa](https://github.com/moos-ivp/moos-ivp/commit/faff8adfa1a69d68614461f679ebbc1d741c51aa)
- Marlink Cyber Security Advisory: [MCSAID-2026-030](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-030-moos-ivp-out-of-bounds-read-in-isbraced-isquoted-and-ischevroned.md)
- Merge commit: [f2f8cbebb59b048b931f46a511b61df5388e079b](https://github.com/moos-ivp/moos-ivp/commit/f2f8cbebb59b048b931f46a511b61df5388e079b)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
