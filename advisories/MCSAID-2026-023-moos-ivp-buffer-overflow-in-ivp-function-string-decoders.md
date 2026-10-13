# MOOS-IvP: Buffer Overflow in IvP Function String Decoders

- **Advisory ID:** MCSAID-2026-023
- **CVE ID:** [CVE-2026-85437](https://www.cve.org/CVERecord?id=CVE-2026-85437)
- **Published:** 2026-09-02
- **Severity:** Critical (CVSS 9.8 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **CVSS 4.0:** 9.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Out-of-bounds Write
- **Current state:** Fixed upstream in `main` by [Pull Request #125](https://github.com/moos-ivp/moos-ivp/pull/125) (merged 2026-10-03); not yet in a tagged release (latest release is v24.8.1)
- **Software:** [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
- **CWE:** [CWE-787: Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS-IvP through 24.8.1 contains multiple buffer overflow vulnerabilities in IvP function string decoders that trust attacker-controlled length fields without validation. Attackers can craft malicious encoded strings with mismatched declared and actual field lengths to overflow heap and stack buffers, potentially achieving remote code execution through MOOS variables or alog files.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |
| moos-ivp `main` from commit [`ebe0bf9d6ecd`](https://github.com/moos-ivp/moos-ivp/commit/ebe0bf9d6ecdc86172d4b22b983f591ea0e64ce2) | Fixed |

---

## Details

### Affected code

- **Repository:** [moos-ivp](https://github.com/moos-ivp/moos-ivp)
- **Location:** [`ivp/src/lib_ivpbuild/FunctionEncoder.cpp#L310`](https://github.com/moos-ivp/moos-ivp/blob/1de9ae146cd63c209e8c3fd81611a4ed2472971b/ivp/src/lib_ivpbuild/FunctionEncoder.cpp#L310)

---

## Mitigations

Fixed upstream in the `main` branch; no tagged release containing the fix exists yet.

- Pull request: [Pull Request #125](https://github.com/moos-ivp/moos-ivp/pull/125) (merged 2026-10-03)
- Fix commit: [ebe0bf9d6ecd](https://github.com/moos-ivp/moos-ivp/commit/ebe0bf9d6ecdc86172d4b22b983f591ea0e64ce2)

---

## Recommendations

- Upgrade to a moos-ivp release that includes commit [`ebe0bf9d6ecd`](https://github.com/moos-ivp/moos-ivp/commit/ebe0bf9d6ecdc86172d4b22b983f591ea0e64ce2) once available, or build from `main` at or after that commit.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85437 published
- 2026-10-03 – Fix merged upstream in [Pull Request #125](https://github.com/moos-ivp/moos-ivp/pull/125)
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85437](https://www.cve.org/CVERecord?id=CVE-2026-85437)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 Buffer Overflow in IvP Function String Decoders](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-buffer-overflow-in-ivp-function-string-decoders)
- Upstream pull request: [Pull Request #125](https://github.com/moos-ivp/moos-ivp/pull/125)
- Fix commit (PR head): [81ca795fcfd62b42002d277f5a2390f4c8ab8c7f](https://github.com/moos-ivp/moos-ivp/commit/81ca795fcfd62b42002d277f5a2390f4c8ab8c7f)
- Marlink Cyber Security Advisory: [MCSAID-2026-023](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-023-moos-ivp-buffer-overflow-in-ivp-function-string-decoders.md)
- Merge commit: [ebe0bf9d6ecdc86172d4b22b983f591ea0e64ce2](https://github.com/moos-ivp/moos-ivp/commit/ebe0bf9d6ecdc86172d4b22b983f591ea0e64ce2)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
