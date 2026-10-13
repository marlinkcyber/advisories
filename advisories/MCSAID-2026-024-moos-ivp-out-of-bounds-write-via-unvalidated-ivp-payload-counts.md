# MOOS-IvP: Out-of-Bounds Write via Unvalidated IvP Payload Counts

- **Advisory ID:** MCSAID-2026-024
- **CVE ID:** [CVE-2026-85438](https://www.cve.org/CVERecord?id=CVE-2026-85438)
- **Published:** 2026-09-02
- **Severity:** Critical (CVSS 9.8 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **CVSS 4.0:** 9.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Integer Overflow or Wraparound
- **Current state:** Fixed upstream in `main` by [Pull Request #126](https://github.com/moos-ivp/moos-ivp/pull/126) (merged 2026-10-05); not yet in a tagged release (latest release is v24.8.1)
- **Software:** [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
- **CWE:** [CWE-190: Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS-IvP through 24.8.1 contains a buffer overflow vulnerability in StringToIvPFunction() where dimension, piece, and degree counts from encoded BHV_IPF payloads are used as allocation sizes and loop bounds without validation. Attackers can supply crafted payloads with mismatched dimension values to write attacker-controlled doubles past the end of the IvPBox weight array, causing memory corruption and potential code execution.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |
| moos-ivp `main` from commit [`718d3dbfe847`](https://github.com/moos-ivp/moos-ivp/commit/718d3dbfe847bf88b4d2178b171b926088f9ea03) | Fixed |

---

## Details

### Affected code

- **Repository:** [moos-ivp](https://github.com/moos-ivp/moos-ivp)
- **Location:** [`ivp/src/lib_ivpbuild/FunctionEncoder.cpp#L407`](https://github.com/moos-ivp/moos-ivp/blob/1de9ae146cd63c209e8c3fd81611a4ed2472971b/ivp/src/lib_ivpbuild/FunctionEncoder.cpp#L407)

---

## Mitigations

Fixed upstream in the `main` branch; no tagged release containing the fix exists yet.

- Pull request: [Pull Request #126](https://github.com/moos-ivp/moos-ivp/pull/126) (merged 2026-10-05)
- Fix commit: [718d3dbfe847](https://github.com/moos-ivp/moos-ivp/commit/718d3dbfe847bf88b4d2178b171b926088f9ea03)

---

## Recommendations

- Upgrade to a moos-ivp release that includes commit [`718d3dbfe847`](https://github.com/moos-ivp/moos-ivp/commit/718d3dbfe847bf88b4d2178b171b926088f9ea03) once available, or build from `main` at or after that commit.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85438 published
- 2026-10-05 – Fix merged upstream in [Pull Request #126](https://github.com/moos-ivp/moos-ivp/pull/126)
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85438](https://www.cve.org/CVERecord?id=CVE-2026-85438)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 Out-of-Bounds Write via Unvalidated IvP Payload Counts](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-out-of-bounds-write-via-unvalidated-ivp-payload-counts)
- Upstream pull request: [Pull Request #126](https://github.com/moos-ivp/moos-ivp/pull/126)
- Fix commit (PR head): [85f4653ff792b30c3ab14dc0eac0991d1405d904](https://github.com/moos-ivp/moos-ivp/commit/85f4653ff792b30c3ab14dc0eac0991d1405d904)
- Marlink Cyber Security Advisory: [MCSAID-2026-024](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-024-moos-ivp-out-of-bounds-write-via-unvalidated-ivp-payload-counts.md)
- Merge commit: [718d3dbfe847bf88b4d2178b171b926088f9ea03](https://github.com/moos-ivp/moos-ivp/commit/718d3dbfe847bf88b4d2178b171b926088f9ea03)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
