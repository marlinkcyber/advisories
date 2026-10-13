# MOOS-IvP: pMarineViewer Unbounded Memory Consumption via NODE_REPORT

- **Advisory ID:** MCSAID-2026-035
- **CVE ID:** [CVE-2026-85449](https://www.cve.org/CVERecord?id=CVE-2026-85449)
- **Published:** 2026-09-02
- **Severity:** High (CVSS 7.5 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **CVSS 4.0:** 8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Allocation of Resources Without Limits or Throttling
- **Current state:** Fixed upstream in `main` by [Pull Request #134](https://github.com/moos-ivp/moos-ivp/pull/134) (merged 2026-09-11); not yet in a tagged release (latest release is v24.8.1)
- **Software:** [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
- **CWE:** [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS-IvP pMarineViewer through 24.8.1 fails to limit the number of tracked node identities from NODE_REPORT messages, allowing attackers to exhaust memory by supplying unbounded distinct node names. Attackers can publish crafted NODE_REPORT data to cause memory exhaustion and stall the operator display without authentication.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |
| moos-ivp `main` from commit [`5650f5eb824d`](https://github.com/moos-ivp/moos-ivp/commit/5650f5eb824dbb94a790c4f4ca07d525ada5a12a) | Fixed |

---

## Details

### Affected code

- **Repository:** [moos-ivp](https://github.com/moos-ivp/moos-ivp)
- **Location:** [`ivp/src/lib_geodaid/ContactLedger.cpp#L186`](https://github.com/moos-ivp/moos-ivp/blob/1de9ae146cd63c209e8c3fd81611a4ed2472971b/ivp/src/lib_geodaid/ContactLedger.cpp#L186)

---

## Mitigations

Fixed upstream in the `main` branch; no tagged release containing the fix exists yet.

- Pull request: [Pull Request #134](https://github.com/moos-ivp/moos-ivp/pull/134) (merged 2026-09-11)
- Fix commit: [5650f5eb824d](https://github.com/moos-ivp/moos-ivp/commit/5650f5eb824dbb94a790c4f4ca07d525ada5a12a)

---

## Recommendations

- Upgrade to a moos-ivp release that includes commit [`5650f5eb824d`](https://github.com/moos-ivp/moos-ivp/commit/5650f5eb824dbb94a790c4f4ca07d525ada5a12a) once available, or build from `main` at or after that commit.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85449 published
- 2026-09-11 – Fix merged upstream in [Pull Request #134](https://github.com/moos-ivp/moos-ivp/pull/134)
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85449](https://www.cve.org/CVERecord?id=CVE-2026-85449)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 pMarineViewer Unbounded Memory Consumption via NODE_REPORT](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-pmarineviewer-unbounded-memory-consumption-via-node-report)
- Upstream pull request: [Pull Request #134](https://github.com/moos-ivp/moos-ivp/pull/134)
- Fix commit (PR head): [4d8d0693d3f8bf8907dc0aed04ea488d85af9f22](https://github.com/moos-ivp/moos-ivp/commit/4d8d0693d3f8bf8907dc0aed04ea488d85af9f22)
- Marlink Cyber Security Advisory: [MCSAID-2026-035](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-035-moos-ivp-pmarineviewer-unbounded-memory-consumption-via-node-report.md)
- Merge commit: [5650f5eb824dbb94a790c4f4ca07d525ada5a12a](https://github.com/moos-ivp/moos-ivp/commit/5650f5eb824dbb94a790c4f4ca07d525ada5a12a)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
