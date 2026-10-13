# MOOS-IvP: uFldNodeComms Quadratic Processing Denial of Service

- **Advisory ID:** MCSAID-2026-032
- **CVE ID:** [CVE-2026-85446](https://www.cve.org/CVERecord?id=CVE-2026-85446)
- **Published:** 2026-09-02
- **Severity:** High (CVSS 7.5 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **CVSS 4.0:** 8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Inefficient Algorithmic Complexity
- **Current state:** Fixed upstream in `main` by [Pull Request #131](https://github.com/moos-ivp/moos-ivp/pull/131) (merged 2026-10-05); not yet in a tagged release (latest release is v24.8.1)
- **Software:** [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
- **CWE:** [CWE-407: Inefficient Algorithmic Complexity](https://cwe.mitre.org/data/definitions/407.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS-IvP versions through 24.8.1 contain a quadratic processing vulnerability in uFldNodeComms where each new node identity creates a ledger entry and triggers all-pairs distribution work. Attackers can supply unbounded distinct node names in reports to drive the shoreside broker into quadratic processing, delaying or preventing distribution of legitimate node reports.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |
| moos-ivp `main` from commit [`3f0928a9712f`](https://github.com/moos-ivp/moos-ivp/commit/3f0928a9712f802d020414e190ed21a1a028d34b) | Fixed |

---

## Details

### Affected code

- **Repository:** [moos-ivp](https://github.com/moos-ivp/moos-ivp)
- **Location:** [`ivp/src/uFldNodeComms/FldNodeComms.cpp#L169`](https://github.com/moos-ivp/moos-ivp/blob/1de9ae146cd63c209e8c3fd81611a4ed2472971b/ivp/src/uFldNodeComms/FldNodeComms.cpp#L169)

---

## Mitigations

Fixed upstream in the `main` branch; no tagged release containing the fix exists yet.

- Pull request: [Pull Request #131](https://github.com/moos-ivp/moos-ivp/pull/131) (merged 2026-10-05)
- Fix commit: [3f0928a9712f](https://github.com/moos-ivp/moos-ivp/commit/3f0928a9712f802d020414e190ed21a1a028d34b)

---

## Recommendations

- Upgrade to a moos-ivp release that includes commit [`3f0928a9712f`](https://github.com/moos-ivp/moos-ivp/commit/3f0928a9712f802d020414e190ed21a1a028d34b) once available, or build from `main` at or after that commit.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85446 published
- 2026-10-05 – Fix merged upstream in [Pull Request #131](https://github.com/moos-ivp/moos-ivp/pull/131)
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85446](https://www.cve.org/CVERecord?id=CVE-2026-85446)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 uFldNodeComms Quadratic Processing Denial of Service](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-ufldnodecomms-quadratic-processing-denial-of-service)
- Upstream pull request: [Pull Request #131](https://github.com/moos-ivp/moos-ivp/pull/131)
- Fix commit (PR head): [8e30008d4eb68d83797187bd46e929e6cb06b195](https://github.com/moos-ivp/moos-ivp/commit/8e30008d4eb68d83797187bd46e929e6cb06b195)
- Marlink Cyber Security Advisory: [MCSAID-2026-032](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-032-moos-ivp-ufldnodecomms-quadratic-processing-denial-of-service.md)
- Merge commit: [3f0928a9712f802d020414e190ed21a1a028d34b](https://github.com/moos-ivp/moos-ivp/commit/3f0928a9712f802d020414e190ed21a1a028d34b)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
