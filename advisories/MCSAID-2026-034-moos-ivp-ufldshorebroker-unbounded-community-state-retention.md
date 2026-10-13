# MOOS-IvP: uFldShoreBroker Unbounded Community State Retention

- **Advisory ID:** MCSAID-2026-034
- **CVE ID:** [CVE-2026-85448](https://www.cve.org/CVERecord?id=CVE-2026-85448)
- **Published:** 2026-09-02
- **Severity:** High (CVSS 7.5 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **CVSS 4.0:** 8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Allocation of Resources Without Limits or Throttling
- **Current state:** Fixed upstream in `main` by [Pull Request #133](https://github.com/moos-ivp/moos-ivp/pull/133) (merged 2026-09-11); not yet in a tagged release (latest release is v24.8.1)
- **Software:** [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
- **CWE:** [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS-IvP uFldShoreBroker through 24.8.1 fails to limit the number of claimed communities stored in parallel vectors within ShoreBroker::handleMailNodePing(). A single publisher can supply unbounded distinct community names to grow retained state and per-pass work without limit, causing memory exhaustion and performance degradation.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |
| moos-ivp `main` from commit [`d40a41371dae`](https://github.com/moos-ivp/moos-ivp/commit/d40a41371dae55a172b7d04319cbfd667153ff0a) | Fixed |

---

## Details

### Affected code

- **Repository:** [moos-ivp](https://github.com/moos-ivp/moos-ivp)
- **Location:** [`ivp/src/uFldShoreBroker/ShoreBroker.cpp#L124`](https://github.com/moos-ivp/moos-ivp/blob/1de9ae146cd63c209e8c3fd81611a4ed2472971b/ivp/src/uFldShoreBroker/ShoreBroker.cpp#L124)

---

## Mitigations

Fixed upstream in the `main` branch; no tagged release containing the fix exists yet.

- Pull request: [Pull Request #133](https://github.com/moos-ivp/moos-ivp/pull/133) (merged 2026-09-11)
- Fix commit: [d40a41371dae](https://github.com/moos-ivp/moos-ivp/commit/d40a41371dae55a172b7d04319cbfd667153ff0a)

---

## Recommendations

- Upgrade to a moos-ivp release that includes commit [`d40a41371dae`](https://github.com/moos-ivp/moos-ivp/commit/d40a41371dae55a172b7d04319cbfd667153ff0a) once available, or build from `main` at or after that commit.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85448 published
- 2026-09-11 – Fix merged upstream in [Pull Request #133](https://github.com/moos-ivp/moos-ivp/pull/133)
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85448](https://www.cve.org/CVERecord?id=CVE-2026-85448)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 uFldShoreBroker Unbounded Community State Retention](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-ufldshorebroker-unbounded-community-state-retention)
- Upstream pull request: [Pull Request #133](https://github.com/moos-ivp/moos-ivp/pull/133)
- Fix commit (PR head): [2cbaed2227db31f50d5542cafe08445596800801](https://github.com/moos-ivp/moos-ivp/commit/2cbaed2227db31f50d5542cafe08445596800801)
- Marlink Cyber Security Advisory: [MCSAID-2026-034](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-034-moos-ivp-ufldshorebroker-unbounded-community-state-retention.md)
- Merge commit: [d40a41371dae55a172b7d04319cbfd667153ff0a](https://github.com/moos-ivp/moos-ivp/commit/d40a41371dae55a172b7d04319cbfd667153ff0a)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
