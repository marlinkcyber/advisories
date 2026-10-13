# MOOS-IvP: uFldShoreBroker Bridge Route Injection via Unverified Node Ping

- **Advisory ID:** MCSAID-2026-020
- **CVE ID:** [CVE-2026-85434](https://www.cve.org/CVERecord?id=CVE-2026-85434)
- **Published:** 2026-09-02
- **Severity:** Critical (CVSS 9.1 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
- **CVSS 4.0:** 9.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N)
- **Vulnerability type:** Insufficient Verification of Data Authenticity
- **Current state:** Fixed upstream in `main` by [Pull Request #123](https://github.com/moos-ivp/moos-ivp/pull/123) (merged 2026-09-05); not yet in a tagged release (latest release is v24.8.1)
- **Software:** [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
- **CWE:** [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS-IvP uFldShoreBroker through 24.8.1 fails to verify node ping authenticity before creating outbound bridge routes. Attackers can publish NODE_BROKER_PING messages with crafted HostRecord data to redirect bridged variables to attacker-controlled addresses.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |
| moos-ivp `main` from commit [`275e6993bab0`](https://github.com/moos-ivp/moos-ivp/commit/275e6993bab098bff43bffbab09def33cdab9440) | Fixed |

---

## Details

### Affected code

- **Repository:** [moos-ivp](https://github.com/moos-ivp/moos-ivp)
- **Location:** [`ivp/src/uFldShoreBroker/ShoreBroker.cpp#L93`](https://github.com/moos-ivp/moos-ivp/blob/1de9ae146cd63c209e8c3fd81611a4ed2472971b/ivp/src/uFldShoreBroker/ShoreBroker.cpp#L93)

---

## Mitigations

Fixed upstream in the `main` branch; no tagged release containing the fix exists yet.

- Pull request: [Pull Request #123](https://github.com/moos-ivp/moos-ivp/pull/123) (merged 2026-09-05)
- Fix commit: [275e6993bab0](https://github.com/moos-ivp/moos-ivp/commit/275e6993bab098bff43bffbab09def33cdab9440)

---

## Recommendations

- Upgrade to a moos-ivp release that includes commit [`275e6993bab0`](https://github.com/moos-ivp/moos-ivp/commit/275e6993bab098bff43bffbab09def33cdab9440) once available, or build from `main` at or after that commit.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85434 published
- 2026-09-05 – Fix merged upstream in [Pull Request #123](https://github.com/moos-ivp/moos-ivp/pull/123)
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85434](https://www.cve.org/CVERecord?id=CVE-2026-85434)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 uFldShoreBroker Bridge Route Injection via Unverified Node Ping](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-ufldshorebroker-bridge-route-injection-via-unverified-node-ping)
- Upstream pull request: [Pull Request #123](https://github.com/moos-ivp/moos-ivp/pull/123)
- Fix commit (PR head): [2f5224dcd68f92ce9ae10c261bb45dd7000f4d33](https://github.com/moos-ivp/moos-ivp/commit/2f5224dcd68f92ce9ae10c261bb45dd7000f4d33)
- Marlink Cyber Security Advisory: [MCSAID-2026-020](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-020-moos-ivp-ufldshorebroker-bridge-route-injection-via-unverified-node-ping.md)
- Merge commit: [275e6993bab098bff43bffbab09def33cdab9440](https://github.com/moos-ivp/moos-ivp/commit/275e6993bab098bff43bffbab09def33cdab9440)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
