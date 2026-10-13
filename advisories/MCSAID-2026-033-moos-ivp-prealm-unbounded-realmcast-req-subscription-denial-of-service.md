# MOOS-IvP: pRealm Unbounded REALMCAST_REQ Subscription Denial of Service

- **Advisory ID:** MCSAID-2026-033
- **CVE ID:** [CVE-2026-85447](https://www.cve.org/CVERecord?id=CVE-2026-85447)
- **Published:** 2026-09-02
- **Severity:** High (CVSS 7.5 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **CVSS 4.0:** 8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Allocation of Resources Without Limits or Throttling
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #132](https://github.com/moos-ivp/moos-ivp/pull/132) (not merged)
- **Software:** [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
- **CWE:** [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS-IvP pRealm through version 24.8.1 accepts unbounded REALMCAST_REQ subscriptions without validating duration or variable list limits. Attackers can register long-lived pipeways with many variables to cause pRealm to generate excessive output indefinitely, exhausting system resources.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |

---

## Details

### Affected code

- **Repository:** [moos-ivp](https://github.com/moos-ivp/moos-ivp)
- **Location:** [`ivp/src/pRealm/PipeWay.cpp#L109`](https://github.com/moos-ivp/moos-ivp/blob/1de9ae146cd63c209e8c3fd81611a4ed2472971b/ivp/src/pRealm/PipeWay.cpp#L109)

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #132](https://github.com/moos-ivp/moos-ivp/pull/132)
- Proposed fix commit: [8a4bb9d9154a](https://github.com/moos-ivp/moos-ivp/commit/8a4bb9d9154a70e769a7290ee11dde5157c03e9b)

---

## Recommendations

- Apply the proposed fix from [Pull Request #132](https://github.com/moos-ivp/moos-ivp/pull/132) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85447 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85447](https://www.cve.org/CVERecord?id=CVE-2026-85447)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 pRealm Unbounded REALMCAST_REQ Subscription Denial of Service](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-prealm-unbounded-realmcast-req-subscription-denial-of-service)
- Upstream pull request: [Pull Request #132](https://github.com/moos-ivp/moos-ivp/pull/132)
- Proposed fix commit: [8a4bb9d9154a70e769a7290ee11dde5157c03e9b](https://github.com/moos-ivp/moos-ivp/commit/8a4bb9d9154a70e769a7290ee11dde5157c03e9b)
- Marlink Cyber Security Advisory: [MCSAID-2026-033](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-033-moos-ivp-prealm-unbounded-realmcast-req-subscription-denial-of-service.md)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
