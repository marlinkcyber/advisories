# MOOS-IvP: uFldNodeBroker Unauthenticated Shore Route Enrollment

- **Advisory ID:** MCSAID-2026-021
- **CVE ID:** [CVE-2026-85435](https://www.cve.org/CVERecord?id=CVE-2026-85435)
- **Published:** 2026-09-02
- **Severity:** Critical (CVSS 9.1 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
- **CVSS 4.0:** 9.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N)
- **Vulnerability type:** Insufficient Verification of Data Authenticity
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #124](https://github.com/moos-ivp/moos-ivp/pull/124) (not merged)
- **Software:** [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
- **CWE:** [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS-IvP uFldNodeBroker through 24.8.1 fails to validate the source of TRY_SHORE_HOST messages on the vehicle bus, allowing any publisher to enroll attacker-controlled shore routes. Attackers can publish malicious shore route messages to receive bridged vehicle traffic including sensor data and control information.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |

---

## Details

### Affected code

- **Repository:** [moos-ivp](https://github.com/moos-ivp/moos-ivp)
- **Location:** [`ivp/src/uFldNodeBroker/NodeBroker.cpp#L97`](https://github.com/moos-ivp/moos-ivp/blob/1de9ae146cd63c209e8c3fd81611a4ed2472971b/ivp/src/uFldNodeBroker/NodeBroker.cpp#L97)

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #124](https://github.com/moos-ivp/moos-ivp/pull/124)
- Proposed fix commit: [d66394f576ca](https://github.com/moos-ivp/moos-ivp/commit/d66394f576cae0c63c0a777760e1595802b83edf)

---

## Recommendations

- Apply the proposed fix from [Pull Request #124](https://github.com/moos-ivp/moos-ivp/pull/124) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85435 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85435](https://www.cve.org/CVERecord?id=CVE-2026-85435)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 uFldNodeBroker Unauthenticated Shore Route Enrollment](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-ufldnodebroker-unauthenticated-shore-route-enrollment)
- Upstream pull request: [Pull Request #124](https://github.com/moos-ivp/moos-ivp/pull/124)
- Proposed fix commit: [d66394f576cae0c63c0a777760e1595802b83edf](https://github.com/moos-ivp/moos-ivp/commit/d66394f576cae0c63c0a777760e1595802b83edf)
- Marlink Cyber Security Advisory: [MCSAID-2026-021](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-021-moos-ivp-ufldnodebroker-unauthenticated-shore-route-enrollment.md)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
