# MOOS essential-moos: pShare Unauthorized Runtime Route Reconfiguration

- **Advisory ID:** MCSAID-2026-019
- **CVE ID:** [CVE-2026-85433](https://www.cve.org/CVERecord?id=CVE-2026-85433)
- **Published:** 2026-09-02
- **Severity:** Critical (CVSS 9.8 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **CVSS 4.0:** 9.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Missing Authorization
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #20](https://github.com/themoos/essential-moos/pull/20) (not merged)
- **Software:** [MOOS essential-moos](https://github.com/themoos/essential-moos)
- **CWE:** [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS essential-moos pShare through 10.0.1 fails to properly authorize PSHARE_CMD messages, allowing any publisher to reconfigure network routes and listeners at runtime. Attackers can send crafted PSHARE_CMD messages with cmd=output or cmd=input parameters to open new listeners on arbitrary addresses and redirect or duplicate bus traffic to attacker-controlled destinations.

---

## Affected Versions

| Version | Status |
|---------|--------|
| essential-moos <= 10.0.1 | Vulnerable |

---

## Details

### Affected code

- **Repository:** [essential-moos](https://github.com/themoos/essential-moos)
- **Location:** [`Essentials/pShare/Share.cpp#L813`](https://github.com/themoos/essential-moos/blob/b897ea86dba8b61412dc48ac0cfb5ff34cdaf5f6/Essentials/pShare/Share.cpp#L813)

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #20](https://github.com/themoos/essential-moos/pull/20)
- Proposed fix commit: [8e51cedcbd8d](https://github.com/themoos/essential-moos/commit/8e51cedcbd8de9781adec2e9cce354f51750a547)

---

## Recommendations

- Apply the proposed fix from [Pull Request #20](https://github.com/themoos/essential-moos/pull/20) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85433 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85433](https://www.cve.org/CVERecord?id=CVE-2026-85433)
- VulnCheck advisory: [MOOS essential-moos through 10.0.1 pShare Unauthorized Runtime Route Reconfiguration](https://www.vulncheck.com/advisories/moos-essential-moos-through-10.0.1-pshare-unauthorized-runtime-route-reconfiguration)
- Upstream pull request: [Pull Request #20](https://github.com/themoos/essential-moos/pull/20)
- Proposed fix commit: [8e51cedcbd8de9781adec2e9cce354f51750a547](https://github.com/themoos/essential-moos/commit/8e51cedcbd8de9781adec2e9cce354f51750a547)
- Marlink Cyber Security Advisory: [MCSAID-2026-019](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-019-essential-moos-pshare-unauthorized-runtime-route-reconfiguration.md)
- Software: [MOOS essential-moos](https://github.com/themoos/essential-moos)
