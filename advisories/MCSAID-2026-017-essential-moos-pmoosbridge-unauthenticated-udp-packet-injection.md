# MOOS essential-moos: pMOOSBridge Unauthenticated UDP Packet Injection

- **Advisory ID:** MCSAID-2026-017
- **CVE ID:** [CVE-2026-85431](https://www.cve.org/CVERecord?id=CVE-2026-85431)
- **Published:** 2026-09-02
- **Severity:** High (CVSS 7.5 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N)
- **CVSS 4.0:** 8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N)
- **Vulnerability type:** Insufficient Verification of Data Authenticity
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #19](https://github.com/themoos/essential-moos/pull/19) (not merged)
- **Software:** [MOOS essential-moos](https://github.com/themoos/essential-moos)
- **CWE:** [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS essential-moos through version 10.0.1 contains an unauthenticated UDP packet injection vulnerability in pMOOSBridge when configured with UDPListen. Attackers can send crafted UDP packets to the configured port to inject arbitrary variables into the local MOOS community with spoofed source and community identifiers.

---

## Affected Versions

| Version | Status |
|---------|--------|
| essential-moos <= 10.0.1 | Vulnerable |

---

## Details

### Affected code

- **Repository:** [essential-moos](https://github.com/themoos/essential-moos)
- **Location:** [`Essentials/pMOOSBridge/MOOSUDPLink.cpp#L21`](https://github.com/themoos/essential-moos/blob/b897ea86dba8b61412dc48ac0cfb5ff34cdaf5f6/Essentials/pMOOSBridge/MOOSUDPLink.cpp#L21)

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #19](https://github.com/themoos/essential-moos/pull/19)
- Proposed fix commit: [d8441eac57d0](https://github.com/themoos/essential-moos/commit/d8441eac57d04ee89e7b82723480d10a558b45d6)

---

## Recommendations

- Apply the proposed fix from [Pull Request #19](https://github.com/themoos/essential-moos/pull/19) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85431 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85431](https://www.cve.org/CVERecord?id=CVE-2026-85431)
- VulnCheck advisory: [MOOS essential-moos through 10.0.1 pMOOSBridge Unauthenticated UDP Packet Injection](https://www.vulncheck.com/advisories/moos-essential-moos-through-10.0.1-pmoosbridge-unauthenticated-udp-packet-injection)
- Upstream pull request: [Pull Request #19](https://github.com/themoos/essential-moos/pull/19)
- Proposed fix commit: [d8441eac57d04ee89e7b82723480d10a558b45d6](https://github.com/themoos/essential-moos/commit/d8441eac57d04ee89e7b82723480d10a558b45d6)
- Marlink Cyber Security Advisory: [MCSAID-2026-017](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-017-essential-moos-pmoosbridge-unauthenticated-udp-packet-injection.md)
- Software: [MOOS essential-moos](https://github.com/themoos/essential-moos)
