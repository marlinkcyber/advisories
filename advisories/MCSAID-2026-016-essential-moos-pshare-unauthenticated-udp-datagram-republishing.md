# MOOS essential-moos: pShare Unauthenticated UDP Datagram Republishing

- **Advisory ID:** MCSAID-2026-016
- **CVE ID:** [CVE-2026-85430](https://www.cve.org/CVERecord?id=CVE-2026-85430)
- **Published:** 2026-09-02
- **Severity:** Critical (CVSS 9.1 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H)
- **CVSS 4.0:** 8.8 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Insufficient Verification of Data Authenticity
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #18](https://github.com/themoos/essential-moos/pull/18) (not merged)
- **Software:** [MOOS essential-moos](https://github.com/themoos/essential-moos)
- **CWE:** [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS essential-moos through 10.0.1 contains an authentication bypass vulnerability in pShare that accepts UDP datagrams from any source and republishes them with the attacker-claimed identity intact. Attackers can send crafted UDP datagrams to pShare input routes to inject messages into the local MOOS community under spoofed identities, or send malformed datagrams to crash the pShare process.

---

## Affected Versions

| Version | Status |
|---------|--------|
| essential-moos <= 10.0.1 | Vulnerable |

---

## Details

### Affected code

- **Repository:** [essential-moos](https://github.com/themoos/essential-moos)
- **Location:** [`Essentials/pShare/Listener.cpp#L132`](https://github.com/themoos/essential-moos/blob/b897ea86dba8b61412dc48ac0cfb5ff34cdaf5f6/Essentials/pShare/Listener.cpp#L132)

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #18](https://github.com/themoos/essential-moos/pull/18)
- Proposed fix commit: [53729b6325a9](https://github.com/themoos/essential-moos/commit/53729b6325a991a8dbd84dcd04e4707f3e592fd6)

---

## Recommendations

- Apply the proposed fix from [Pull Request #18](https://github.com/themoos/essential-moos/pull/18) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85430 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85430](https://www.cve.org/CVERecord?id=CVE-2026-85430)
- VulnCheck advisory: [MOOS essential-moos through 10.0.1 pShare Unauthenticated UDP Datagram Republishing](https://www.vulncheck.com/advisories/moos-essential-moos-through-10.0.1-pshare-unauthenticated-udp-datagram-republishing)
- Upstream pull request: [Pull Request #18](https://github.com/themoos/essential-moos/pull/18)
- Proposed fix commit: [53729b6325a991a8dbd84dcd04e4707f3e592fd6](https://github.com/themoos/essential-moos/commit/53729b6325a991a8dbd84dcd04e4707f3e592fd6)
- Marlink Cyber Security Advisory: [MCSAID-2026-016](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-016-essential-moos-pshare-unauthenticated-udp-datagram-republishing.md)
- Software: [MOOS essential-moos](https://github.com/themoos/essential-moos)
