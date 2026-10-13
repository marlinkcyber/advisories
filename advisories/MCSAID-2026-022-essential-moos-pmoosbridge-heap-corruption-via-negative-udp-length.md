# MOOS essential-moos: pMOOSBridge Heap Corruption via Negative UDP Length

- **Advisory ID:** MCSAID-2026-022
- **CVE ID:** [CVE-2026-85436](https://www.cve.org/CVERecord?id=CVE-2026-85436)
- **Published:** 2026-09-02
- **Severity:** High (CVSS 7.5 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **CVSS 4.0:** 8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Integer Underflow (Wrap or Wraparound)
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #21](https://github.com/themoos/essential-moos/pull/21) (not merged)
- **Software:** [MOOS essential-moos](https://github.com/themoos/essential-moos)
- **CWE:** [CWE-191: Integer Underflow (Wrap or Wraparound)](https://cwe.mitre.org/data/definitions/191.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS essential-moos through 10.0.1 contains a buffer overflow vulnerability in CMOOSUDPLink::ReadPktFromArray() that allows remote attackers to corrupt heap memory by sending UDP datagrams with negative declared lengths. Attackers can send crafted UDP packets to the configured UDPListen port to trigger an oversized memcpy operation that writes past the destination buffer, causing heap corruption and denial of service.

---

## Affected Versions

| Version | Status |
|---------|--------|
| essential-moos <= 10.0.1 | Vulnerable |

---

## Details

### Affected code

- **Repository:** [essential-moos](https://github.com/themoos/essential-moos)
- **Location:** [`Essentials/pMOOSBridge/MOOSUDPLink.cpp#L171`](https://github.com/themoos/essential-moos/blob/b897ea86dba8b61412dc48ac0cfb5ff34cdaf5f6/Essentials/pMOOSBridge/MOOSUDPLink.cpp#L171)

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #21](https://github.com/themoos/essential-moos/pull/21)
- Proposed fix commit: [613175fcf63f](https://github.com/themoos/essential-moos/commit/613175fcf63fb9c6c5329c4ec57c2d18588b33e2)

---

## Recommendations

- Apply the proposed fix from [Pull Request #21](https://github.com/themoos/essential-moos/pull/21) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85436 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85436](https://www.cve.org/CVERecord?id=CVE-2026-85436)
- VulnCheck advisory: [MOOS essential-moos through 10.0.1 pMOOSBridge Heap Corruption via Negative UDP Length](https://www.vulncheck.com/advisories/moos-essential-moos-through-10.0.1-pmoosbridge-heap-corruption-via-negative-udp-length)
- Upstream pull request: [Pull Request #21](https://github.com/themoos/essential-moos/pull/21)
- Proposed fix commit: [613175fcf63fb9c6c5329c4ec57c2d18588b33e2](https://github.com/themoos/essential-moos/commit/613175fcf63fb9c6c5329c4ec57c2d18588b33e2)
- Marlink Cyber Security Advisory: [MCSAID-2026-022](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-022-essential-moos-pmoosbridge-heap-corruption-via-negative-udp-length.md)
- Software: [MOOS essential-moos](https://github.com/themoos/essential-moos)
