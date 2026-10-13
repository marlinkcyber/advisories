# MOOS-IvP: BHV_IPF Demultiplexer Memory Exhaustion via Packet Count

- **Advisory ID:** MCSAID-2026-031
- **CVE ID:** [CVE-2026-85445](https://www.cve.org/CVERecord?id=CVE-2026-85445)
- **Published:** 2026-09-02
- **Severity:** High (CVSS 7.5 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **CVSS 4.0:** 8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Memory Allocation with Excessive Size Value
- **Current state:** Fixed upstream in `main` by [Pull Request #129](https://github.com/moos-ivp/moos-ivp/pull/129) (merged 2026-10-03); not yet in a tagged release (latest release is v24.8.1)
- **Software:** [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
- **CWE:** [CWE-789: Memory Allocation with Excessive Size Value](https://cwe.mitre.org/data/definitions/789.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS-IvP through 24.8.1 contains a denial of service vulnerability in the Demuxer::addMuxPacket() function that trusts the packet count declared in mux headers without validation. Attackers can declare arbitrarily large packet counts to trigger unbounded memory allocation, exhausting system resources and causing service unavailability.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |
| moos-ivp `main` from commit [`1db7a5d19ffc`](https://github.com/moos-ivp/moos-ivp/commit/1db7a5d19ffc5dfec66e121af320cbcff24361bc) | Fixed |

---

## Details

### Affected code

- **Repository:** [moos-ivp](https://github.com/moos-ivp/moos-ivp)
- **Location:** [`ivp/src/lib_ivpbuild/Demuxer.cpp#L79`](https://github.com/moos-ivp/moos-ivp/blob/1de9ae146cd63c209e8c3fd81611a4ed2472971b/ivp/src/lib_ivpbuild/Demuxer.cpp#L79)

---

## Mitigations

Fixed upstream in the `main` branch; no tagged release containing the fix exists yet.

- Pull request: [Pull Request #129](https://github.com/moos-ivp/moos-ivp/pull/129) (merged 2026-10-03)
- Fix commit: [1db7a5d19ffc](https://github.com/moos-ivp/moos-ivp/commit/1db7a5d19ffc5dfec66e121af320cbcff24361bc)

---

## Recommendations

- Upgrade to a moos-ivp release that includes commit [`1db7a5d19ffc`](https://github.com/moos-ivp/moos-ivp/commit/1db7a5d19ffc5dfec66e121af320cbcff24361bc) once available, or build from `main` at or after that commit.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85445 published
- 2026-10-03 – Fix merged upstream in [Pull Request #129](https://github.com/moos-ivp/moos-ivp/pull/129)
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85445](https://www.cve.org/CVERecord?id=CVE-2026-85445)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 BHV_IPF Demultiplexer Memory Exhaustion via Packet Count](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-bhv-ipf-demultiplexer-memory-exhaustion-via-packet-count)
- Upstream pull request: [Pull Request #129](https://github.com/moos-ivp/moos-ivp/pull/129)
- Fix commit (PR head): [fc5649ac12915f66a9f09520cdb6b14bc6d77595](https://github.com/moos-ivp/moos-ivp/commit/fc5649ac12915f66a9f09520cdb6b14bc6d77595)
- Marlink Cyber Security Advisory: [MCSAID-2026-031](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-031-moos-ivp-bhv-ipf-demultiplexer-memory-exhaustion-via-packet-count.md)
- Merge commit: [1db7a5d19ffc5dfec66e121af320cbcff24361bc](https://github.com/moos-ivp/moos-ivp/commit/1db7a5d19ffc5dfec66e121af320cbcff24361bc)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
