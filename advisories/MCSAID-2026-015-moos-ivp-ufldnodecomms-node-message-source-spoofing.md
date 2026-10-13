# MOOS-IvP: uFldNodeComms Node Message Source Spoofing

- **Advisory ID:** MCSAID-2026-015
- **CVE ID:** [CVE-2026-85429](https://www.cve.org/CVERecord?id=CVE-2026-85429)
- **Published:** 2026-09-02
- **Severity:** High (CVSS 7.5 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N)
- **CVSS 4.0:** 8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N)
- **Vulnerability type:** Insufficient Verification of Data Authenticity
- **Current state:** Fixed upstream in `main` by [Pull Request #122](https://github.com/moos-ivp/moos-ivp/pull/122) (merged 2026-09-11); not yet in a tagged release (latest release is v24.8.1)
- **Software:** [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
- **CWE:** [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS-IvP uFldNodeComms through 24.8.1 trusts the source node identity from the message body rather than validating it from the connection source. Attackers can craft NODE_MESSAGE packets with spoofed source identities to impersonate other nodes and post arbitrary variable notifications without validation.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |
| moos-ivp `main` from commit [`21cb05149415`](https://github.com/moos-ivp/moos-ivp/commit/21cb051494158b072fc50ab3bc774e0787774587) | Fixed |

---

## Details

### Affected code

- **Repository:** [moos-ivp](https://github.com/moos-ivp/moos-ivp)
- **Location:** [`ivp/src/uFldNodeComms/FldNodeComms.cpp#L114`](https://github.com/moos-ivp/moos-ivp/blob/1de9ae146cd63c209e8c3fd81611a4ed2472971b/ivp/src/uFldNodeComms/FldNodeComms.cpp#L114)

---

## Mitigations

Fixed upstream in the `main` branch; no tagged release containing the fix exists yet.

- Pull request: [Pull Request #122](https://github.com/moos-ivp/moos-ivp/pull/122) (merged 2026-09-11)
- Fix commit: [21cb05149415](https://github.com/moos-ivp/moos-ivp/commit/21cb051494158b072fc50ab3bc774e0787774587)

---

## Recommendations

- Upgrade to a moos-ivp release that includes commit [`21cb05149415`](https://github.com/moos-ivp/moos-ivp/commit/21cb051494158b072fc50ab3bc774e0787774587) once available, or build from `main` at or after that commit.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85429 published
- 2026-09-11 – Fix merged upstream in [Pull Request #122](https://github.com/moos-ivp/moos-ivp/pull/122)
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85429](https://www.cve.org/CVERecord?id=CVE-2026-85429)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 uFldNodeComms Node Message Source Spoofing](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-ufldnodecomms-node-message-source-spoofing)
- Upstream pull request: [Pull Request #122](https://github.com/moos-ivp/moos-ivp/pull/122)
- Fix commit (PR head): [3907ac07cdfd8a7255d65657dc18dc6b77b30b64](https://github.com/moos-ivp/moos-ivp/commit/3907ac07cdfd8a7255d65657dc18dc6b77b30b64)
- Marlink Cyber Security Advisory: [MCSAID-2026-015](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-015-moos-ivp-ufldnodecomms-node-message-source-spoofing.md)
- Merge commit: [21cb051494158b072fc50ab3bc774e0787774587](https://github.com/moos-ivp/moos-ivp/commit/21cb051494158b072fc50ab3bc774e0787774587)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
