# MOOS core-moos: Remote Process Termination via Hard-Coded Multicast Passphrase

- **Advisory ID:** MCSAID-2026-037
- **CVE ID:** [CVE-2026-85451](https://www.cve.org/CVERecord?id=CVE-2026-85451)
- **Published:** 2026-09-02
- **Severity:** High (CVSS 7.1 – CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H)
- **CVSS 4.0:** 7.1 (CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Use of Hard-coded Credentials
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #85](https://github.com/themoos/core-moos/pull/85) (not merged)
- **Software:** [MOOS core-moos](https://github.com/themoos/core-moos)
- **CWE:** [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS core-moos through 10.4.0 contains a remote process termination vulnerability in the SuicidalSleeper component that uses a hard-coded passphrase for multicast command authorization. Any multicast-reachable peer can enumerate MOOS processes and send termination commands to trigger process shutdown by exploiting the default multicast group and port with the known passphrase.

---

## Affected Versions

| Version | Status |
|---------|--------|
| core-moos <= 10.4.0 | Vulnerable |

---

## Details

### Affected code

- **Repository:** [core-moos](https://github.com/themoos/core-moos)
- **Location:** [`Core/libMOOS/Comms/SuicidalSleeper.cpp#L45`](https://github.com/themoos/core-moos/blob/ec9c77c68fcbdef8f5e4c60fe243acd223433f0c/Core/libMOOS/Comms/SuicidalSleeper.cpp#L45)

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #85](https://github.com/themoos/core-moos/pull/85)
- Proposed fix commit: [488806a07db9](https://github.com/themoos/core-moos/commit/488806a07db9f21eea124f48a9c0392f058f01dc)

---

## Recommendations

- Apply the proposed fix from [Pull Request #85](https://github.com/themoos/core-moos/pull/85) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85451 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85451](https://www.cve.org/CVERecord?id=CVE-2026-85451)
- VulnCheck advisory: [MOOS core-moos through 10.4.0 Remote Process Termination via Hard-Coded Multicast Passphrase](https://www.vulncheck.com/advisories/moos-core-moos-through-10.4.0-remote-process-termination-via-hard-coded-multicast-passphrase)
- Upstream pull request: [Pull Request #85](https://github.com/themoos/core-moos/pull/85)
- Proposed fix commit: [488806a07db9f21eea124f48a9c0392f058f01dc](https://github.com/themoos/core-moos/commit/488806a07db9f21eea124f48a9c0392f058f01dc)
- Marlink Cyber Security Advisory: [MCSAID-2026-037](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-037-core-moos-remote-process-termination-via-hard-coded-multicast-passphrase.md)
- Software: [MOOS core-moos](https://github.com/themoos/core-moos)
