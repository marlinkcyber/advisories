# MOOS core-moos: Off-by-One Buffer Overflow in Serial Telegram Handling

- **Advisory ID:** MCSAID-2026-040
- **CVE ID:** [CVE-2026-85454](https://www.cve.org/CVERecord?id=CVE-2026-85454)
- **Published:** 2026-09-01
- **Severity:** Medium (CVSS 6.1 – CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H)
- **CVSS 4.0:** 5.2 (CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Off-by-one Error
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #73](https://github.com/themoos/core-moos/pull/73) (not merged)
- **Software:** [MOOS core-moos](https://github.com/themoos/core-moos)
- **CWE:** [CWE-193: Off-by-one Error](https://cwe.mitre.org/data/definitions/193.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS core-moos through 10.4.0 contains a buffer overflow vulnerability in CMOOSSerialPort::GetTelegram() that writes a NUL terminator one byte past the serial telegram stack buffer. Attackers controlling the serial line can send a full-length telegram to trigger the off-by-one write, corrupting the stack and potentially enabling code execution.

---

## Affected Versions

| Version | Status |
|---------|--------|
| core-moos <= 10.4.0 | Vulnerable |

---

## Details

### Affected code

- **Repository:** [core-moos](https://github.com/themoos/core-moos)
- **Location:** [`Core/libMOOS/Utils/MOOSSerialPort.cpp#L595`](https://github.com/themoos/core-moos/blob/ec9c77c68fcbdef8f5e4c60fe243acd223433f0c/Core/libMOOS/Utils/MOOSSerialPort.cpp#L595)

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #73](https://github.com/themoos/core-moos/pull/73)
- Proposed fix commit: [befb04df2039](https://github.com/themoos/core-moos/commit/befb04df2039d0080715ea35f56268092db4ec0f)

---

## Recommendations

- Apply the proposed fix from [Pull Request #73](https://github.com/themoos/core-moos/pull/73) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-01 – CVE-2026-85454 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85454](https://www.cve.org/CVERecord?id=CVE-2026-85454)
- VulnCheck advisory: [MOOS core-moos through 10.4.0 Off-by-One Buffer Overflow in Serial Telegram Handling](https://www.vulncheck.com/advisories/moos-core-moos-through-10.4.0-off-by-one-buffer-overflow-in-serial-telegram-handling)
- Upstream pull request: [Pull Request #73](https://github.com/themoos/core-moos/pull/73)
- Proposed fix commit: [befb04df2039d0080715ea35f56268092db4ec0f](https://github.com/themoos/core-moos/commit/befb04df2039d0080715ea35f56268092db4ec0f)
- Marlink Cyber Security Advisory: [MCSAID-2026-040](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-040-core-moos-off-by-one-buffer-overflow-in-serial-telegram-handling.md)
- Software: [MOOS core-moos](https://github.com/themoos/core-moos)
