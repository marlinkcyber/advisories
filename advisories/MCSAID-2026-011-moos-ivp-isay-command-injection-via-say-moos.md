# MOOS-IvP: iSay Command Injection via SAY_MOOS

- **Advisory ID:** MCSAID-2026-011
- **CVE ID:** [CVE-2026-85425](https://www.cve.org/CVERecord?id=CVE-2026-85425)
- **Published:** 2026-09-02
- **Severity:** Critical (CVSS 9.8 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **CVSS 4.0:** 9.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- **Current state:** Fixed upstream in `main` by [Pull Request #141](https://github.com/moos-ivp/moos-ivp/pull/141) (merged 2026-09-11); not yet in a tagged release (latest release is v24.8.1)
- **Software:** [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
- **CWE:** [CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

iSay concatenates `SAY_MOOS` text into a double-quoted shell command line and runs it with `system()`. Command substitution still happens inside double quotes, and a literal quote closes the string, so any MOOS publisher gets arbitrary command execution as the iSay user. No configuration is required and the speech binaries need not even exist.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |
| moos-ivp `main` from commit [`f56c6907aed8`](https://github.com/moos-ivp/moos-ivp/commit/f56c6907aed8b1c4b35b4b7b94593876dfa95646) | Fixed |

Tested against: MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master.

---

## Impact

Arbitrary OS command execution as the user running iSay, on the vehicle or the
shoreside box.  Combined with [MCSAID-2026-010](./MCSAID-2026-010-core-moos-missing-authentication-for-moosdb-publish-subscribe-and-db-clear.md) (no authentication on the MOOSDB
listener) this is **unauthenticated remote code execution** with a single
publication.  This triage raises the severity from high to critical for that
reason.

---

## Exploitation

Any MOOS publisher able to send SAY_MOOS to a deployed iSay - i.e. any peer that can reach the MOOSDB port ([MCSAID-2026-010](./MCSAID-2026-010-core-moos-missing-authentication-for-moosdb-publish-subscribe-and-db-clear.md)), or anything upstream of a bridge ([MCSAID-2026-016](./MCSAID-2026-016-essential-moos-pshare-unauthenticated-udp-datagram-republishing.md) and [MCSAID-2026-017](./MCSAID-2026-017-essential-moos-pmoosbridge-unauthenticated-udp-packet-injection.md)).

Preconditions:

* iSay deployed in the mission (it is a stock app, built by default).
* No configuration is needed: `os_mode` defaults to `both` (Sayer.cpp:45).
* The `say`/`espeak` binaries need not exist - the shell expands the payload before failing to exec.

---

## Details

### Affected code

* **`ivp/src/iSay/Sayer.cpp`** - lines 79-81: OnNewMail(): SAY_MOOS -> addUtterance(sval, ...)
* **`ivp/src/iSay/Utterance.cpp`** - lines 63-71: initFromString(): a plain string with no say={ / say=" / file= is stored verbatim
* **`ivp/src/iSay/Sayer.cpp`** - lines 343-360: cmd = "say -r " + rate; cmd += " \"" + text + "\" ";  (and the espeak branch)
* **`ivp/src/iSay/Sayer.cpp`** - line 416: result = system(cmd.c_str());

### Root cause

`SAY_MOOS` text is stored verbatim by `Utterance::initFromString()` whenever it
does not look like the structured form, then concatenated into a command line
inside double quotes and handed to `system()`.  Double quotes do not stop the
shell from performing command substitution, so `$(...)` and backticks execute;
a literal `"` closes the quote and lets the attacker append arbitrary commands
with `;`.

---

## Reproduction

### Test environment

Ubuntu 24.04, x86-64, gcc 13.3.0, cmake 3.28.3, FLTK 1.3.8, Python 3.14.

All four MOOS repositories were built from source with their default settings -
Release `-O2`, and every resulting binary is a hardened PIE with a stack canary,
FORTIFY, NX and full RELRO:

| Repository | Version | Built with |
| --- | --- | --- |
| core-moos | `v10.4.0-49-gec9c77c` (`ec9c77c`) | `cmake .. && make` |
| essential-moos | `10.0.1-release-22-gb897ea8` (`b897ea8`) | `cmake -DMOOS_DIR=<core-moos build> .. && make` |
| ui-moos | commit `50b9c6c` | `cmake -DBUILD_GRAPHICAL_TOOLS=ON -DBUILD_UMS=ON -DMOOS_DIR=<core-moos build> .. && make` |
| MOOS-IvP | `1de9ae146cd63c209e8c3fd81611a4ed2472971b` | `./build-moos.sh && ./build-ivp.sh` |

This is MOOS-IvP specific code. It does not exist in core-moos, essential-moos or ui-moos, so MOOS-IvP is the only affected repository.

#### Tested / reproduced

Yes - reproduced against MOOS-IvP `1de9ae146`, default production build (`./build-moos.sh && ./build-ivp.sh`).

### Steps and results

iSay was started against a stock MOOSDB with the default configuration.  One
publication of

    SAY_MOOS = $(id > /tmp/.../proof.txt; touch /tmp/.../PWNED)

produced the assembled command line (iSay helpfully publishes it as
`ISAY_DEBUGA`):

    say -r 200 "$(id > /tmp/.../proof.txt; touch /tmp/.../PWNED)"

and the proof file contained `uid=1001(ai) gid=1001(ai) ...`.  A second payload,
`hello" ; echo "INJECTED-VIA-QUOTE-BREAK" >> proof ; echo "`, also executed, so
the injection is not limited to command substitution.

---

## Mitigations

Fixed upstream in the `main` branch; no tagged release containing the fix exists yet.

The upstream maintainers implemented their own fix in [Pull Request #141](https://github.com/moos-ivp/moos-ivp/pull/141), which supersedes the originally proposed [Pull Request #120](https://github.com/moos-ivp/moos-ivp/pull/120) (closed without merge).

- Pull request: [Pull Request #141](https://github.com/moos-ivp/moos-ivp/pull/141) (merged 2026-09-11)
- Fix commit: [f56c6907aed8](https://github.com/moos-ivp/moos-ivp/commit/f56c6907aed8b1c4b35b4b7b94593876dfa95646)

### Recommended fix

Do not build a shell command line.  Execute the speech binary directly with an
`argv` array (`posix_spawn`/`fork`+`execvp`, or `boost::process`), passing the
utterance as a separate argument, or pipe the text on stdin (`espeak --stdin`
already supports this).  Separately, treat `SAY_MOOS` as a privileged variable:
either restrict who may publish it, or restrict the accepted character set to
something a text-to-speech engine actually needs.

---

## Recommendations

- Upgrade to a moos-ivp release that includes commit [`f56c6907aed8`](https://github.com/moos-ivp/moos-ivp/commit/f56c6907aed8b1c4b35b4b7b94593876dfa95646) once available, or build from `main` at or after that commit.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85425 published
- 2026-09-11 – Fix merged upstream in [Pull Request #141](https://github.com/moos-ivp/moos-ivp/pull/141)
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85425](https://www.cve.org/CVERecord?id=CVE-2026-85425)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 iSay Command Injection via SAY_MOOS](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-isay-command-injection-via-say-moos)
- Originally proposed pull request: [Pull Request #120](https://github.com/moos-ivp/moos-ivp/pull/120)
- Upstream fix: [Pull Request #141](https://github.com/moos-ivp/moos-ivp/pull/141), commit [f56c6907aed8b1c4b35b4b7b94593876dfa95646](https://github.com/moos-ivp/moos-ivp/commit/f56c6907aed8b1c4b35b4b7b94593876dfa95646)
- Originally proposed fix commit: [ed3a44131fd3e5528602f20adc37ba82273c1cd8](https://github.com/moos-ivp/moos-ivp/commit/ed3a44131fd3e5528602f20adc37ba82273c1cd8)
- Marlink Cyber Security Advisory: [MCSAID-2026-011](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-011-moos-ivp-isay-command-injection-via-say-moos.md)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
