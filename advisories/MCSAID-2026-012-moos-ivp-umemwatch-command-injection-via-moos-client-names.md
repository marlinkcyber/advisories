# MOOS-IvP: uMemWatch Command Injection via MOOS Client Names

- **Advisory ID:** MCSAID-2026-012
- **CVE ID:** [CVE-2026-85426](https://www.cve.org/CVERecord?id=CVE-2026-85426)
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

MOOS client names are unconstrained strings. MOOSDB publishes them verbatim in `DB_CLIENTS`, uMemWatch copies one into a temporary filename, and that filename is interpolated into two shell command lines passed to `system()`. Choosing a client name and publishing one double therefore executes arbitrary commands as the uMemWatch user.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |
| moos-ivp `main` from commit [`f56c6907aed8`](https://github.com/moos-ivp/moos-ivp/commit/f56c6907aed8b1c4b35b4b7b94593876dfa95646) | Fixed |

Tested against: MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master.

---

## Impact

Arbitrary command execution as the user running uMemWatch.  Chained with
[MCSAID-2026-010](./MCSAID-2026-010-core-moos-missing-authentication-for-moosdb-publish-subscribe-and-db-clear.md) this is unauthenticated remote code execution on any host running
uMemWatch, which is a diagnostic app operators commonly leave running.
Severity raised to critical for the same reason as [MCSAID-2026-011](./MCSAID-2026-011-moos-ivp-isay-command-injection-via-say-moos.md).

---

## Exploitation

Any peer that can connect to the MOOSDB and choose its own client name, and publish one double.

Preconditions:

* uMemWatch deployed. A configured `watch_only` list would restrict which names are processed; the default has none.
* Name constraints derived from the code, not from any security control: no ',' (DB_CLIENTS is comma-separated), no '_' (handleMailInfoPID bites at the first underscore), lower case (tmp_file uses tolower). None of these exclude ';', '$( )', backticks or redirection.

---

## Details

### Affected code

* **`ivp/src/uMemWatch/MemWatch.cpp`** - lines 147-159: handleMailDBClients(): every name in DB_CLIENTS is stored verbatim and toupper(client)+"_PID" is registered
* **`ivp/src/uMemWatch/MemWatch.cpp`** - lines 247-290: handleMailInfoPID(): the matching *_PID publication puts the original client name into m_app; no name grammar is enforced
* **`ivp/src/uMemWatch/MemWatch.cpp`** - lines 174-186: tmp_file = ".mem_info_" + tolower(app) + "_" + pid;  syscall = "appmem.sh --pid=" + pid + " > " + tmp_file;  system(syscall.c_str());
* **`ivp/src/uMemWatch/MemWatch.cpp`** - lines 189-190: syscall_rm = "rm -f " + tmp_file + " &";  system(syscall_rm.c_str());
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/DB/MOOSDB.cpp`** - lines 480-491: UpdateDBClientsVar() publishes the raw client names as a comma-separated DB_CLIENTS string

### Root cause

MOOS client names are unconstrained strings.  MOOSDB publishes them verbatim in
`DB_CLIENTS`; uMemWatch registers `<NAME>_PID` for each; when someone publishes
that variable (the attacker can), the name is copied into `m_app`.  On the next
measurement cycle the name is interpolated into a temporary filename which is
interpolated into two shell command lines passed to `system()`.

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

Connected with the client name

    x;id>/tmp/.../proof.txt;echo done>>/tmp/.../proof.txt;

MOOSDB published it in `DB_CLIENTS`, uMemWatch registered the corresponding
`X;ID>/TMP/.../PROOF.TXT;...;_PID` variable, and after publishing that variable
the proof file contained:

    uid=1001(ai) gid=1001(ai) groups=1001(ai),27(sudo),...
    done

uMemWatch's working directory also held the truncated `.mem_info_x` file, showing
where the command line was cut.

---

## Mitigations

Fixed upstream in the `main` branch; no tagged release containing the fix exists yet.

The upstream maintainers implemented their own fix in [Pull Request #141](https://github.com/moos-ivp/moos-ivp/pull/141), which supersedes the originally proposed [Pull Request #121](https://github.com/moos-ivp/moos-ivp/pull/121) (closed without merge).

- Pull request: [Pull Request #141](https://github.com/moos-ivp/moos-ivp/pull/141) (merged 2026-09-11)
- Fix commit: [f56c6907aed8](https://github.com/moos-ivp/moos-ivp/commit/f56c6907aed8b1c4b35b4b7b94593876dfa95646)

### Recommended fix

Replace both `system()` calls: invoke the helper with `posix_spawn`/`execvp` and
a validated numeric PID, and delete the temporary file with `unlink()`.  Better
still, read `/proc/<pid>/status` directly and drop the shell entirely.  Use
`mkstemp()` rather than a name derived from untrusted input.  Independently,
enforce a strict client-name grammar (`[A-Za-z0-9_.-]{1,64}`) in
`CMOOSCommServer::HandShake`, which also mitigates [MCSAID-2026-038](./MCSAID-2026-038-ui-moos-ums-buffer-overflow-via-long-moos-identifiers.md) and this one at
the source.

---

## Recommendations

- Upgrade to a moos-ivp release that includes commit [`f56c6907aed8`](https://github.com/moos-ivp/moos-ivp/commit/f56c6907aed8b1c4b35b4b7b94593876dfa95646) once available, or build from `main` at or after that commit.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85426 published
- 2026-09-11 – Fix merged upstream in [Pull Request #141](https://github.com/moos-ivp/moos-ivp/pull/141)
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85426](https://www.cve.org/CVERecord?id=CVE-2026-85426)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 uMemWatch Command Injection via MOOS Client Names](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-umemwatch-command-injection-via-moos-client-names)
- Originally proposed pull request: [Pull Request #121](https://github.com/moos-ivp/moos-ivp/pull/121)
- Upstream fix: [Pull Request #141](https://github.com/moos-ivp/moos-ivp/pull/141), commit [f56c6907aed8b1c4b35b4b7b94593876dfa95646](https://github.com/moos-ivp/moos-ivp/commit/f56c6907aed8b1c4b35b4b7b94593876dfa95646)
- Originally proposed fix commit: [0b2bd991b0ca7139b1edcf271473d33e7eccfc20](https://github.com/moos-ivp/moos-ivp/commit/0b2bd991b0ca7139b1edcf271473d33e7eccfc20)
- Marlink Cyber Security Advisory: [MCSAID-2026-012](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-012-moos-ivp-umemwatch-command-injection-via-moos-client-names.md)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
