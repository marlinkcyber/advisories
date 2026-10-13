# MOOS essential-moos: pAntler Remote Code Execution via Unauthenticated MISSION_FILE

- **Advisory ID:** MCSAID-2026-013
- **CVE ID:** [CVE-2026-85427](https://www.cve.org/CVERecord?id=CVE-2026-85427)
- **Published:** 2026-09-02
- **Severity:** High (CVSS 8.1 – CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **CVSS 4.0:** 9.2 (CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Download of Code Without Integrity Check
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #17](https://github.com/themoos/essential-moos/pull/17) (not merged)
- **Software:** [MOOS essential-moos](https://github.com/themoos/essential-moos)
- **CWE:** [CWE-494: Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

In headless mode pAntler acts on any message named `MISSION_FILE`, with no check of who sent it. It writes the body to disk, tears down the running mission, and launches whatever executables the received file names, with an argv the file also controls. One publication is arbitrary code execution plus mission destruction.

---

## Affected Versions

| Version | Status |
|---------|--------|
| essential-moos <= 10.0.1 | Vulnerable |

Tested against: essential-moos `10.0.1-release-22-gb897ea8` (commit `b897ea86dba8b61412dc48ac0cfb5ff34cdaf5f6`), latest master; and MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master, which bundles the same code.

---

## Impact

Arbitrary code execution with pAntler's OS privileges, plus destruction of the
running mission (pAntler stops everything it launched first).  On a vehicle this
is complete takeover of the autonomy payload.  Severity raised to critical
because it needs no credential ([MCSAID-2026-010](./MCSAID-2026-010-core-moos-missing-authentication-for-moosdb-publish-subscribe-and-db-clear.md)) and grants code execution plus
mission denial in one message.

---

## Exploitation

Any publisher on the coordinating MOOSDB.

Preconditions:

* pAntler running in headless/distributed mode (`pAntler <host> <port> <name>`). No checked-in mission uses it, but it is a documented supported mode for distributed launches.

---

## Details

### Affected code

Each affected file is listed twice: first at its path in **essential-moos** git master (commit `b897ea8`), which is where a fix has to land, then at its path inside the copy bundled in MOOS-IvP under `MOOS_Jul2724/MOOSEssentials`. The two copies are byte-identical unless stated otherwise.

* **`Essentials/pAntler/Antler.cpp`** - lines 92-148: DoRemoteControl(): PeekMail(NewMail,"MISSION_FILE",Msg) matches on the variable name only; the body is written to runtime_<ts>.moos and the current job is torn down
* **`MOOS_Jul2724/MOOSEssentials/Essentials/pAntler/Antler.cpp`** - lines 92-148: DoRemoteControl(): PeekMail(NewMail,"MISSION_FILE",Msg) matches on the variable name only; the body is written to runtime_<ts>.moos and the current job is torn down
* **`Essentials/pAntler/Antler.cpp`** - lines 367-459: Spawn(): parses `Run = <exe> @ <opts> ~ <name>` out of the received file
* **`MOOS_Jul2724/MOOSEssentials/Essentials/pAntler/Antler.cpp`** - lines 367-459: Spawn(): parses `Run = <exe> @ <opts> ~ <name>` out of the received file
* **`Essentials/pAntler/Antler.cpp`** - lines 660-820: CreateMOOSProcess(): resolves the executable path and builds argv from ExtraProcessParams
* **`MOOS_Jul2724/MOOSEssentials/Essentials/pAntler/Antler.cpp`** - lines 660-820: CreateMOOSProcess(): resolves the executable path and builds argv from ExtraProcessParams
* **`Essentials/pAntler/Antler.cpp`** - lines 960-1037: DoNixOSLaunch(): execvp(pNewProc->m_sApp.c_str(), pExecVParams)
* **`MOOS_Jul2724/MOOSEssentials/Essentials/pAntler/Antler.cpp`** - lines 960-1037: DoNixOSLaunch(): execvp(pNewProc->m_sApp.c_str(), pExecVParams)
* **`Essentials/pAntler/AntlerMain.cpp`** - lines 175-181: headless mode is entered as `pAntler <DBHost> <DBPort> <AntlerName>`
* **`MOOS_Jul2724/MOOSEssentials/Essentials/pAntler/AntlerMain.cpp`** - lines 175-181: headless mode is entered as `pAntler <DBHost> <DBPort> <AntlerName>`

### Root cause

In headless mode pAntler polls for a variable literally named `MISSION_FILE`.
`PeekMail` matches on the name only - no publisher check, no signature, no
freshness check.  The body is written to `runtime_<timestamp>.moos`, the running
mission is signalled to quit, and the new file is then `Spawn()`ed: every
`Run =` line in its `ANTLER` block is parsed and the named executable is launched
with `execvp` and an argv built from the file's own `ExtraProcessParams`.

Using `InhibitMOOSParams=true` the attacker gets full control of argv, so
`Run = /bin/sh @ InhibitMOOSParams=true,ExtraProcessParams=P ~ x` with
`P = -c,<commands>` is arbitrary shell.

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

The affected code lives in **essential-moos** (`10.0.1-release-22-gb897ea8`, commit `b897ea8`) and is also bundled inside MOOS-IvP under `MOOS_Jul2724/MOOSEssentials`. Both copies were checked; unless noted otherwise in the text they are byte-identical, so a fix belongs in essential-moos and MOOS-IvP needs to pick it up.

#### Tested / reproduced

Yes - reproduced against essential-moos `10.0.1-release-22-gb897ea8`, default production build: pAntler launched `/bin/sh` with attacker argv and tore down the running mission.

### Steps and results

`pAntler 127.0.0.1 <port> drone1` was started against a stock MOOSDB.  A single
381-byte `MISSION_FILE` publication from a client called
`not-the-mission-commander` produced, in pAntler's own log:

    |***** Dynamic Brief *****|
    runtime__23_8_2026_____15_50.moos received [381 bytes]
    shutting down all current spawned processes:
    |****** Launch ******|
    [000] Process: /bin/sh         ~ innocent_logger launched successfully

and the injected process wrote:

    uid=1001(ai) gid=1001(ai) groups=1001(ai),27(sudo),...
    ai
    PWNED-BY-MISSION_FILE

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #17](https://github.com/themoos/essential-moos/pull/17)
- Proposed fix commit: [e219f2671092](https://github.com/themoos/essential-moos/commit/e219f26710927f9c155a6b0dc11e3bd5f3da6730)

### Recommended fix

Do not accept a mission from the bus without proving where it came from.
Require a detached signature from an authorised mission-authority key, with a
nonce or monotonic version to stop replay.  Enforce server-side publish ACLs on
`MISSION_FILE`.  Constrain what a received mission may launch: an allow-list of
executables and a ban on `InhibitMOOSParams` for received missions.  Consider
requiring local operator confirmation before replacing a running job.

---

## Recommendations

- Apply the proposed fix from [Pull Request #17](https://github.com/themoos/essential-moos/pull/17) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85427 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85427](https://www.cve.org/CVERecord?id=CVE-2026-85427)
- VulnCheck advisory: [MOOS essential-moos through 10.0.1 pAntler Remote Code Execution via Unauthenticated MISSION_FILE](https://www.vulncheck.com/advisories/moos-essential-moos-through-10.0.1-pantler-remote-code-execution-via-unauthenticated-mission-file)
- Upstream pull request: [Pull Request #17](https://github.com/themoos/essential-moos/pull/17)
- Proposed fix commit: [e219f26710927f9c155a6b0dc11e3bd5f3da6730](https://github.com/themoos/essential-moos/commit/e219f26710927f9c155a6b0dc11e3bd5f3da6730)
- Marlink Cyber Security Advisory: [MCSAID-2026-013](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-013-essential-moos-pantler-remote-code-execution-via-unauthenticated-mission-file.md)
- Software: [MOOS essential-moos](https://github.com/themoos/essential-moos)
