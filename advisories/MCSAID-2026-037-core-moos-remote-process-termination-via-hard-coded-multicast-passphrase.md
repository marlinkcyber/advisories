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

Every MOOS application and the MOOSDB itself join a multicast group by default and terminate on request when presented with a pass phrase that is a string literal in the public source. A discovery action makes each process disclose its name, pid and IP address, and the kill action accepts a wildcard target, so one UDP datagram shuts down every reachable autonomy process.

---

## Affected Versions

| Version | Status |
|---------|--------|
| core-moos <= 10.4.0 | Vulnerable |

Tested against: core-moos `v10.4.0-49-gec9c77c` (commit `ec9c77c68fcbdef8f5e4c60fe243acd223433f0c`), latest master; and MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master, which bundles the same code.

---

## Impact

Remote shutdown of the entire autonomy stack - helm, PID, bridges, viewers and
the MOOSDB - with a single UDP datagram and no credential the attacker does not
already have.  The discovery action makes target enumeration free.

---

## Exploitation

Any multicast-reachable peer. The credential is published in the source tree and compiled into every binary.

Preconditions:

* Multicast reachability to 224.1.1.3:4000. Enabled by default in every MOOS application and in the MOOSDB unless `moos_suicide_disable` is set.

---

## Details

### Affected code

Each affected file is listed twice: first at its path in **core-moos** git master (commit `ec9c77c`), which is where a fix has to land, then at its path inside the copy bundled in MOOS-IvP under `MOOS_Jul2724/MOOSCore`. The two copies are byte-identical unless stated otherwise.

* **`Core/libMOOS/Comms/SuicidalSleeper.cpp`** - lines 42-50: GetDefaultPassPhrase() returns "elks have been know to waltz"; GetDefaultMulticastAddress() returns "224.1.1.3"; the default port is 4000
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/SuicidalSleeper.cpp`** - lines 42-50: GetDefaultPassPhrase() returns "elks have been know to waltz"; GetDefaultMulticastAddress() returns "224.1.1.3"; the default port is 4000
* **`Core/libMOOS/Comms/SuicidalSleeper.cpp`** - lines 135-173: Work(): parses "<Action>:<Phrase>:<AppPattern>"; '?' answers with name/pid/IP, 'K' starts a countdown and calls exit(0)
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/SuicidalSleeper.cpp`** - lines 135-173: Work(): parses "<Action>:<Phrase>:<AppPattern>"; '?' answers with name/pid/IP, 'K' starts a countdown and calls exit(0)
* **`Core/libMOOS/App/MOOSApp.cpp`** - lines 501-507: if(!GetFlagFromCommandLineOrConfigurationFile("moos_suicide_disable")) m_SuicidalSleeper.Run();
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/App/MOOSApp.cpp`** - lines 501-507: if(!GetFlagFromCommandLineOrConfigurationFile("moos_suicide_disable")) m_SuicidalSleeper.Run();
* **`Core/libMOOS/DB/MOOSDB.cpp`** - lines 410-413: the MOOSDB itself does the same
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/DB/MOOSDB.cpp`** - lines 410-413: the MOOSDB itself does the same

### Root cause

Every MOOS process joins a multicast group and listens for
`<Action>:<Phrase>:<AppPattern>`.  `?` makes it disclose its application name,
pid and IP address.  `K` makes it start a three-second countdown and call
`exit(0)`.  The phrase is a hard-coded default and the app pattern accepts
wildcards, so `K:elks have been know to waltz:*` terminates everything
reachable.

This is a remote-kill control plane that is on by default and secured by a
constant in a public repository.

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

The affected code lives in **core-moos** (`v10.4.0-49-gec9c77c`, commit `ec9c77c`) and is also bundled inside MOOS-IvP under `MOOS_Jul2724/MOOSCore`. Both copies were checked; unless noted otherwise in the text they are byte-identical, so a fix belongs in core-moos and MOOS-IvP needs to pick it up.

#### Tested / reproduced

Yes - reproduced against standalone core-moos `v10.4.0-49-gec9c77c` (commit `ec9c77c`), default production build (`cmake .. && make`, Release -O2, hardened PIE), and against the copy bundled in MOOS-IvP.

### Steps and results

A small mission (MOOSDB + iSay + pShare) was started with stock configuration.

`?:elks have been know to waltz:*` produced:

    /path/to/bin/iSay pid 3612979 on 192.0.2.31 would die
    pShare               pid 3612980 on 192.0.2.31 would die
    MOOSDB_victim9900    pid 3612970 on 192.0.2.31 would die
    MOOSDB_triage        pid 3471331 on 192.0.2.31 would die   <-- an
        unrelated MOOSDB belonging to a different test, discovered and (in the
        first run, with the `*` wildcard) killed as collateral.

`K:<phrase>:<pattern>` then terminated each target.  The shipped PoC scopes the
kill to the processes it started; `--all` reproduces the wildcard behaviour.

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #85](https://github.com/themoos/core-moos/pull/85)
- Proposed fix commit: [488806a07db9](https://github.com/themoos/core-moos/commit/488806a07db9f21eea124f48a9c0392f058f01dc)

### Recommended fix

Disable the termination listener by default and require an explicit opt-in.  If
it is retained, it must be an authenticated control channel: per-deployment keys
(no default), a MAC over the message, replay protection, rate limiting, and an
app pattern that cannot be a bare wildcard.  Never ship a shared default
credential; if no key is configured, do not start the listener.

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
