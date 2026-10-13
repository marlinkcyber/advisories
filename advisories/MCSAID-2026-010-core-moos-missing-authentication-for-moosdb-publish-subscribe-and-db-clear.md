# MOOS core-moos: Missing Authentication for MOOSDB Publish, Subscribe and DB_CLEAR

- **Advisory ID:** MCSAID-2026-010
- **CVE ID:** [CVE-2026-85424](https://www.cve.org/CVERecord?id=CVE-2026-85424)
- **Published:** 2026-09-02
- **Severity:** Critical (CVSS 9.8 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **CVSS 4.0:** 9.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Missing Authentication for Critical Function
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #84](https://github.com/themoos/core-moos/pull/84) (not merged)
- **Software:** [MOOS core-moos](https://github.com/themoos/core-moos)
- **CWE:** [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

The MOOS v10 protocol has no authentication. A peer sends a 32-byte protocol string that is a compile-time constant in the public source, plus any unused client name, and is then a fully privileged client: publish, subscribe, wildcard-subscribe, enumerate the namespace and the client list, and issue `DB_CLEAR`, which wipes every variable's state and destroys every client's pending mail. The listener binds all interfaces by default.

---

## Affected Versions

| Version | Status |
|---------|--------|
| core-moos <= 10.4.0 | Vulnerable |

Tested against: core-moos `v10.4.0-49-gec9c77c` (commit `ec9c77c68fcbdef8f5e4c60fe243acd223433f0c`), latest master; and MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master, which bundles the same code.

---

## Impact

Complete compromise of the autonomy bus: disclosure of all operational data,
injection of actuator and mission commands, denial of data to legitimate
clients, and destruction of database state.  It is also the precondition that
turns the other issues in this series that need a MOOSDB connection (for example [MCSAID-2026-011](./MCSAID-2026-011-moos-ivp-isay-command-injection-via-say-moos.md), [MCSAID-2026-012](./MCSAID-2026-012-moos-ivp-umemwatch-command-injection-via-moos-client-names.md) and [MCSAID-2026-013](./MCSAID-2026-013-essential-moos-pantler-remote-code-execution-via-unauthenticated-mission-file.md)) into unauthenticated attacks.  Severity
raised to critical because the exposure is total and the effort is nil.

---

## Exploitation

Any unauthenticated network peer that can reach the MOOSDB TCP port.

Preconditions:

* Network reachability. The listener binds all interfaces, so this is whatever the deployment's firewalling allows.

---

## Details

### Affected code

Each affected file is listed twice: first at its path in **core-moos** git master (commit `ec9c77c`), which is where a fix has to land, then at its path inside the copy bundled in MOOS-IvP under `MOOS_Jul2724/MOOSCore`. The two copies are byte-identical unless stated otherwise.

* **`Core/libMOOS/Comms/MOOSCommServer.cpp`** - lines 919-1005: CheckProtocol() compares a public string; HandShake() then accepts any unused client name. That is the entire admission control.
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/MOOSCommServer.cpp`** - lines 919-1005: CheckProtocol() compares a public string; HandShake() then accepts any unused client name. That is the entire admission control.
* **`Core/libMOOS/Comms/MOOSCommServer.cpp`** - line 409, and `XPCTcpSocket.cpp` lines 246-256: the listen socket is bound without restricting the address, i.e. INADDR_ANY
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/MOOSCommServer.cpp`** - line 409, and `XPCTcpSocket.cpp` lines 246-256: the listen socket is bound without restricting the address, i.e. INADDR_ANY
* **`Core/libMOOS/DB/MOOSDB.cpp`** - lines 671-697: ProcessMsg(): NOTIFY / REGISTER / UNREGISTER / WILDCARD_* / SERVER_REQUEST are dispatched with no principal and no ACL
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/DB/MOOSDB.cpp`** - lines 671-697: ProcessMsg(): NOTIFY / REGISTER / UNREGISTER / WILDCARD_* / SERVER_REQUEST are dispatched with no principal and no ACL
* **`Core/libMOOS/DB/MOOSDB.cpp`** - lines 1145-1169: DoServerRequest(): ALL, PROC_SUMMARY, VAR_SUMMARY and DB_CLEAR are available to anyone
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/DB/MOOSDB.cpp`** - lines 1145-1169: DoServerRequest(): ALL, PROC_SUMMARY, VAR_SUMMARY and DB_CLEAR are available to anyone
* **`Core/libMOOS/DB/MOOSDB.cpp`** - lines 1377-1411: OnClearRequested(): resets every variable and destroys every client's pending mail
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/DB/MOOSDB.cpp`** - lines 1377-1411: OnClearRequested(): resets every variable and destroys every client's pending mail

### Root cause

The MOOS v10 wire protocol has no authentication mechanism at all.  A peer sends
the 32-byte protocol string `ELKS CAN'T DANCE 2/8/10` - which is a compile-time
constant in the public source - and a client name that is only checked for
uniqueness.  From that point it is a fully privileged client: it can publish and
subscribe to anything, wildcard-subscribe to everything, enumerate the variable
namespace and the client list, and issue `DB_CLEAR`.

`DB_CLEAR` is the sharpest edge: it resets every variable's value, timestamp and
writer list and empties every client's pending mail queue.

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

Connected as `definitely-not-authorised`:

* `MOOS_WELCOME` returned, community `triage`, async support on.
* `VAR_SUMMARY` returned the whole namespace; `PROC_SUMMARY` returned the client
  list.
* Wildcard-subscribed to `*:*`.
* Injected `DESIRED_HEADING=270`, `DESIRED_SPEED=5.0`,
  `MOOS_MANUAL_OVERRIDE='false'`; a separate victim client received all three.
* Cancelled the victim's `DESIRED_HEADING` subscription (via [MCSAID-2026-018](./MCSAID-2026-018-core-moos-moosdb-message-source-spoofing-via-wire-identity.md)).
* `DB_CLEAR`: a fresh subscriber was handed the live value before, and nothing
  after; the attacker's own `PUBLISHED` list went from
  `DESIRED_HEADING,DESIRED_SPEED,MOOS_MANUAL_OVERRIDE,SENSOR_FEED` to empty;
  and **all 40** messages queued for a slow logger were destroyed before
  delivery.

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #84](https://github.com/themoos/core-moos/pull/84)
- Proposed fix commit: [5ff5cdec4424](https://github.com/themoos/core-moos/commit/5ff5cdec44242156a168cc1a545a6a21357bd3ac)

### Recommended fix

This is a design gap, so the fix is a design change.  Practical steps, roughly
in order of cost:

1. Bind the listener to a configurable address, defaulting to loopback, so the
   default deployment is not exposed. This alone removes most real exposure.
2. Add a mutually authenticated transport - TLS with client certificates, or a
   pre-shared key handshake - and bind each connection to a durable principal.
3. Enforce deny-by-default publish/subscribe ACLs per principal, configured in
   the mission file.
4. Make `DB_CLEAR` (and the other server requests) require an administrative
   principal.

Even without (2)-(4), documenting prominently that the MOOSDB port must never be
reachable from an untrusted network would be a material improvement.

---

## Recommendations

- Apply the proposed fix from [Pull Request #84](https://github.com/themoos/core-moos/pull/84) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85424 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85424](https://www.cve.org/CVERecord?id=CVE-2026-85424)
- VulnCheck advisory: [MOOS core-moos through 10.4.0 Missing Authentication for MOOSDB Publish, Subscribe and DB_CLEAR](https://www.vulncheck.com/advisories/moos-core-moos-through-10.4.0-missing-authentication-for-moosdb-publish-subscribe-and-db-clear)
- Upstream pull request: [Pull Request #84](https://github.com/themoos/core-moos/pull/84)
- Proposed fix commit: [5ff5cdec44242156a168cc1a545a6a21357bd3ac](https://github.com/themoos/core-moos/commit/5ff5cdec44242156a168cc1a545a6a21357bd3ac)
- Marlink Cyber Security Advisory: [MCSAID-2026-010](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-010-core-moos-missing-authentication-for-moosdb-publish-subscribe-and-db-clear.md)
- Software: [MOOS core-moos](https://github.com/themoos/core-moos)
