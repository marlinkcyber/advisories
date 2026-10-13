# MOOS core-moos: MOOSDB Accept Loop Denial of Service

- **Advisory ID:** MCSAID-2026-029
- **CVE ID:** [CVE-2026-85443](https://www.cve.org/CVERecord?id=CVE-2026-85443)
- **Published:** 2026-09-01
- **Severity:** High (CVSS 7.5 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **CVSS 4.0:** 8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Uncontrolled Resource Consumption
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #83](https://github.com/themoos/core-moos/pull/83) (not merged)
- **Software:** [MOOS core-moos](https://github.com/themoos/core-moos)
- **CWE:** [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

The MOOSDB has one accept path, and it performs the protocol handshake synchronously on that thread starting with a blocking `recv()` that has no timeout. One TCP connection that sends zero bytes therefore blocks all new client admission for as long as the attacker holds it, while the port continues to look healthy from outside.

---

## Affected Versions

| Version | Status |
|---------|--------|
| core-moos <= 10.4.0 | Vulnerable |

Tested against: core-moos `v10.4.0-49-gec9c77c` (commit `ec9c77c68fcbdef8f5e4c60fe243acd223433f0c`), latest master; and MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master, which bundles the same code.

---

## Impact

Total denial of new-client admission with one idle socket, zero bytes and no
credential.  In MOOS terms that means: no process can join the community, and
any process that restarts (or the whole mission being brought up by pAntler)
cannot reconnect.  This triage raises the severity from medium to high - it is
the cheapest complete-availability attack in the report, and it is
indistinguishable from a network glitch.

---

## Exploitation

Any unauthenticated TCP peer.

Preconditions:

* Ability to open one TCP connection to the MOOSDB port. No bytes need to be sent.

---

## Details

### Affected code

Each affected file is listed twice: first at its path in **core-moos** git master (commit `ec9c77c`), which is where a fix has to land, then at its path inside the copy bundled in MOOS-IvP under `MOOS_Jul2724/MOOSCore`. The two copies are byte-identical unless stated otherwise.

* **`Core/libMOOS/Comms/MOOSCommServer.cpp`** - lines 470-500: ListenLoop(): Accept() then OnNewClient() -> HandShake() on the same thread, inside m_SocketListLock
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/MOOSCommServer.cpp`** - lines 470-500: ListenLoop(): Accept() then OnNewClient() -> HandShake() on the same thread, inside m_SocketListLock
* **`Core/libMOOS/Comms/MOOSCommServer.cpp`** - lines 919-925: CheckProtocol(): pNewClient->iRecieveMessage(sProtocol, 32) - a plain blocking recv with no timeout
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/MOOSCommServer.cpp`** - lines 919-925: CheckProtocol(): pNewClient->iRecieveMessage(sProtocol, 32) - a plain blocking recv with no timeout
* **`Core/libMOOS/Comms/MOOSCommServer.cpp`** - line 957: the 5-second timeout applies only to the NEXT read, ReadMsg(..., 5)
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/MOOSCommServer.cpp`** - line 957: the 5-second timeout applies only to the NEXT read, ReadMsg(..., 5)
* **`Core/libMOOS/Comms/XPCTcpSocket.cpp`** - lines 211-223: iRecieveMessage() is an unbounded recv()
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/XPCTcpSocket.cpp`** - lines 211-223: iRecieveMessage() is an unbounded recv()

### Root cause

The MOOSDB has a single accept path.  After `accept()` returns it performs the
protocol handshake synchronously on that thread, and the first step of the
handshake is a blocking `recv()` with no timeout at all.  A peer that completes
the TCP three-way handshake and then sends nothing parks the accept thread for
as long as it likes.  In single-threaded mode the held `m_SocketListLock` also
blocks progress for existing clients.

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

One socket, zero bytes:

    baseline connect                   : 0.20s, community 'victim9500'
    3 legitimate clients while held     : all BLOCKED (6.01s timeout each)
    probes at t+9s, t+18s, t+27s        : all still blocked
    after the attacker closed the socket: a client connected again

The kernel still completes the TCP handshake, so the port looks healthy from
outside while no application-level admission happens.

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #83](https://github.com/themoos/core-moos/pull/83)
- Proposed fix commit: [8d940303949a](https://github.com/themoos/core-moos/commit/8d940303949a850d4625eca2a60f27adee9c3ec4)

### Recommended fix

Apply one absolute deadline to the whole pre-authentication phase (protocol
string plus handshake message), enforced with `setsockopt(SO_RCVTIMEO)` or a
`select()`/`poll()` wrapper - `iReadMessageWithTimeOut` already exists and is
used for the next read, so `CheckProtocol` should use it too.  Do not hold
`m_SocketListLock` across network I/O.  Move the handshake off the accept
thread, into a small bounded worker pool or a non-blocking state machine, so a
slow or hostile peer cannot occupy the only accept path.

---

## Recommendations

- Apply the proposed fix from [Pull Request #83](https://github.com/themoos/core-moos/pull/83) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-01 – CVE-2026-85443 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85443](https://www.cve.org/CVERecord?id=CVE-2026-85443)
- VulnCheck advisory: [MOOS core-moos through 10.4.0 MOOSDB Accept Loop Denial of Service](https://www.vulncheck.com/advisories/moos-core-moos-through-10.4.0-moosdb-accept-loop-denial-of-service)
- Upstream pull request: [Pull Request #83](https://github.com/themoos/core-moos/pull/83)
- Proposed fix commit: [8d940303949a850d4625eca2a60f27adee9c3ec4](https://github.com/themoos/core-moos/commit/8d940303949a850d4625eca2a60f27adee9c3ec4)
- Marlink Cyber Security Advisory: [MCSAID-2026-029](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-029-core-moos-moosdb-accept-loop-denial-of-service.md)
- Software: [MOOS core-moos](https://github.com/themoos/core-moos)
