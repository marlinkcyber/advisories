# MOOS-IvP: uFldNodeBroker Unauthenticated Shore Route Enrollment

- **Advisory ID:** MCSAID-2026-021
- **CVE ID:** [CVE-2026-85435](https://www.cve.org/CVERecord?id=CVE-2026-85435)
- **Published:** 2026-09-02
- **Severity:** Critical (CVSS 9.1 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
- **CVSS 4.0:** 9.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N)
- **Vulnerability type:** Insufficient Verification of Data Authenticity
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #124](https://github.com/moos-ivp/moos-ivp/pull/124) (not merged)
- **Software:** [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
- **CWE:** [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

uFldNodeBroker adds a shore route on request from anyone (`TRY_SHORE_HOST`) and then confirms it on receipt of a `NODE_BROKER_ACK` whose only authenticator is a small integer - the index of the route in the vehicle's own vector. Indexes start at zero, so two unauthenticated publications redirect all of the vehicle's configured bridge variables to an attacker endpoint.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |

Tested against: MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master.

---

## Impact

Persistent redirection of a vehicle's telemetry, node reports, mission hash,
appcasts and any mission-specific bridge variables to an attacker-chosen UDP
endpoint.  The legitimate shore route keeps working, so the operator sees
nothing wrong.

---

## Exploitation

Any publisher on the vehicle's MOOSDB, or anything upstream of the vehicle's pShare input route.

Preconditions:

* uFldNodeBroker running on the vehicle with `bridge =` entries (the standard vehicle configuration).

---

## Details

### Affected code

* **`ivp/src/uFldNodeBroker/NodeBroker.cpp`** - lines 87-93: TRY_SHORE_HOST from the bus is handled with no publisher check, then registerPingBridges(true)
* **`ivp/src/uFldNodeBroker/NodeBroker.cpp`** - lines 391-437: handleConfigTryShoreHost(): the only validation is isValidPShareRoute() plus a duplicate check
* **`ivp/src/uFldNodeBroker/NodeBroker.cpp`** - lines 445-476: handleMailAck(): key_ix = atoi(hrecord.getKey()); the only test is key_ix < m_shore_routes.size(); then m_shore_pings_ack[key_ix]++ and registerUserBridges()
* **`ivp/src/uFldNodeBroker/NodeBroker.cpp`** - lines 312-330: registerUserBridges(): postPShareCommand for every configured bridge variable to m_shore_routes[k]

### Root cause

Two unauthenticated publications are enough.

`TRY_SHORE_HOST = pshare_route=<host>:<port>` appends the route to
`m_shore_routes` after nothing more than a syntax check, and immediately makes
pShare bridge `NODE_BROKER_PING_<i>` there.

`NODE_BROKER_ACK` is then accepted if its `key` field is a number smaller than
the number of known routes.  That "key" is just the vector index the vehicle
itself put into its outgoing pings - it is not a nonce, it is not bound to any
peer, and indexes start at 0, so it can simply be enumerated.  A matching ack
sets `m_shore_pings_ack[k] > 0`, which makes `registerUserBridges()` export
every configured bridge variable to that route.

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

Against a stock vehicle (MOOSDB + uFldNodeBroker + pShare + pHostInfo):

* `TRY_SHORE_HOST = pshare_route=127.0.0.1:16700` produced
  `cmd=output,src_name=NODE_BROKER_PING_1,dest_name=NODE_BROKER_PING,route=127.0.0.1:16700`.
* A forged `NODE_BROKER_ACK` with `key=1` produced **11** further output routes
  and the vehicle announced
  `NODE_PSHARE_VARS=VEHICLE_SECRET,MISSION_HASH,NODE_MESSAGE,NODE_REPORT,VIEW_POLYGON,REALMCAST,WATCHCAST,REALMCAST_CHANNELS,APPCAST,NODE_PSHARE_VARS`.
* The attacker's UDP collector then received `NODE_REPORT`,
  `VEHICLE_SECRET='sonar-key=0xDEADBEEF'`, `MISSION_HASH` and the vehicle's
  appcasts.

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #124](https://github.com/moos-ivp/moos-ivp/pull/124)
- Proposed fix commit: [d66394f576ca](https://github.com/moos-ivp/moos-ivp/commit/d66394f576cae0c63c0a777760e1595802b83edf)

### Recommended fix

Take shore enrolment out of the data plane: configure permitted shore routes in
the mission file, or require a signed shore-identity assertion.  If dynamic
discovery must stay, replace the index "key" with a server-generated random
nonce that is bound to the exact route and to an authenticated shore identity,
expire unacknowledged enrolments, and never let an ack for one route enable
bridges for another.

---

## Recommendations

- Apply the proposed fix from [Pull Request #124](https://github.com/moos-ivp/moos-ivp/pull/124) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85435 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85435](https://www.cve.org/CVERecord?id=CVE-2026-85435)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 uFldNodeBroker Unauthenticated Shore Route Enrollment](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-ufldnodebroker-unauthenticated-shore-route-enrollment)
- Upstream pull request: [Pull Request #124](https://github.com/moos-ivp/moos-ivp/pull/124)
- Proposed fix commit: [d66394f576cae0c63c0a777760e1595802b83edf](https://github.com/moos-ivp/moos-ivp/commit/d66394f576cae0c63c0a777760e1595802b83edf)
- Marlink Cyber Security Advisory: [MCSAID-2026-021](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-021-moos-ivp-ufldnodebroker-unauthenticated-shore-route-enrollment.md)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
