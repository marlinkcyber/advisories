# MOOS core-moos: MOOSDB Message Source Spoofing via Wire Identity

- **Advisory ID:** MCSAID-2026-018
- **CVE ID:** [CVE-2026-85432](https://www.cve.org/CVERecord?id=CVE-2026-85432)
- **Published:** 2026-09-01
- **Severity:** High (CVSS 8.2 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L)
- **CVSS 4.0:** 8.8 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:L/SC:N/SI:N/SA:N)
- **Vulnerability type:** Authentication Bypass by Spoofing
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #76](https://github.com/themoos/core-moos/pull/76) (not merged)
- **Software:** [MOOS core-moos](https://github.com/themoos/core-moos)
- **CWE:** [CWE-290: Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOSDB knows the authenticated name of every socket but does not use it. Publication attribution, originating community, subscription ownership and wildcard matching are all driven by the `m_sSrc` / `m_sOriginatingCommunity` fields inside each message, which any client can set freely. One client can therefore impersonate any application or community, forge server-side provenance, cancel another client's subscriptions, and push data into another client's mailbox.

---

## Affected Versions

| Version | Status |
|---------|--------|
| core-moos <= 10.4.0 | Vulnerable |

Tested against: core-moos `v10.4.0-49-gec9c77c` (commit `ec9c77c68fcbdef8f5e4c60fe243acd223433f0c`), latest master; and MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master, which bundles the same code.

---

## Impact

Impersonation of any application and any community; corrupted provenance in
logs and operator displays; silent denial of data to other clients by cancelling
their subscriptions; unsolicited injection into other clients' mailboxes.  This
finding is the enabler for several others (2, 15, 18, 19 step 6).

---

## Exploitation

Any peer with a MOOSDB connection, using any unused client name.

Preconditions:

* A TCP connection to the MOOSDB (which needs no credential - [MCSAID-2026-010](./MCSAID-2026-010-core-moos-missing-authentication-for-moosdb-publish-subscribe-and-db-clear.md)).

---

## Details

### Affected code

Each affected file is listed twice: first at its path in **core-moos** git master (commit `ec9c77c`), which is where a fix has to land, then at its path inside the copy bundled in MOOS-IvP under `MOOS_Jul2724/MOOSCore`. The two copies are byte-identical unless stated otherwise.

* **`Core/libMOOS/DB/MOOSDB.cpp`** - lines 582-590: OnRxPkt(const std::string & sClient, ...) never uses sClient
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/DB/MOOSDB.cpp`** - lines 582-590: OnRxPkt(const std::string & sClient, ...) never uses sClient
* **`Core/libMOOS/DB/MOOSDB.cpp`** - lines 745, 772: OnNotify(): rVar.m_sWhoChangedMe = Msg.m_sSrc; rVar.m_Writers.insert(Msg.m_sSrc)
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/DB/MOOSDB.cpp`** - lines 745, 772: OnNotify(): rVar.m_sWhoChangedMe = Msg.m_sSrc; rVar.m_Writers.insert(Msg.m_sSrc)
* **`Core/libMOOS/DB/MOOSDB.cpp`** - lines 751-757: the originating community is taken from the wire whenever it is non-empty
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/DB/MOOSDB.cpp`** - lines 751-757: the originating community is taken from the wire whenever it is non-empty
* **`Core/libMOOS/DB/MOOSDB.cpp`** - lines 943, 964: OnRegister(): rVar.AddSubscriber(Msg.m_sSrc, ...) and AddMessageToClientBox(Msg.m_sSrc, ...)
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/DB/MOOSDB.cpp`** - lines 943, 964: OnRegister(): rVar.AddSubscriber(Msg.m_sSrc, ...) and AddMessageToClientBox(Msg.m_sSrc, ...)
* **`Core/libMOOS/DB/MOOSDB.cpp`** - line 888: OnUnRegister(): rVar.RemoveSubscriber(Msg.m_sSrc)
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/DB/MOOSDB.cpp`** - line 888: OnUnRegister(): rVar.RemoveSubscriber(Msg.m_sSrc)
* **`Core/libMOOS/Comms/MOOSCommServer.cpp`** - lines 944-970: HandShake() stores the authenticated name in m_Socket2ClientMap - the information exists, it is simply not used
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/MOOSCommServer.cpp`** - lines 944-970: HandShake() stores the authenticated name in m_Socket2ClientMap - the information exists, it is simply not used

### Root cause

The server does know who each socket is: `CMOOSCommServer::HandShake()` records
the handshake name in `m_Socket2ClientMap` and passes it to `OnRxPkt()` as
`sClient`.  `CMOOSDB::OnRxPkt()` then discards that argument and dispatches
purely on the message's own `m_sSrc` and `m_sOriginatingCommunity` fields, which
are ordinary serialised wire fields under the sender's control.

Consequences, all reachable from one connection:

* Publication attribution: `rVar.m_sWhoChangedMe` and `rVar.m_Writers` record
  the claimed name, so `PROC_SUMMARY`, `DB_RWSUMMARY`, appcasts and every
  subscriber see the forged source.
* Community provenance: a message that never left the host can be labelled as
  originating in another community, which is exactly the signal that
  uFldShoreBroker, uFldNodeBroker and pMOOSBridge use to decide whether traffic
  is "remote" (see [MCSAID-2026-020](./MCSAID-2026-020-moos-ivp-ufldshorebroker-bridge-route-injection-via-unverified-node-ping.md), [MCSAID-2026-017](./MCSAID-2026-017-essential-moos-pmoosbridge-unauthenticated-udp-packet-injection.md) and [MCSAID-2026-021](./MCSAID-2026-021-moos-ivp-ufldnodebroker-unauthenticated-shore-route-enrollment.md)).
* Subscription ownership: `OnRegister`/`OnUnRegister` use `Msg.m_sSrc` as the
  subscriber, so one client can cancel another client's subscriptions, or
  register *on behalf of* another client - which also delivers the current value
  into that client's mailbox.
* Wildcard filters match on `GetSource()`, so app-pattern based subscriptions
  can be satisfied by lying about the source.

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

Connected as `lowly-sensor-sim`, the PoC:

* published `DESIRED_RUDDER` that every subscriber saw as `src='pHelmIvP'`,
  `community='shoreside'`;
* had its own `PROC_SUMMARY` entry show no publication at all;
* got the DB to replay the stored writer as `pHelmIvP` to a later subscriber;
* labelled a local message as originating in community `alpha`;
* cancelled `pMarinePID`'s `DESIRED_THRUST` subscription (`RemoveSubscriber`)
  so the victim stopped receiving it;
* pushed `SECRET_TASKING='ATTACK-PAYLOAD'` into `pMarinePID`'s mailbox by
  registering in its name.

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #76](https://github.com/themoos/core-moos/pull/76)
- Proposed fix commit: [26308f0e393f](https://github.com/themoos/core-moos/commit/26308f0e393f0e80bfa09b275891e776b8dbf522)

### Recommended fix

Derive identity from the connection, not from the payload:

* In `CMOOSDB::OnRxPkt`, overwrite `m_sSrc` (and `m_sOriginatingCommunity` for
  ordinary clients) with the authenticated per-socket principal before
  dispatching, or reject messages whose fields disagree with it.
* Use the socket principal - never `Msg.m_sSrc` - as the key for
  `AddSubscriber`, `RemoveSubscriber`, `AddMessageToClientBox` and the wildcard
  filter map.
* Bridges legitimately need to preserve a remote origin.  Give them an explicit,
  authorised role and an integrity-protected origin envelope rather than letting
  every client set the field.

---

## Recommendations

- Apply the proposed fix from [Pull Request #76](https://github.com/themoos/core-moos/pull/76) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-01 – CVE-2026-85432 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85432](https://www.cve.org/CVERecord?id=CVE-2026-85432)
- VulnCheck advisory: [MOOS core-moos through 10.4.0 MOOSDB Message Source Spoofing via Wire Identity](https://www.vulncheck.com/advisories/moos-core-moos-through-10.4.0-moosdb-message-source-spoofing-via-wire-identity)
- Upstream pull request: [Pull Request #76](https://github.com/themoos/core-moos/pull/76)
- Proposed fix commit: [26308f0e393f0e80bfa09b275891e776b8dbf522](https://github.com/themoos/core-moos/commit/26308f0e393f0e80bfa09b275891e776b8dbf522)
- Marlink Cyber Security Advisory: [MCSAID-2026-018](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-018-core-moos-moosdb-message-source-spoofing-via-wire-identity.md)
- Software: [MOOS core-moos](https://github.com/themoos/core-moos)
