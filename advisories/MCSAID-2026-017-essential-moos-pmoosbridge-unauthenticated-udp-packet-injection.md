# MOOS essential-moos: pMOOSBridge Unauthenticated UDP Packet Injection

- **Advisory ID:** MCSAID-2026-017
- **CVE ID:** [CVE-2026-85431](https://www.cve.org/CVERecord?id=CVE-2026-85431)
- **Published:** 2026-09-02
- **Severity:** High (CVSS 7.5 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N)
- **CVSS 4.0:** 8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N)
- **Vulnerability type:** Insufficient Verification of Data Authenticity
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #19](https://github.com/themoos/essential-moos/pull/19) (not merged)
- **Software:** [MOOS essential-moos](https://github.com/themoos/essential-moos)
- **CWE:** [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

pMOOSBridge's optional `UDPListen` socket accepts any datagram from anyone, decodes it as a full `CMOOSCommPkt`, and publishes every message it contains into the local community with the source preserved. The two apparent checks - key not already registered, community differs from the local one - are attacker-controlled fields whose purpose is loop prevention, not authorisation.

---

## Affected Versions

| Version | Status |
|---------|--------|
| essential-moos <= 10.0.1 | Vulnerable |

Tested against: essential-moos `10.0.1-release-22-gb897ea8` (commit `b897ea86dba8b61412dc48ac0cfb5ff34cdaf5f6`), latest master; and MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master, which bundles the same code.

---

## Impact

Forged cross-community control and telemetry publication into a live community
from anywhere on the network, with provenance chosen by the attacker.  Because
one datagram can carry a whole packet, an attacker can set an entire command
state atomically.

---

## Exploitation

Any host that can send UDP to the configured UDPListen port.

Preconditions:

* pMOOSBridge configured with `UDPListen = <port>`.

---

## Details

### Affected code

Each affected file is listed twice: first at its path in **essential-moos** git master (commit `b897ea8`), which is where a fix has to land, then at its path inside the copy bundled in MOOS-IvP under `MOOS_Jul2724/MOOSEssentials`. The two copies are byte-identical unless stated otherwise.

* **`Essentials/pMOOSBridge/MOOSUDPLink.cpp`** - lines 121-153: ListenLoop(): iRecieveMessage() then ReadPktFromArray + CMOOSCommPkt::Serialize; the sender address is never retained
* **`MOOS_Jul2724/MOOSEssentials/Essentials/pMOOSBridge/MOOSUDPLink.cpp`** - lines 121-153: ListenLoop(): iRecieveMessage() then ReadPktFromArray + CMOOSCommPkt::Serialize; the sender address is never retained
* **`Essentials/pMOOSBridge/MOOSBridge.cpp`** - lines 150-181: the only gates are HasMOOSSRegistration(key) and community != local community - both attacker-controlled fields
* **`MOOS_Jul2724/MOOSEssentials/Essentials/pMOOSBridge/MOOSBridge.cpp`** - lines 150-181: the only gates are HasMOOSSRegistration(key) and community != local community - both attacker-controlled fields
* **`Essentials/pMOOSBridge/MOOSCommunity.cpp`** - lines 123-145: Post() forwards into the local MOOSDB with the source preserved
* **`MOOS_Jul2724/MOOSEssentials/Essentials/pMOOSBridge/MOOSCommunity.cpp`** - lines 123-145: Post() forwards into the local MOOSDB with the source preserved
* **`Essentials/pMOOSBridge/MOOSBridge.cpp`** - lines 401-410: UDPListen = <port> starts the listener; without it the bridge is outgoing-only
* **`MOOS_Jul2724/MOOSEssentials/Essentials/pMOOSBridge/MOOSBridge.cpp`** - lines 401-410: UDPListen = <port> starts the listener; without it the bridge is outgoing-only

### Root cause

The bridge's UDP listener accepts any datagram, decodes it as a
`CMOOSCommPkt` (so one datagram can carry many messages), and posts each message
into the local community.  The two "loop guards" are (a) the key must not be one
the bridge is itself registered for and (b) the claimed originating community
must differ from the local one.  Both are fields the sender controls, so they
are trivially satisfied; they exist to prevent feedback loops, not to
authenticate anyone.  `Post()` preserves the source, so the attacker's chosen
application name and community appear in the database.

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

Yes - reproduced against essential-moos `10.0.1-release-22-gb897ea8`, default production build: six messages in one datagram landed in the live community with forged source and community, and the loop guard was bypassed by changing one string.

### Steps and results

With `UDPListen = <port>` and nothing else:

* `ss -lunp` shows `0.0.0.0:<port>`.
* One 369-byte datagram carrying four messages put `DEPLOY='true'`,
  `RETURN='false'`, `MOOS_MANUAL_OVERRIDE='false'` and `DESIRED_HEADING=180.0`
  into community `alpha`, all attributed to `pMarineViewer`/`pHelmIvP` in
  community `shoreside`.
* Changing one string (`community=alpha` -> `community=anything`) was enough to
  get past the loop guard, showing that the guard is not an authorisation
  check.

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #19](https://github.com/themoos/essential-moos/pull/19)
- Proposed fix commit: [d8441eac57d0](https://github.com/themoos/essential-moos/commit/d8441eac57d04ee89e7b82723480d10a558b45d6)

### Recommended fix

Same shape as [MCSAID-2026-016](./MCSAID-2026-016-essential-moos-pshare-unauthenticated-udp-datagram-republishing.md): authenticate and replay-protect the datagrams with a
per-peer key, use `recvfrom()` and validate the peer against a configured list,
derive the originating community from the authenticated route instead of the
packet, and require an explicit key allow-list.

---

## Recommendations

- Apply the proposed fix from [Pull Request #19](https://github.com/themoos/essential-moos/pull/19) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85431 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85431](https://www.cve.org/CVERecord?id=CVE-2026-85431)
- VulnCheck advisory: [MOOS essential-moos through 10.0.1 pMOOSBridge Unauthenticated UDP Packet Injection](https://www.vulncheck.com/advisories/moos-essential-moos-through-10.0.1-pmoosbridge-unauthenticated-udp-packet-injection)
- Upstream pull request: [Pull Request #19](https://github.com/themoos/essential-moos/pull/19)
- Proposed fix commit: [d8441eac57d04ee89e7b82723480d10a558b45d6](https://github.com/themoos/essential-moos/commit/d8441eac57d04ee89e7b82723480d10a558b45d6)
- Marlink Cyber Security Advisory: [MCSAID-2026-017](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-017-essential-moos-pmoosbridge-unauthenticated-udp-packet-injection.md)
- Software: [MOOS essential-moos](https://github.com/themoos/essential-moos)
