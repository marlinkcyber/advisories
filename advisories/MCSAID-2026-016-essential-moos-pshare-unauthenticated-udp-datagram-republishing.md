# MOOS essential-moos: pShare Unauthenticated UDP Datagram Republishing

- **Advisory ID:** MCSAID-2026-016
- **CVE ID:** [CVE-2026-85430](https://www.cve.org/CVERecord?id=CVE-2026-85430)
- **Published:** 2026-09-02
- **Severity:** Critical (CVSS 9.1 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H)
- **CVSS 4.0:** 8.8 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Insufficient Verification of Data Authenticity
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #18](https://github.com/themoos/essential-moos/pull/18) (not merged)
- **Software:** [MOOS essential-moos](https://github.com/themoos/essential-moos)
- **CWE:** [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

A configured pShare input route is a bare UDP socket bound to all interfaces that never looks at who sent a datagram. Anything that arrives is deserialised and posted into the local MOOSDB with the sender's chosen source application and originating community preserved. As a bonus, one malformed datagram makes the listener thread throw a `std::exception`, which the code handles with `exit(-1)`.

---

## Affected Versions

| Version | Status |
|---------|--------|
| essential-moos <= 10.0.1 | Vulnerable |

Tested against: essential-moos `10.0.1-release-22-gb897ea8` (commit `b897ea86dba8b61412dc48ac0cfb5ff34cdaf5f6`), latest master; and MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master, which bundles the same code.

---

## Impact

Injection of arbitrary allowed variables into a community from off-network, with
forged application and community provenance, plus a one-packet kill of the
bridge process itself.  Anything downstream that trusts community metadata
(uFldShoreBroker, uFldNodeBroker, pMOOSBridge loop guards) is now driven by the
attacker.

---

## Exploitation

Any host that can send UDP to a configured pShare input port.

Preconditions:

* pShare running with at least one `Input = route=...` (the normal field configuration), or with an input route created at runtime via [MCSAID-2026-019](./MCSAID-2026-019-essential-moos-pshare-unauthorized-runtime-route-reconfiguration.md).

---

## Details

### Affected code

Each affected file is listed twice: first at its path in **essential-moos** git master (commit `b897ea8`), which is where a fix has to land, then at its path inside the copy bundled in MOOS-IvP under `MOOS_Jul2724/MOOSEssentials`. The two copies are byte-identical unless stated otherwise.

* **`Essentials/pShare/Listener.cpp`** - lines 70-119: unicast input routes bind htonl(INADDR_ANY); read() discards the sender address; the datagram is deserialised straight into a CMOOSMsg
* **`MOOS_Jul2724/MOOSEssentials/Essentials/pShare/Listener.cpp`** - lines 68-117: unicast input routes bind htonl(INADDR_ANY); read() discards the sender address; the datagram is deserialised straight into a CMOOSMsg
* **`Essentials/pShare/Listener.cpp`** - _not present in essential-moos at git master_: IsWanted() is an optional white-list matched against the message's own key
* **`MOOS_Jul2724/MOOSEssentials/Essentials/pShare/Listener.cpp`** - lines 140-154: IsWanted() is an optional white-list matched against the message's own key
* **`Essentials/pShare/Share.cpp`** - lines 564-584: m_Comms.Post(new_msg, true) - the `true` preserves the attacker's source and community
* **`MOOS_Jul2724/MOOSEssentials/Essentials/pShare/Share.cpp`** - lines 580-600: m_Comms.Post(new_msg, true) - the `true` preserves the attacker's source and community
* **`Essentials/pShare/Listener.cpp`** - lines 123-136: catch(const std::exception & e) { ...; exit(-1); } - any std:: exception from deserialisation kills pShare
* **`MOOS_Jul2724/MOOSEssentials/Essentials/pShare/Listener.cpp`** - lines 120-134: catch(const std::exception & e) { ...; exit(-1); } - any std:: exception from deserialisation kills pShare

### Root cause

A pShare input route is a bare UDP socket.  For unicast routes it binds
`INADDR_ANY`, so it is reachable on every interface regardless of what host name
the operator wrote in the configuration.  `read()` is called without
`recvfrom()`, so the sender's address is not even available to be checked.  The
datagram is deserialised as a `CMOOSMsg` and, if the optional `white_list`
matches (a match on the message's *own* key, not on any identity), posted into
the local MOOSDB with source preservation enabled - so the attacker's `m_sSrc`
and `m_sOriginatingCommunity` land in the database verbatim.

Separately, the whole listen loop is wrapped in
`catch(const std::exception&) { ... exit(-1); }`.  Deserialisation can raise
`std::length_error` (see [MCSAID-2026-027](./MCSAID-2026-027-core-moos-moosdb-denial-of-service-via-negative-serialized-string-length.md)), so one malformed datagram terminates
pShare - a second, independent defect in the same function.

**The upstream pShare is worse than the copy bundled in MOOS-IvP.**  Testing
against essential-moos `10.0.1-release-22-gb897ea8` showed that its `Listener`
has no `white_list` at all - not the string, not the class member, not
`IsWanted()`.  `ListenLoop` simply does

```cpp
CMOOSMsg msg;
msg.Serialize(incoming_buffer.data(), incoming_buffer.size(), false);
//push onto queue
queue_.Push(msg);
```

So the optional key allow-list that at least narrows the attack in the MOOS-IvP
copy does not exist in the released essential-moos at all: every key an attacker
sends is accepted.

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

Yes - reproduced against essential-moos `10.0.1-release-22-gb897ea8`, default production build: six command variables injected with forged provenance, and one malformed datagram killed pShare. Note that the upstream pShare has NO white_list at all, so the optional key allow-list that exists in the MOOS-IvP copy is not even available here.

### Steps and results

With a single ordinary `Input = route=localhost:<port>`:

* `ss -lunp` shows the socket bound to `0.0.0.0:<port>`, not to a peer.
* Two bare UDP datagrams put `DEPLOY='false'` (src `pHelmIvP`, community
  `shoreside`) and `DESIRED_SPEED=99.0` (src `pMarinePID`) into the community
  `victim`, with the forged source and community preserved.
* A 20-byte datagram declaring a negative string length made pShare print
  `Caught exception in a listening thread: basic_string::_M_replace` and exit
  with status 255.

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #18](https://github.com/themoos/essential-moos/pull/18)
- Proposed fix commit: [53729b6325a9](https://github.com/themoos/essential-moos/commit/53729b6325a991a8dbd84dcd04e4707f3e592fd6)

### Recommended fix

* Use `recvfrom()` and keep the peer address; drop datagrams from anything not
  on a configured peer list.
* Wrap the payload in an AEAD envelope with a per-route key and a replay window,
  so an off-path host cannot inject at all.
* Derive `m_sOriginatingCommunity` from the authenticated route rather than
  taking it from the packet.
* Make the key allow-list mandatory rather than optional.
* Do not `exit(-1)` from a listener thread on a malformed packet: log it, drop
  the datagram, and keep serving.

---

## Recommendations

- Apply the proposed fix from [Pull Request #18](https://github.com/themoos/essential-moos/pull/18) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85430 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85430](https://www.cve.org/CVERecord?id=CVE-2026-85430)
- VulnCheck advisory: [MOOS essential-moos through 10.0.1 pShare Unauthenticated UDP Datagram Republishing](https://www.vulncheck.com/advisories/moos-essential-moos-through-10.0.1-pshare-unauthenticated-udp-datagram-republishing)
- Upstream pull request: [Pull Request #18](https://github.com/themoos/essential-moos/pull/18)
- Proposed fix commit: [53729b6325a991a8dbd84dcd04e4707f3e592fd6](https://github.com/themoos/essential-moos/commit/53729b6325a991a8dbd84dcd04e4707f3e592fd6)
- Marlink Cyber Security Advisory: [MCSAID-2026-016](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-016-essential-moos-pshare-unauthenticated-udp-datagram-republishing.md)
- Software: [MOOS essential-moos](https://github.com/themoos/essential-moos)
