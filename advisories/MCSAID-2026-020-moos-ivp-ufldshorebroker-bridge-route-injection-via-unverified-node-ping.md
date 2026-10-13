# MOOS-IvP: uFldShoreBroker Bridge Route Injection via Unverified Node Ping

- **Advisory ID:** MCSAID-2026-020
- **CVE ID:** [CVE-2026-85434](https://www.cve.org/CVERecord?id=CVE-2026-85434)
- **Published:** 2026-09-02
- **Severity:** Critical (CVSS 9.1 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
- **CVSS 4.0:** 9.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N)
- **Vulnerability type:** Insufficient Verification of Data Authenticity
- **Current state:** Fixed upstream in `main` by [Pull Request #123](https://github.com/moos-ivp/moos-ivp/pull/123) (merged 2026-09-05); not yet in a tagged release (latest release is v24.8.1)
- **Software:** [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
- **CWE:** [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

A single unauthenticated `NODE_BROKER_PING` naming a community uFldShoreBroker has not seen before is enough to enrol an attacker-chosen pShare route. The shore then emits `PSHARE_CMD` output routes for every configured bridge variable and starts streaming its command and tasking traffic to the attacker's UDP endpoint. A configured `keyword` mismatch is recorded as a status string and does not prevent any of this.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |
| moos-ivp `main` from commit [`275e6993bab0`](https://github.com/moos-ivp/moos-ivp/commit/275e6993bab098bff43bffbab09def33cdab9440) | Fixed |

Tested against: MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master.

---

## Impact

Silent exfiltration of shoreside command traffic (`DEPLOY_ALL`, `RETURN_ALL`,
`STATION_KEEP_ALL`, `MOOS_MANUAL_OVERRIDE_ALL`, `MISSION_TASK`, `MISSION_HASH`,
`APPCAST_REQ`, `REALMCAST_REQ`, and every user-configured bridge variable) to an
attacker-chosen host, plus a forged view of the fleet in the operator's
topology display.  The same route is bidirectional in practice: the attacker now
knows the exact variable names and the shore's own host record.

---

## Exploitation

Any publisher of NODE_BROKER_PING on the shoreside MOOSDB - in practice anyone who can reach the shore MOOSDB port ([MCSAID-2026-010](./MCSAID-2026-010-core-moos-missing-authentication-for-moosdb-publish-subscribe-and-db-clear.md)) or send UDP to a pShare/pMOOSBridge input route ([MCSAID-2026-016](./MCSAID-2026-016-essential-moos-pshare-unauthenticated-udp-datagram-republishing.md) and [MCSAID-2026-017](./MCSAID-2026-017-essential-moos-pmoosbridge-unauthenticated-udp-packet-injection.md)).

Preconditions:

* uFldShoreBroker running with one or more `bridge`/`qbridge` variables configured (the normal shoreside configuration).
* The ping must claim an originating community different from the shore's own (ShoreBroker.cpp:82-93) - [MCSAID-2026-018](./MCSAID-2026-018-core-moos-moosdb-message-source-spoofing-via-wire-identity.md) makes that field attacker-chosen.
* pHostInfo must have supplied a valid PHI_HOST_INFO, which it does in every real deployment.

---

## Details

### Affected code

* **`ivp/src/uFldShoreBroker/ShoreBroker.cpp`** - lines 369-463: handleMailNodePing(): a syntactically valid HostRecord from an unknown community is enrolled; keyword mismatch only sets a status string
* **`ivp/src/uFldShoreBroker/ShoreBroker.cpp`** - lines 502-554: makeBridgeRequestAll()/makeBridgeRequest(): emits PSHARE_CMD cmd=output with route= taken from the ping
* **`ivp/src/lib_ufield/HostRecord.cpp`** - lines 92-110: valid() checks only: non-empty community, parseable IP, numeric port_db
* **`ivp/src/lib_ufield/HostRecordUtils.cpp`** - lines 35-70: string2HostRecord() silently ignores unknown fields

### Root cause

`handleMailNodePing()` builds a `HostRecord` from the message text and accepts it
if `HostRecord::valid()` passes - which requires only a non-empty community
string, an IP address that parses, and a numeric `port_db`.  A configured
`keyword` is compared, but a mismatch only writes `status = "keyword_mismatch"`
into the record; the node is still enrolled and still gets acknowledged.

The claimed community is then used as the node's identity.  Because it is fresh,
the duplicate-detection loop does not fold it into an existing record, so six
parallel vectors are appended and `makeBridgeRequestAll()` emits one
`PSHARE_CMD` `cmd=output` per configured bridge variable, with
`route=<pshare_iroutes from the ping>`.  pShare obeys those commands without any
authorisation of its own ([MCSAID-2026-019](./MCSAID-2026-019-essential-moos-pshare-unauthorized-runtime-route-reconfiguration.md)), so the shore starts streaming its
command and tasking variables to the attacker's UDP endpoint.

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

One 150-byte `NODE_BROKER_PING` with `community=pirate` and a deliberately wrong
keyword produced **16 `PSHARE_CMD` output routes** to the attacker's UDP port:

    cmd=output,src_name=DEPLOY_ALL,dest_name=DEPLOY,route=127.0.0.1:15300
    cmd=output,src_name=MOOS_MANUAL_OVERRIDE_ALL,...
    cmd=output,src_name=MISSION_TASK,...
    ... 13 more

and the collector then received the real traffic, including
`MISSION_TASK = 'RENDEZVOUS 41.123,-71.456 AT 0300Z'`.  The shore also kept
sending `NODE_BROKER_ACK` with `status=keyword_mismatch` - the mismatch is
reported, never enforced.

---

## Mitigations

Fixed upstream in the `main` branch; no tagged release containing the fix exists yet.

- Pull request: [Pull Request #123](https://github.com/moos-ivp/moos-ivp/pull/123) (merged 2026-09-05)
- Fix commit: [275e6993bab0](https://github.com/moos-ivp/moos-ivp/commit/275e6993bab098bff43bffbab09def33cdab9440)

### Recommended fix

Make node enrolment an authenticated, fail-closed operation:

* Require a pre-shared or certificate-based node identity, and bind the claimed
  community to it.  Reject any ping whose signature does not verify.
* Make `keyword` (and `timewarp`) mismatches a rejection, not a status string.
* Do not take `pshare_iroutes` from the peer at all, or validate it against an
  operator-configured allow-list of permitted endpoints.
* Bind `NODE_BROKER_ACK` to a server-generated nonce so an acknowledgement
  cannot be replayed or guessed.

---

## Recommendations

- Upgrade to a moos-ivp release that includes commit [`275e6993bab0`](https://github.com/moos-ivp/moos-ivp/commit/275e6993bab098bff43bffbab09def33cdab9440) once available, or build from `main` at or after that commit.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85434 published
- 2026-09-05 – Fix merged upstream in [Pull Request #123](https://github.com/moos-ivp/moos-ivp/pull/123)
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85434](https://www.cve.org/CVERecord?id=CVE-2026-85434)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 uFldShoreBroker Bridge Route Injection via Unverified Node Ping](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-ufldshorebroker-bridge-route-injection-via-unverified-node-ping)
- Upstream pull request: [Pull Request #123](https://github.com/moos-ivp/moos-ivp/pull/123)
- Fix commit (PR head): [2f5224dcd68f92ce9ae10c261bb45dd7000f4d33](https://github.com/moos-ivp/moos-ivp/commit/2f5224dcd68f92ce9ae10c261bb45dd7000f4d33)
- Marlink Cyber Security Advisory: [MCSAID-2026-020](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-020-moos-ivp-ufldshorebroker-bridge-route-injection-via-unverified-node-ping.md)
- Merge commit: [275e6993bab098bff43bffbab09def33cdab9440](https://github.com/moos-ivp/moos-ivp/commit/275e6993bab098bff43bffbab09def33cdab9440)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
