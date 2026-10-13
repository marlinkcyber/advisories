# MOOS essential-moos: pShare Unauthorized Runtime Route Reconfiguration

- **Advisory ID:** MCSAID-2026-019
- **CVE ID:** [CVE-2026-85433](https://www.cve.org/CVERecord?id=CVE-2026-85433)
- **Published:** 2026-09-02
- **Severity:** Critical (CVSS 9.8 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **CVSS 4.0:** 9.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Missing Authorization
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #20](https://github.com/themoos/essential-moos/pull/20) (not merged)
- **Software:** [MOOS essential-moos](https://github.com/themoos/essential-moos)
- **CWE:** [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

pShare turns any fresh `PSHARE_CMD` message into a routing change, using the same parser it applies to the trusted mission file. The only check is that the message is newer than pShare's start time. An attacker can therefore create UDP egress for any variable to any endpoint, and create new unauthenticated ingress into the community, on a pShare that was configured with nothing at all.

---

## Affected Versions

| Version | Status |
|---------|--------|
| essential-moos <= 10.0.1 | Vulnerable |

Tested against: essential-moos `10.0.1-release-22-gb897ea8` (commit `b897ea86dba8b61412dc48ac0cfb5ff34cdaf5f6`), latest master; and MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master, which bundles the same code.

---

## Impact

Two distinct powers beyond what a bus client already has: (a) egress of any
variable to an arbitrary Internet endpoint, and (b) creation of new
unauthenticated ingress into the community (which then enables [MCSAID-2026-016](./MCSAID-2026-016-essential-moos-pshare-unauthenticated-udp-datagram-republishing.md)).
Plus unbounded socket and thread consumption.

---

## Exploitation

Any MOOS publisher, with no topology-administration authority.

Preconditions:

* pShare running. No Input/Output configuration is needed - an empty pShare is fully reprogrammable.

---

## Details

### Affected code

Each affected file is listed twice: first at its path in **essential-moos** git master (commit `b897ea8`), which is where a fix has to land, then at its path inside the copy bundled in MOOS-IvP under `MOOS_Jul2724/MOOSEssentials`. The two copies are byte-identical unless stated otherwise.

* **`Essentials/pShare/Share.cpp`** - line 260: OnStartUp(): EnableCommandMessageFiltering(true) subscribes pShare to PSHARE_CMD
* **`MOOS_Jul2724/MOOSEssentials/Essentials/pShare/Share.cpp`** - line 260: OnStartUp(): EnableCommandMessageFiltering(true) subscribes pShare to PSHARE_CMD
* **`Essentials/pShare/Share.cpp`** - lines 811-846: OnCommandMsg(): the only check is Msg.IsYoungerThan(GetAppStartTime()); cmd=output / cmd=input go straight to ProcessIOConfigurationString
* **`MOOS_Jul2724/MOOSEssentials/Essentials/pShare/Share.cpp`** - lines 872-910: OnCommandMsg(): the only check is Msg.IsYoungerThan(GetAppStartTime()); cmd=output / cmd=input go straight to ProcessIOConfigurationString
* **`Essentials/pShare/Share.cpp`** - lines 479-562: ProcessIOConfigurationString(): the same function used for trusted mission-file configuration
* **`MOOS_Jul2724/MOOSEssentials/Essentials/pShare/Share.cpp`** - lines 479-568: ProcessIOConfigurationString(): the same function used for trusted mission-file configuration
* **`Essentials/pShare/Share.cpp`** - lines 158, 1139: AddInputRoute() spawns a new INADDR_ANY listener thread; AddOutputRoute() creates the egress socket
* **`MOOS_Jul2724/MOOSEssentials/Essentials/pShare/Share.cpp`** - lines 162, 1215: AddInputRoute() spawns a new INADDR_ANY listener thread; AddOutputRoute() creates the egress socket

### Root cause

pShare subscribes to `PSHARE_CMD` and hands any fresh message to the same
configuration parser it uses for the mission file.  `cmd=output,src_name=X,
route=host:port` creates a UDP egress route for variable X; `cmd=input,
route=host:port` spawns a new listener thread bound to all interfaces.  The only
check is that the message is younger than pShare's start time - there is no
source check, no role, no destination allow-list and no cap on the number of
routes or sockets.

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

Yes - reproduced against essential-moos `10.0.1-release-22-gb897ea8`, default production build: NAV_X/NAV_Y/NAV_HEADING/MISSION_TASK/MISSION_HASH exfiltrated to the attacker's UDP collector, and a new ingress port opened and used to inject DEPLOY and MOOS_MANUAL_OVERRIDE.

### Steps and results

pShare started with an empty configuration.

* Three `PSHARE_CMD` publications created output routes for `NAV_X`, `NAV_Y` and
  `MISSION_TASK`; the attacker's UDP collector then received
  `NAV_X=1234.5`, `NAV_Y=6789.0` and
  `MISSION_TASK='RENDEZVOUS AT 41.123,-71.456 AT 0300Z'`.
* One more publication (`cmd=input,route=127.0.0.1:10400`) made a new listener
  appear (`UNCONN 0 0 0.0.0.0:10400 ... users:(("pShare",...))`), and datagrams
  sent there were imported as `DEPLOY='false'` (src `pHelmIvP`, community
  `shoreside`) and `MOOS_MANUAL_OVERRIDE='false'`.

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #20](https://github.com/themoos/essential-moos/pull/20)
- Proposed fix commit: [8e51cedcbd8d](https://github.com/themoos/essential-moos/commit/8e51cedcbd8de9781adec2e9cce354f51750a547)

### Recommended fix

Disable runtime topology commands unless explicitly enabled, and when enabled
require an authenticated administrative principal (which needs [MCSAID-2026-018](./MCSAID-2026-018-core-moos-moosdb-message-source-spoofing-via-wire-identity.md) fixed
first, so that `m_sSrc` means something).  Restrict destinations to a configured
allow-list of endpoints and variables, cap the number of routes, sockets and
listener threads, and give dynamic routes an expiry plus an audit log so an
operator can see what changed.

---

## Recommendations

- Apply the proposed fix from [Pull Request #20](https://github.com/themoos/essential-moos/pull/20) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85433 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85433](https://www.cve.org/CVERecord?id=CVE-2026-85433)
- VulnCheck advisory: [MOOS essential-moos through 10.0.1 pShare Unauthorized Runtime Route Reconfiguration](https://www.vulncheck.com/advisories/moos-essential-moos-through-10.0.1-pshare-unauthorized-runtime-route-reconfiguration)
- Upstream pull request: [Pull Request #20](https://github.com/themoos/essential-moos/pull/20)
- Proposed fix commit: [8e51cedcbd8de9781adec2e9cce354f51750a547](https://github.com/themoos/essential-moos/commit/8e51cedcbd8de9781adec2e9cce354f51750a547)
- Marlink Cyber Security Advisory: [MCSAID-2026-019](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-019-essential-moos-pshare-unauthorized-runtime-route-reconfiguration.md)
- Software: [MOOS essential-moos](https://github.com/themoos/essential-moos)
