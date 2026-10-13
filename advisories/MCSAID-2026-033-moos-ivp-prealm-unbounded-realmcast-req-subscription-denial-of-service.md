# MOOS-IvP: pRealm Unbounded REALMCAST_REQ Subscription Denial of Service

- **Advisory ID:** MCSAID-2026-033
- **CVE ID:** [CVE-2026-85447](https://www.cve.org/CVERecord?id=CVE-2026-85447)
- **Published:** 2026-09-02
- **Severity:** High (CVSS 7.5 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **CVSS 4.0:** 8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Allocation of Resources Without Limits or Throttling
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #132](https://github.com/moos-ivp/moos-ivp/pull/132) (not merged)
- **Software:** [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
- **CWE:** [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

`REALMCAST_REQ` lets a publisher name its own client identifier and its own duration, with the duration only checked for being non-zero. 500 requests with a 31-year duration and a 200-variable list took pRealm from 0.3% to 105% of a CPU core - fully saturated - and the pipes stay live for as long as the attacker asked.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |

Tested against: MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master.

---

## Impact

Sustained CPU saturation and memory growth in pRealm, plus MOOS bandwidth and
field-link amplification, for a duration the attacker chooses.  On a vehicle
that shares a CPU with the helm this is a safety-relevant availability
attack, which is why we score this high rather than medium.

---

## Exploitation

Any MOOS publisher, including anything upstream of a field bridge (pRealm's requests are bridged from the shore by default).

Preconditions:

* pRealm running - it is part of the standard vehicle and shoreside configurations, and uFldShoreBroker auto-bridges REALMCAST_REQ.

---

## Details

### Affected code

* **`ivp/src/pRealm/Realm.cpp`** - lines 281-303: handleMailRealmCastReq(): the client name is an attacker-chosen map key; any valid pipeway is stored and its expiry reset
* **`ivp/src/pRealm/PipeWay.cpp`** - lines 109-119: valid(): requires only a non-empty client, a non-zero duration, and either a channel or one variable. Duration has no upper bound.
* **`ivp/src/pRealm/PipeWay.cpp`** - lines 180-215: string2PipeWay(): the variable list is a ':'-separated list with no length limit
* **`ivp/src/pRealm/Realm.cpp`** - lines 340-447: buildRealmCast()/buildWatchCast(): every live pipeway is serialised and published on every interval

### Root cause

A `REALMCAST_REQ` names its own client identifier, so N requests with N distinct
identifiers create N persistent pipeways.  `duration` is only tested for
non-zero, so `duration=1000000000` keeps a pipe alive for ~31 years.  The
variable list is unbounded, and every live pipeway causes pRealm to serialise
and publish its content on every cast interval.

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

500 requests (2257 bytes each, ~1.1 MB total), each with `duration=1000000000`
and a 200-variable list:

    RSS  4484 kB -> 17732 kB
    CPU  0.3% -> 105.1% of a core   (315x; pRealm fully saturated a core)

and the pipes remain live for the attacker-chosen 1e9 seconds.

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #132](https://github.com/moos-ivp/moos-ivp/pull/132)
- Proposed fix commit: [8a4bb9d9154a](https://github.com/moos-ivp/moos-ivp/commit/8a4bb9d9154a70e769a7290ee11dde5157c03e9b)

### Recommended fix

Bind requests to an authenticated client identity rather than a self-declared
string.  Cap the duration (and clamp it to a documented maximum), the number of
concurrent pipeways, the number of variables per request and the request size.
Enforce an aggregate serialisation/output budget per interval so total work is
bounded no matter how many requests arrive.

---

## Recommendations

- Apply the proposed fix from [Pull Request #132](https://github.com/moos-ivp/moos-ivp/pull/132) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85447 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85447](https://www.cve.org/CVERecord?id=CVE-2026-85447)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 pRealm Unbounded REALMCAST_REQ Subscription Denial of Service](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-prealm-unbounded-realmcast-req-subscription-denial-of-service)
- Upstream pull request: [Pull Request #132](https://github.com/moos-ivp/moos-ivp/pull/132)
- Proposed fix commit: [8a4bb9d9154a70e769a7290ee11dde5157c03e9b](https://github.com/moos-ivp/moos-ivp/commit/8a4bb9d9154a70e769a7290ee11dde5157c03e9b)
- Marlink Cyber Security Advisory: [MCSAID-2026-033](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-033-moos-ivp-prealm-unbounded-realmcast-req-subscription-denial-of-service.md)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
