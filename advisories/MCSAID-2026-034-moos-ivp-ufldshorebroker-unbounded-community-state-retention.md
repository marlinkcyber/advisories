# MOOS-IvP: uFldShoreBroker Unbounded Community State Retention

- **Advisory ID:** MCSAID-2026-034
- **CVE ID:** [CVE-2026-85448](https://www.cve.org/CVERecord?id=CVE-2026-85448)
- **Published:** 2026-09-02
- **Severity:** High (CVSS 7.5 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **CVSS 4.0:** 8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Allocation of Resources Without Limits or Throttling
- **Current state:** Fixed upstream in `main` by [Pull Request #133](https://github.com/moos-ivp/moos-ivp/pull/133) (merged 2026-09-11); not yet in a tagged release (latest release is v24.8.1)
- **Software:** [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
- **CWE:** [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

uFldShoreBroker appends six parallel vectors for every fresh claimed community and never erases them - staleness only sets a flag. Every periodic pass then iterates the whole set, and the bridge pass costs one `PSHARE_CMD` per bridge variable per node. 354 kB of pings burned 26 seconds of CPU and delayed a genuine node's acknowledgement to 20 seconds.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |
| moos-ivp `main` from commit [`d40a41371dae`](https://github.com/moos-ivp/moos-ivp/commit/d40a41371dae55a172b7d04319cbfd667153ff0a) | Fixed |

Tested against: MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master.

---

## Impact

Monotonic heap growth and increasing periodic work until the broker can no
longer keep up, at which point legitimate nodes stop being acknowledged and stop
getting their bridges - i.e. real vehicles silently fall out of the field
network.

---

## Exploitation

Any publisher of NODE_BROKER_PING with unique claimed community names.

Preconditions:

* uFldShoreBroker running (standard shoreside configuration).

---

## Details

### Affected code

* **`ivp/src/uFldShoreBroker/ShoreBroker.cpp`** - lines 436-462: handleMailNodePing(): a linear scan folds exact repeats, but any fresh community appends to six parallel vectors
* **`ivp/src/uFldShoreBroker/ShoreBroker.cpp`** - lines 219-338: checkForStaleNodes() sets m_node_is_stale[i] = true and nothing ever erases the entry; sendAcks() and postNodeCount() keep iterating the full vector
* **`ivp/src/uFldShoreBroker/ShoreBroker.cpp`** - lines 502-528: makeBridgeRequestAll() emits one PSHARE_CMD per bridge variable per node, every pass

### Root cause

Community strings are the node identity and are asserted, not proved.  Each
fresh one appends to six vectors.  Staleness only flips a flag, so the vectors
grow monotonically for the lifetime of the process, and every periodic pass -
acknowledgement, bridge reconciliation, node count, appcast report - iterates
the whole set.  The bridge pass is O(nodes x bridge-variables).

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

3000 pings (118 bytes each, 354 kB total) against a stock shoreside:

    UFSB_NODE_COUNT reported : 3000
    RSS  4664 kB -> 11392 kB
    CPU  0.00s -> 26.06s of CPU burned in ~25 seconds

and then the decisive measurement: a **genuine** node's ping was acknowledged
only after **20.3 seconds** (normally sub-second).

---

## Mitigations

Fixed upstream in the `main` branch; no tagged release containing the fix exists yet.

- Pull request: [Pull Request #133](https://github.com/moos-ivp/moos-ivp/pull/133) (merged 2026-09-11)
- Fix commit: [d40a41371dae](https://github.com/moos-ivp/moos-ivp/commit/d40a41371dae55a172b7d04319cbfd667153ff0a)

### Recommended fix

Authenticate enrolment (see [MCSAID-2026-020](./MCSAID-2026-020-moos-ivp-ufldshorebroker-bridge-route-injection-via-unverified-node-ping.md) - the same fix addresses both).  Cap the
number of active and retained nodes, rate-limit new-identity creation, and
actually erase records after a bounded grace period instead of flagging them.
Replace the six parallel vectors with a single map keyed on identity so removal
is cheap and cannot desynchronise.

---

## Recommendations

- Upgrade to a moos-ivp release that includes commit [`d40a41371dae`](https://github.com/moos-ivp/moos-ivp/commit/d40a41371dae55a172b7d04319cbfd667153ff0a) once available, or build from `main` at or after that commit.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85448 published
- 2026-09-11 – Fix merged upstream in [Pull Request #133](https://github.com/moos-ivp/moos-ivp/pull/133)
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85448](https://www.cve.org/CVERecord?id=CVE-2026-85448)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 uFldShoreBroker Unbounded Community State Retention](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-ufldshorebroker-unbounded-community-state-retention)
- Upstream pull request: [Pull Request #133](https://github.com/moos-ivp/moos-ivp/pull/133)
- Fix commit (PR head): [2cbaed2227db31f50d5542cafe08445596800801](https://github.com/moos-ivp/moos-ivp/commit/2cbaed2227db31f50d5542cafe08445596800801)
- Marlink Cyber Security Advisory: [MCSAID-2026-034](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-034-moos-ivp-ufldshorebroker-unbounded-community-state-retention.md)
- Merge commit: [d40a41371dae55a172b7d04319cbfd667153ff0a](https://github.com/moos-ivp/moos-ivp/commit/d40a41371dae55a172b7d04319cbfd667153ff0a)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
