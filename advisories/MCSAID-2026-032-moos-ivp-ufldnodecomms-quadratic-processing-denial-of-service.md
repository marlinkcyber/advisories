# MOOS-IvP: uFldNodeComms Quadratic Processing Denial of Service

- **Advisory ID:** MCSAID-2026-032
- **CVE ID:** [CVE-2026-85446](https://www.cve.org/CVERecord?id=CVE-2026-85446)
- **Published:** 2026-09-02
- **Severity:** High (CVSS 7.5 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **CVSS 4.0:** 8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Inefficient Algorithmic Complexity
- **Current state:** Fixed upstream in `main` by [Pull Request #131](https://github.com/moos-ivp/moos-ivp/pull/131) (merged 2026-10-05); not yet in a tagged release (latest release is v24.8.1)
- **Software:** [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
- **CWE:** [CWE-407: Inefficient Algorithmic Complexity](https://cwe.mitre.org/data/definitions/407.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

Node identity in uFldNodeComms is just the `NAME` field of a `NODE_REPORT`. Every new name is retained and each new record is then compared against the entire ledger before any staleness cleanup, so N asserted identities cost O(N^2) work. 43 kB of traffic multiplied the broker's steady-state CPU by 48 and stopped legitimate vehicle-to-vehicle messages from being delivered at all.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |
| moos-ivp `main` from commit [`3f0928a9712f`](https://github.com/moos-ivp/moos-ivp/commit/3f0928a9712f802d020414e190ed21a1a028d34b) | Fixed |

Tested against: MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master.

---

## Impact

CPU, memory and MOOS notification amplification that starves legitimate field
communications.  This is the broker every vehicle depends on for
vehicle-to-vehicle messaging, so degrading it is a mission-availability
attack.

---

## Exploitation

Any publisher of NODE_REPORT on the shoreside MOOSDB, or anything upstream of a field bridge.

Preconditions:

* uFldNodeComms running (the standard shoreside field-comms broker).

---

## Details

### Affected code

* **`ivp/src/uFldNodeComms/FldNodeComms.cpp`** - lines 315-321: handleMailNodeReport(): every new NAME becomes a ledger entry and is flagged as a new record
* **`ivp/src/uFldNodeComms/FldNodeComms.cpp`** - lines 518-526: distributeNodeReportInfo(): iterates the whole ledger for each new record
* **`ivp/src/uFldNodeComms/FldNodeComms.cpp`** - lines 840-900: the all-pairs distribution runs before any staleness cleanup

### Root cause

Node identity is the `NAME` field of a `NODE_REPORT`.  Any new name creates a
new ledger entry and is marked as a new record.  For each new record,
`distributeNodeReportInfo()` walks *all* known names to decide who should
receive it, so N new names cost O(N^2) comparisons and up to O(N^2)
notifications.  Stale entries are removed only after a substantial retention
interval, and only after the expensive fanout has already run.

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

43 kB of `NODE_REPORT` traffic (400 unique names, ~110 bytes each):

    steady-state CPU with 5 nodes   :   0.2% of a core
    steady-state CPU with 405 nodes :   8.0% of a core   (48x amplification)
    RSS                             :   5336 kB -> 16664 kB

and, decisively, a genuine node-to-node `NODE_MESSAGE` between two real
vehicles was **never delivered within 25 seconds** after the flood.

---

## Mitigations

Fixed upstream in the `main` branch; no tagged release containing the fix exists yet.

- Pull request: [Pull Request #131](https://github.com/moos-ivp/moos-ivp/pull/131) (merged 2026-10-05)
- Fix commit: [3f0928a9712f](https://github.com/moos-ivp/moos-ivp/commit/3f0928a9712f802d020414e190ed21a1a028d34b)

### Recommended fix

Authenticate and enrol node identities so a name cannot simply be asserted.
Cap the number of active identities and the length of a name, rate-limit the
creation of new identities, give each iteration a work budget, and replace the
all-pairs fanout with an index keyed on the actual relevance criteria
(range/group).  Run staleness cleanup before distribution, not after.

---

## Recommendations

- Upgrade to a moos-ivp release that includes commit [`3f0928a9712f`](https://github.com/moos-ivp/moos-ivp/commit/3f0928a9712f802d020414e190ed21a1a028d34b) once available, or build from `main` at or after that commit.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85446 published
- 2026-10-05 – Fix merged upstream in [Pull Request #131](https://github.com/moos-ivp/moos-ivp/pull/131)
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85446](https://www.cve.org/CVERecord?id=CVE-2026-85446)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 uFldNodeComms Quadratic Processing Denial of Service](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-ufldnodecomms-quadratic-processing-denial-of-service)
- Upstream pull request: [Pull Request #131](https://github.com/moos-ivp/moos-ivp/pull/131)
- Fix commit (PR head): [8e30008d4eb68d83797187bd46e929e6cb06b195](https://github.com/moos-ivp/moos-ivp/commit/8e30008d4eb68d83797187bd46e929e6cb06b195)
- Marlink Cyber Security Advisory: [MCSAID-2026-032](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-032-moos-ivp-ufldnodecomms-quadratic-processing-denial-of-service.md)
- Merge commit: [3f0928a9712f802d020414e190ed21a1a028d34b](https://github.com/moos-ivp/moos-ivp/commit/3f0928a9712f802d020414e190ed21a1a028d34b)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
