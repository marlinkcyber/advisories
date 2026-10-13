# MOOS-IvP: pMarineViewer Unbounded Memory Consumption via NODE_REPORT

- **Advisory ID:** MCSAID-2026-035
- **CVE ID:** [CVE-2026-85449](https://www.cve.org/CVERecord?id=CVE-2026-85449)
- **Published:** 2026-09-02
- **Severity:** High (CVSS 7.5 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **CVSS 4.0:** 8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Allocation of Resources Without Limits or Throttling
- **Current state:** Fixed upstream in `main` by [Pull Request #134](https://github.com/moos-ivp/moos-ivp/pull/134) (merged 2026-09-11); not yet in a tagged release (latest release is v24.8.1)
- **Software:** [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
- **CWE:** [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

pMarineViewer accepts every unique `NODE_REPORT` name into its contact ledger, bounds only the per-node history, and redraws by walking the full vehicle list every frame with no work budget and no automatic stale eviction. 430 kB of node reports added 4000 permanent contacts, 18.7 MB of memory and a 23-fold increase in render cost to the operator's display.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |
| moos-ivp `main` from commit [`5650f5eb824d`](https://github.com/moos-ivp/moos-ivp/commit/5650f5eb824dbb94a790c4f4ca07d525ada5a12a) | Fixed |

Tested against: MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master.

---

## Impact

Memory growth and a collapsing frame rate in the operator's situational-awareness
display - i.e. the operator loses the picture at exactly the moment an attacker
is doing something else.  It is a usability/availability attack on the human in
the loop rather than on the autonomy itself.

---

## Exploitation

Any field publisher able to supply NODE_REPORT data, directly or through a bridge.

Preconditions:

* pMarineViewer running - the standard operator display. No configuration change needed.

---

## Details

### Affected code

* **`ivp/src/pMarineViewer/PMV_MOOSApp.cpp`** - lines 324-359: NODE_REPORT / NODE_REPORT_LOCAL are subscribed by default and handed to the ContactLedger
* **`ivp/src/lib_geodaid/ContactLedger.cpp`** - lines 37-47: every NAME becomes a new ledger entry; the history cap is per node, not on the number of nodes
* **`ivp/src/pMarineViewer/PMV_Viewer.cpp`** - lines 182-311: the draw path enumerates every vehicle every frame with no per-frame work budget

### Root cause

Node identity is a name in a `NODE_REPORT`.  The viewer accepts every new name
into its `ContactLedger`, bounds only the per-node history, and redraws by
walking the full vehicle list each frame.  Stale eviction is not enabled on the
default path and there is no cap on the number of nodes.

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

430 kB of `NODE_REPORT` traffic (4000 unique names) against a stock
pMarineViewer running headless:

    RSS  161576 kB -> 180732 kB   (+18.7 MB)
    CPU  6.6% -> 151.0% of a core (23x; more than one core saturated)

and the 4000 identities stay in the ledger indefinitely.

---

## Mitigations

Fixed upstream in the `main` branch; no tagged release containing the fix exists yet.

- Pull request: [Pull Request #134](https://github.com/moos-ivp/moos-ivp/pull/134) (merged 2026-09-11)
- Fix commit: [5650f5eb824d](https://github.com/moos-ivp/moos-ivp/commit/5650f5eb824dbb94a790c4f4ca07d525ada5a12a)

### Recommended fix

Enrol node identities (or at least require them to have been seen by an
authenticated broker), cap the number of active contacts and the total history,
rate-limit the creation of new identities, evict stale contacts automatically by
default, and bound per-frame rendering work (cull off-screen contacts, or cap
the number drawn per frame).

---

## Recommendations

- Upgrade to a moos-ivp release that includes commit [`5650f5eb824d`](https://github.com/moos-ivp/moos-ivp/commit/5650f5eb824dbb94a790c4f4ca07d525ada5a12a) once available, or build from `main` at or after that commit.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85449 published
- 2026-09-11 – Fix merged upstream in [Pull Request #134](https://github.com/moos-ivp/moos-ivp/pull/134)
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85449](https://www.cve.org/CVERecord?id=CVE-2026-85449)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 pMarineViewer Unbounded Memory Consumption via NODE_REPORT](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-pmarineviewer-unbounded-memory-consumption-via-node-report)
- Upstream pull request: [Pull Request #134](https://github.com/moos-ivp/moos-ivp/pull/134)
- Fix commit (PR head): [4d8d0693d3f8bf8907dc0aed04ea488d85af9f22](https://github.com/moos-ivp/moos-ivp/commit/4d8d0693d3f8bf8907dc0aed04ea488d85af9f22)
- Marlink Cyber Security Advisory: [MCSAID-2026-035](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-035-moos-ivp-pmarineviewer-unbounded-memory-consumption-via-node-report.md)
- Merge commit: [5650f5eb824dbb94a790c4f4ca07d525ada5a12a](https://github.com/moos-ivp/moos-ivp/commit/5650f5eb824dbb94a790c4f4ca07d525ada5a12a)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
