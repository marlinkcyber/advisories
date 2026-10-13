# MOOS-IvP: uFldNodeComms Node Message Source Spoofing

- **Advisory ID:** MCSAID-2026-015
- **CVE ID:** [CVE-2026-85429](https://www.cve.org/CVERecord?id=CVE-2026-85429)
- **Published:** 2026-09-02
- **Severity:** High (CVSS 7.5 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N)
- **CVSS 4.0:** 8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N)
- **Vulnerability type:** Insufficient Verification of Data Authenticity
- **Current state:** Fixed upstream in `main` by [Pull Request #122](https://github.com/moos-ivp/moos-ivp/pull/122) (merged 2026-09-11); not yet in a tagged release (latest release is v24.8.1)
- **Software:** [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
- **CWE:** [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

`NODE_MESSAGE` carries its own `src_node` field, and uFldNodeComms validates range, freshness and group membership against that claimed identity's ledger record - which the same attacker can create. The receiving vehicle's uFldMessageHandler then calls `Notify(var_name, value, src_node)` with no allow-list, so a field publisher can write any MOOS variable on any vehicle, including the helm override.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |
| moos-ivp `main` from commit [`21cb05149415`](https://github.com/moos-ivp/moos-ivp/commit/21cb051494158b072fc50ab3bc774e0787774587) | Fixed |

Tested against: MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master.

---

## Impact

Cross-node command injection: an attacker with field access can order any
vehicle to change mode, deploy, return, drop its manual override, or accept
falsified data, and the action is attributed to another node in the logs.

---

## Exploitation

Any field or bridged publisher, with no authority for the node it claims to be.

Preconditions:

* uFldNodeComms on the shore for the relay half; uFldMessageHandler on the vehicle for the sink half. Both are stock apps in the standard field configuration.
* For the relay, a NODE_REPORT for the claimed source name must exist - which the same attacker can publish (see [MCSAID-2026-010](./MCSAID-2026-010-core-moos-missing-authentication-for-moosdb-publish-subscribe-and-db-clear.md)).

---

## Details

### Affected code

* **`ivp/src/uFldNodeComms/FldNodeComms.cpp`** - lines 331-352: handleMailNodeMessage(): the source node is taken from the message body
* **`ivp/src/uFldNodeComms/FldNodeComms.cpp`** - lines 655-742: distributeNodeMessageInfo(): range, staleness and group checks are all evaluated against the claimed identity's ledger entry
* **`ivp/src/uFldMessageHandler/MessageHandler.cpp`** - lines 168-247: Notify(var_name, var_sval, src_node) - arbitrary key and value, no allow-list
* **`ivp/src/lib_mbutil/NodeMessage.cpp`** - lines 113-128: valid() requires only a non-empty src_node, some destination, and a non-empty var_name

### Root cause

`src_node` is a plain field in the `NODE_MESSAGE` body.  uFldNodeComms uses it as
the sender's identity and validates range, freshness and group membership
against *that* identity's ledger record - a record the attacker can also create.
The message is then forwarded to every named destination as
`NODE_MESSAGE_<DEST>`.

On the receiving vehicle, `uFldMessageHandler` parses the body and calls
`Notify(var_name, var_sval, src_node)`.  There is no allow-list of permissible
variable names, so any MOOS variable on the vehicle can be written - including
the helm override and deployment flags.

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

*Sink*: against a stock `uFldMessageHandler` on community `bravo`, four
`NODE_MESSAGE` bodies claiming `src_node=shoreside` poked
`MOOS_MANUAL_OVERRIDE='false'`, `DEPLOY='true'`, `RETURN='false'` and
`UP_LOITER='center_assign=41.5,-71.2'`.

*Relay*: against a stock `uFldNodeComms`, a client named `rogue-field-node`
published a `NODE_MESSAGE` with `src_node=alpha`, and the broker relayed it as
both `NODE_MESSAGE_BRAVO` and `NODE_MESSAGE_CHARLIE`, preserving the spoofed
`src_node=alpha` (and adding `src_app=rogue-field-node`, which is the only trace
of the real origin).

---

## Mitigations

Fixed upstream in the `main` branch; no tagged release containing the fix exists yet.

- Pull request: [Pull Request #122](https://github.com/moos-ivp/moos-ivp/pull/122) (merged 2026-09-11)
- Fix commit: [21cb05149415](https://github.com/moos-ivp/moos-ivp/commit/21cb051494158b072fc50ab3bc774e0787774587)

### Recommended fix

Authenticate messages end to end: sign the body with a key bound to the source
node, add a replay window and a message counter, and reject anything whose
signature does not match the claimed `src_node`.  On the receiving side, give
`uFldMessageHandler` a mandatory per-source allow-list of variables it may
write, defaulting to empty, and never let a field message write helm/override
variables unless explicitly configured.

---

## Recommendations

- Upgrade to a moos-ivp release that includes commit [`21cb05149415`](https://github.com/moos-ivp/moos-ivp/commit/21cb051494158b072fc50ab3bc774e0787774587) once available, or build from `main` at or after that commit.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85429 published
- 2026-09-11 – Fix merged upstream in [Pull Request #122](https://github.com/moos-ivp/moos-ivp/pull/122)
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85429](https://www.cve.org/CVERecord?id=CVE-2026-85429)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 uFldNodeComms Node Message Source Spoofing](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-ufldnodecomms-node-message-source-spoofing)
- Upstream pull request: [Pull Request #122](https://github.com/moos-ivp/moos-ivp/pull/122)
- Fix commit (PR head): [3907ac07cdfd8a7255d65657dc18dc6b77b30b64](https://github.com/moos-ivp/moos-ivp/commit/3907ac07cdfd8a7255d65657dc18dc6b77b30b64)
- Marlink Cyber Security Advisory: [MCSAID-2026-015](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-015-moos-ivp-ufldnodecomms-node-message-source-spoofing.md)
- Merge commit: [21cb051494158b072fc50ab3bc774e0787774587](https://github.com/moos-ivp/moos-ivp/commit/21cb051494158b072fc50ab3bc774e0787774587)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
