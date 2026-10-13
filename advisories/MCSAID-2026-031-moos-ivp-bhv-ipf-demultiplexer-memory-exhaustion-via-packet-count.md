# MOOS-IvP: BHV_IPF Demultiplexer Memory Exhaustion via Packet Count

- **Advisory ID:** MCSAID-2026-031
- **CVE ID:** [CVE-2026-85445](https://www.cve.org/CVERecord?id=CVE-2026-85445)
- **Published:** 2026-09-02
- **Severity:** High (CVSS 7.5 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **CVSS 4.0:** 8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Memory Allocation with Excessive Size Value
- **Current state:** Fixed upstream in `main` by [Pull Request #129](https://github.com/moos-ivp/moos-ivp/pull/129) (merged 2026-10-03); not yet in a tagged release (latest release is v24.8.1)
- **Software:** [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
- **CWE:** [CWE-789: Memory Allocation with Excessive Size Value](https://cwe.mitre.org/data/definitions/789.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

The BHV_IPF demultiplexer parses the declared fragment count digit by digit into a signed `int` with no maximum and pre-fills two vectors with that many entries. A 21-byte publication requesting 900 million fragments grew a live uFunctionVis by 3.5 GB in 30 seconds. The same scanning loops also read past the end of the string when the expected commas are absent.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |
| moos-ivp `main` from commit [`1db7a5d19ffc`](https://github.com/moos-ivp/moos-ivp/commit/1db7a5d19ffc5dfec66e121af320cbcff24361bc) | Fixed |

Tested against: MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master.

---

## Impact

Memory exhaustion of the operator's display process from a single small
message, plus an out-of-bounds read.  This is a remote crash/freeze of the
autonomy visualisation tool.

---

## Exploitation

Any MOOS publisher of BHV_IPF.

Preconditions:

* uFunctionVis running (stock app). Any other consumer of Demuxer is equally affected.

---

## Details

### Affected code

* **`ivp/src/lib_ivpbuild/Demuxer.cpp`** - lines 88-144: addMuxPacket(): str_id, str_total and str_ix are accumulated with `x = x*10 + digit` in signed ints with no grammar, no maximum, and no end-of-string check
* **`ivp/src/lib_ivpbuild/DemuxUnit.cpp`** - lines 34-46: DemuxUnit(id, total_packets, ...): for(i=0; i<g_total_packets; i++) { m_data.push_back(""); m_flag.push_back(false); }
* **`ivp/src/uFunctionVis/FV_MOOSApp.cpp`** - lines 63-66: BHV_IPF from the bus goes straight to addMuxPacket; removeStaleUnits() is never called by this consumer

### Root cause

The mux header is `P,<id>,<total>,<index>,<body>`.  `total` is parsed digit by
digit into a signed `int` and passed as `unsigned int` to `DemuxUnit`, which
`push_back`s that many `std::string` and `bool` entries.  Nine digits is enough
to request ~29 GB of vector storage from a 21-byte message.

The same scanning loops use `str[cix]` with no bound, so a mux header without
the expected commas reads past the end of the string.  And because
`removeStaleUnits()` is never invoked by uFunctionVis, incomplete units
accumulate for every distinct attacker-chosen `id`.

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

* `P,` (no delimiters): `AddressSanitizer: stack-buffer-overflow ... READ of
  size 1` at Demuxer.cpp:98.
* `P,bb,900000000,1,body` under a 1.5 GB address-space limit:
  `terminate called after throwing an instance of 'std::bad_alloc'`.
* End to end against a live ASan `uFunctionVis`: that same 21-byte publication
  grew the viewer by **3.49 GB in 30 seconds** and it was still allocating; an
  earlier unattended run reached 13 GB RSS.

---

## Mitigations

Fixed upstream in the `main` branch; no tagged release containing the fix exists yet.

- Pull request: [Pull Request #129](https://github.com/moos-ivp/moos-ivp/pull/129) (merged 2026-10-03)
- Fix commit: [1db7a5d19ffc](https://github.com/moos-ivp/moos-ivp/commit/1db7a5d19ffc5dfec66e121af320cbcff24361bc)

### Recommended fix

Parse the header with a strict grammar (`std::from_chars` on a bounded
`string_view`), require every delimiter, and cap `total_packets`, the id length,
the per-packet body size and the reassembled size.  Reserve lazily rather than
pre-filling the vectors.  Cap the number of concurrent incomplete units per
source and expire them on a timer inside `Demuxer` itself, so a consumer cannot
forget to call `removeStaleUnits()`.

---

## Recommendations

- Upgrade to a moos-ivp release that includes commit [`1db7a5d19ffc`](https://github.com/moos-ivp/moos-ivp/commit/1db7a5d19ffc5dfec66e121af320cbcff24361bc) once available, or build from `main` at or after that commit.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85445 published
- 2026-10-03 – Fix merged upstream in [Pull Request #129](https://github.com/moos-ivp/moos-ivp/pull/129)
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85445](https://www.cve.org/CVERecord?id=CVE-2026-85445)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 BHV_IPF Demultiplexer Memory Exhaustion via Packet Count](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-bhv-ipf-demultiplexer-memory-exhaustion-via-packet-count)
- Upstream pull request: [Pull Request #129](https://github.com/moos-ivp/moos-ivp/pull/129)
- Fix commit (PR head): [fc5649ac12915f66a9f09520cdb6b14bc6d77595](https://github.com/moos-ivp/moos-ivp/commit/fc5649ac12915f66a9f09520cdb6b14bc6d77595)
- Marlink Cyber Security Advisory: [MCSAID-2026-031](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-031-moos-ivp-bhv-ipf-demultiplexer-memory-exhaustion-via-packet-count.md)
- Merge commit: [1db7a5d19ffc5dfec66e121af320cbcff24361bc](https://github.com/moos-ivp/moos-ivp/commit/1db7a5d19ffc5dfec66e121af320cbcff24361bc)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
