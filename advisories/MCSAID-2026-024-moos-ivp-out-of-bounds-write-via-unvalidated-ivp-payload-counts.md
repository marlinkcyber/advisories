# MOOS-IvP: Out-of-Bounds Write via Unvalidated IvP Payload Counts

- **Advisory ID:** MCSAID-2026-024
- **CVE ID:** [CVE-2026-85438](https://www.cve.org/CVERecord?id=CVE-2026-85438)
- **Published:** 2026-09-02
- **Severity:** Critical (CVSS 9.8 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **CVSS 4.0:** 9.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Integer Overflow or Wraparound
- **Current state:** Fixed upstream in `main` by [Pull Request #126](https://github.com/moos-ivp/moos-ivp/pull/126) (merged 2026-10-05); not yet in a tagged release (latest release is v24.8.1)
- **Software:** [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
- **CWE:** [CWE-190: Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

Every structural count in a serialised IvP function - dimensions, pieces, degree - is parsed by accumulating decimal digits into a signed `int` with no bound and no overflow check, then used directly to allocate and to iterate. `IvPBox` additionally narrows the dimension and degree to `short`, so a large dimension becomes negative, no arrays are allocated, and the decoder writes through null pointers.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |
| moos-ivp `main` from commit [`718d3dbfe847`](https://github.com/moos-ivp/moos-ivp/commit/718d3dbfe847bf88b4d2178b171b926088f9ea03) | Fixed |

Tested against: MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master.

---

## Impact

Memory and CPU exhaustion of the consuming process, and out-of-bounds access
after the `short` narrowing.  For uFunctionVis and alogview - operator-facing
tools - this is a remote crash of the display; for any process that decodes
BHV_IPF it is a denial of service driven by one message.

---

## Exploitation

Any BHV_IPF publisher (uFunctionVis, alogview, pHelmIvP consumers), or the supplier of an .alog file.

Preconditions:

* A consumer of IvP function strings: uFunctionVis and alogview are the in-tree ones; both are stock apps.

---

## Details

### Affected code

* **`ivp/src/lib_ivpbuild/FunctionEncoder.cpp`** - lines 295-405: dim, pcs, deg and the domain/gelbox fields are accumulated with `x = x*10 + digit` in signed ints, with no range or overflow check
* **`ivp/src/lib_ivpbuild/FunctionEncoder.cpp`** - lines 406-409: int wtc = (deg*dim)+1;  then `for(d=0; d<wtc; d++) newbox->wt(d) = ...`
* **`ivp/src/lib_ivpcore/PDMap.cpp`** - lines 57-74: m_boxes = new IvPBox *[m_boxCount] with m_boxCount straight from the wire
* **`ivp/src/lib_ivpcore/IvPBox.cpp`** - lines 43-71: m_dim = (short int)g_dim - a narrowing conversion; if it goes negative or zero, no arrays are allocated and the caller writes through null pointers
* **`ivp/src/lib_ivpbuild/FunctionEncoderMK.cpp`** - lines 292-380: the same parser, duplicated

### Root cause

Every structural count in the serialised IvP function is parsed by accumulating
decimal digits into a signed `int` with no bound and no overflow detection, then
used directly for allocation and iteration:

* `pcs` sizes `new IvPBox*[pcs]` in `PDMap` and controls the piece loop.
* `dim` and `deg` size each `IvPBox`, and `(deg*dim)+1` is the weight count -
  a product of two attacker integers, computed in `int`.
* `IvPBox` then narrows `dim` and `deg` to `short`.  `dim = 100000` becomes
  `-31072`, so `if(m_dim > 0)` is false, no arrays are allocated, and the
  decoder's `newbox->setPTS(d, ...)` / `newbox->wt(d)` calls dereference null.

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

* `deg=dim=100000` (so `wtc` is computed from a `short`-narrowed dimension):
  `AddressSanitizer: heap-buffer-overflow ... READ of size 1` at
  FunctionEncoder.cpp:397.
* `pcs=100000000` under a 1.5 GB address-space limit: `Segmentation fault`
  (exit 139) - `PDMap` allocated 800 MB of pointers and construction then ran
  out of memory.

Reachability was also shown end to end against a live ASan `uFunctionVis`: a
single `BHV_IPF` publication from an unauthenticated MOOS peer reaches
`StringToIvPFunction` / `StringToIvPContext` and crashes the viewer.

---

## Mitigations

Fixed upstream in the `main` branch; no tagged release containing the fix exists yet.

- Pull request: [Pull Request #126](https://github.com/moos-ivp/moos-ivp/pull/126) (merged 2026-10-05)
- Fix commit: [718d3dbfe847](https://github.com/moos-ivp/moos-ivp/commit/718d3dbfe847bf88b4d2178b171b926088f9ea03)

### Recommended fix

Use `std::from_chars` (or `strtol` with `errno` checking) for every count,
reject anything outside a documented supported range, and compute
`(deg*dim)+1` with a checked multiply.  Impose an aggregate budget on the total
decoded size before allocating anything.  Store `dim`/`degree` as `int` in
`IvPBox`, or validate them against `SHRT_MAX` before narrowing, and make
`IvPBox` fail construction loudly rather than silently allocating nothing.

---

## Recommendations

- Upgrade to a moos-ivp release that includes commit [`718d3dbfe847`](https://github.com/moos-ivp/moos-ivp/commit/718d3dbfe847bf88b4d2178b171b926088f9ea03) once available, or build from `main` at or after that commit.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85438 published
- 2026-10-05 – Fix merged upstream in [Pull Request #126](https://github.com/moos-ivp/moos-ivp/pull/126)
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85438](https://www.cve.org/CVERecord?id=CVE-2026-85438)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 Out-of-Bounds Write via Unvalidated IvP Payload Counts](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-out-of-bounds-write-via-unvalidated-ivp-payload-counts)
- Upstream pull request: [Pull Request #126](https://github.com/moos-ivp/moos-ivp/pull/126)
- Fix commit (PR head): [85f4653ff792b30c3ab14dc0eac0991d1405d904](https://github.com/moos-ivp/moos-ivp/commit/85f4653ff792b30c3ab14dc0eac0991d1405d904)
- Marlink Cyber Security Advisory: [MCSAID-2026-024](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-024-moos-ivp-out-of-bounds-write-via-unvalidated-ivp-payload-counts.md)
- Merge commit: [718d3dbfe847bf88b4d2178b171b926088f9ea03](https://github.com/moos-ivp/moos-ivp/commit/718d3dbfe847bf88b4d2178b171b926088f9ea03)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
