# MOOS-IvP: Buffer Overflow in IvP Function String Decoders

- **Advisory ID:** MCSAID-2026-023
- **CVE ID:** [CVE-2026-85437](https://www.cve.org/CVERecord?id=CVE-2026-85437)
- **Published:** 2026-09-02
- **Severity:** Critical (CVSS 9.8 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **CVSS 4.0:** 9.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Out-of-bounds Write
- **Current state:** Fixed upstream in `main` by [Pull Request #125](https://github.com/moos-ivp/moos-ivp/pull/125) (merged 2026-10-03); not yet in a tagged release (latest release is v24.8.1)
- **Software:** [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
- **CWE:** [CWE-787: Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

The IvP function-string decoders allocate a buffer from a declared context length and then copy up to the next comma regardless, copy the domain field into a fixed 5000-byte array with no bound at all, and locate every field with `while(str[cix] != ',')` - which walks off the end of the string when a delimiter is missing. All three are reachable from a single `BHV_IPF` publication.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |
| moos-ivp `main` from commit [`ebe0bf9d6ecd`](https://github.com/moos-ivp/moos-ivp/commit/ebe0bf9d6ecdc86172d4b22b983f591ea0e64ce2) | Fixed |

Tested against: MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master.

---

## Impact

Heap and stack corruption in operator-facing tools, driven by one MOOS
publication or one crafted log file.  The context-length case is a
fully-controlled heap overflow (attacker picks both the allocation size and the
number of bytes written), which is the most exploitable primitive in this
report.

---

## Exploitation

Any BHV_IPF publisher on a MOOSDB that uFunctionVis watches, or the supplier of an .alog file opened in alogview.

Preconditions:

* uFunctionVis or alogview in use. Both are stock, built by default. No configuration is required.

---

## Details

### Affected code

* **`ivp/src/lib_ivpbuild/FunctionEncoder.cpp`** - lines 298-311: StringToIvPFunction(): cstr_buff = new char[cstr_len+10] where cstr_len is declared, but the copy loop runs to the next comma with no capacity check
* **`ivp/src/lib_ivpbuild/FunctionEncoder.cpp`** - lines 366-378: the domain field is copied into `char buff[5000]` with no bound at all
* **`ivp/src/lib_ivpbuild/FunctionEncoder.cpp`** - lines 499-524: StringToIvPContext(): the same declared-length-vs-actual-field mismatch
* **`ivp/src/lib_ivpbuild/FunctionEncoder.cpp`** - lines 300-505: every field is scanned with `while(str[cix] != ',')`, which reads past the end of the std::string when a delimiter is missing
* **`ivp/src/lib_ivpbuild/FunctionEncoderMK.cpp`** - lines 292-380: duplicated decoder with the same defects
* **`ivp/src/uFunctionVis/FV_MOOSApp.cpp`** - lines 63-66, 125: BHV_IPF from the bus is demultiplexed and handed to StringToIvPContext / the model
* **`ivp/src/lib_ipfview/IPF_Entry.cpp`** - lines 48, 66: StringToIvPFunction on stored IPF strings
* **`ivp/src/app_alogview/IvPFuncViewerX.cpp`** - lines 439, 537: StringToIvPFunction on log contents

### Root cause

The decoders are hand-written pointer walkers with three independent flaws.

1. The context string's length is read from the message, used to size a
   `new char[cstr_len+10]` buffer, and then *ignored*: the copy loop runs until
   it sees a comma.  Declaring `1` and supplying 4000 bytes writes 4000 bytes
   into an 11-byte heap allocation.
2. The domain field is copied into a fixed `char buff[5000]` with no length
   check whatsoever.
3. Every field is located with `while(str[cix] != ',')`.  `std::string::operator[]`
   past `size()` is undefined behaviour, so a truncated or delimiter-free string
   walks off the end of the buffer - and, because the scan also accumulates
   digits, off the end while signed-overflowing an `int`.

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

Reproduced both in isolation and end to end against a live ASan `uFunctionVis`
driven by an unauthenticated MOOS publisher:

    FunctionEncoder.cpp:516: runtime error: store to address ... with
        insufficient space for an object of type 'char'
    ERROR: AddressSanitizer: heap-buffer-overflow ... WRITE of size 1
        #0 StringToIvPContext(...) FunctionEncoder.cpp:516

    FunctionEncoder.cpp:374: runtime error: index 5000 out of bounds for
        type 'char [5000]'
    ERROR: AddressSanitizer: stack-buffer-overflow ... WRITE of size 1
        #0 StringToIvPFunction(...) FunctionEncoder.cpp:374

    (truncated input "H,1")
    FunctionEncoder.cpp:506: runtime error: signed integer overflow:
        -433333328 * 10 cannot be represented in type 'int'
    ERROR: AddressSanitizer: stack-buffer-overflow ... READ of size 1

---

## Mitigations

Fixed upstream in the `main` branch; no tagged release containing the fix exists yet.

- Pull request: [Pull Request #125](https://github.com/moos-ivp/moos-ivp/pull/125) (merged 2026-10-03)
- Fix commit: [ebe0bf9d6ecd](https://github.com/moos-ivp/moos-ivp/commit/ebe0bf9d6ecdc86172d4b22b983f591ea0e64ce2)

### Recommended fix

Rewrite the decoders against a bounds-checked cursor - `std::string_view` with
explicit `find(',')` and a `npos` check, or a small tokeniser that returns
`std::optional`.  Require every delimiter to be present, require the declared
context length to equal the actual field length, cap each field at a documented
maximum, and return a parse error before allocating.  Delete
`FunctionEncoderMK.cpp` or make it call the same validated implementation
instead of duplicating the bug.

---

## Recommendations

- Upgrade to a moos-ivp release that includes commit [`ebe0bf9d6ecd`](https://github.com/moos-ivp/moos-ivp/commit/ebe0bf9d6ecdc86172d4b22b983f591ea0e64ce2) once available, or build from `main` at or after that commit.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85437 published
- 2026-10-03 – Fix merged upstream in [Pull Request #125](https://github.com/moos-ivp/moos-ivp/pull/125)
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85437](https://www.cve.org/CVERecord?id=CVE-2026-85437)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 Buffer Overflow in IvP Function String Decoders](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-buffer-overflow-in-ivp-function-string-decoders)
- Upstream pull request: [Pull Request #125](https://github.com/moos-ivp/moos-ivp/pull/125)
- Fix commit (PR head): [81ca795fcfd62b42002d277f5a2390f4c8ab8c7f](https://github.com/moos-ivp/moos-ivp/commit/81ca795fcfd62b42002d277f5a2390f4c8ab8c7f)
- Marlink Cyber Security Advisory: [MCSAID-2026-023](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-023-moos-ivp-buffer-overflow-in-ivp-function-string-decoders.md)
- Merge commit: [ebe0bf9d6ecdc86172d4b22b983f591ea0e64ce2](https://github.com/moos-ivp/moos-ivp/commit/ebe0bf9d6ecdc86172d4b22b983f591ea0e64ce2)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
