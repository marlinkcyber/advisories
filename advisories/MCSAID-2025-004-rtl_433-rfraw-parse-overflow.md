# rtl_433: Stack-based Buffer Overflow in `parse_rfraw()` (src/rfraw.c) Leads to Denial of Service / Memory Corruption

- **Advisory ID:** MCSAID-2025-004
- **CVE ID:** *(Pending)*
- **Product:** [rtl_433](https://github.com/merbanan/rtl_433)
- **Reported:** 2025-10-08
- **Published:** 2025-10-08
- **Fixed:** [commit 25e47f8 in master branch (closes #3375)](https://github.com/dd32/rtl_433/commit/25e47f8932f0401392ef1d3c8cc9ed5595bc894a)
- **Severity:** High (Memory corruption / crash)
- **CWE:** [CWE-121: Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

A stack-based buffer overflow vulnerability was discovered in `rtl_433` in the function `parse_rfraw()` (file `src/rfraw.c`). When parsing malicious or overly large raw RF data, this flaw can corrupt the stack, leading to a crash (Denial of Service) or potentially further control over execution.

This issue was resolved in commit [`25e47f8` (closes issue #3375)](https://github.com/dd32/rtl_433/commit/25e47f8932f0401392ef1d3c8cc9ed5595bc894a)

---

## Affected Versions

| Version | Status |
|---|---|
| 25.02 and earlier | Vulnerable |
| prior to commit `25e47f8` | Vulnerable |
| including and after commit `25e47f8` | Patched |

---

## Technical Details

In `parse_rfraw()`, input data lengths are not sufficiently bounded, allowing crafted RF raw data (e.g. via `-r` or `-H` options) to overflow a local buffer on the stack. Under AddressSanitizer or similar bounds checking, the overflow is detected as:


```
$ src/rtl_433 -y @/htp/rtl/overflow.txt
rtl_433 version 25.02-45-g7693dcc5 branch master at 202509251903 inputs file rtl_tcp RTL-SDR with TLS
[Input] Reading test data from "/htp/rtl/overflow.txt"
=================================================================
==1809738==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x753e43c04eb8 at pc 0x61df368be354 bp 0x7ffdcee34520 sp 0x7ffdcee34510
WRITE of size 4 at 0x753e43c04eb8 thread T0
    #0 0x61df368be353 in parse_rfraw /htp/rtl/rtl_433/src/rfraw.c:158
    #1 0x61df368be353 in rfraw_parse /htp/rtl/rtl_433/src/rfraw.c:190
    #2 0x61df3681f74f in main /htp/rtl/rtl_433/src/rtl_433.c:1825
    #3 0x753e4542a1c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #4 0x753e4542a28a in __libc_start_main_impl ../csu/libc-start.c:360
    #5 0x61df36824da4 in _start (/htp/rtl/rtl_433/build_asan/src/rtl_433+0xcfda4) (BuildId: fba2b3d3dbe52e719e39d519e052d309b6361d15)

Address 0x753e43c04eb8 is located in stack of thread T0 at offset 20152 in frame
    #0 0x61df3681e5df in main /htp/rtl/rtl_433/src/rtl_433.c:1624

  This frame has 11 object(s):
    [32, 40) 'e' (line 1787)
    [64, 80) 'delay_timer' (line 1964)
    [96, 112) 'now_tv' (line 108)
    [128, 152) 'p' (line 1726)
    [192, 216) 'single_dev' (line 1811)
    [256, 288) 'opts' (line 2077)
    [320, 472) 'sigact' (line 2044)
    [544, 10216) 'pulse_data' (line 1809)
    [10480, 20152) 'pulse_data' (line 1850) <== Memory access at offset 20152 overflows this variable
    [20416, 21440) 'decoders_str' (line 1723)
    [21568, 29760) 'line' (line 1767)
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow /htp/rtl/rtl_433/src/rfraw.c:158 in parse_rfraw
Shadow bytes around the buggy address:
  0x753e43c04c00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x753e43c04c80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x753e43c04d00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x753e43c04d80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x753e43c04e00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x753e43c04e80: 00 00 00 00 00 00 00[f2]f2 f2 f2 f2 f2 f2 f2 f2
  0x753e43c04f00: f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2
  0x753e43c04f80: f2 f2 f2 f2 f2 f2 f2 f2 f8 f8 f8 f8 f8 f8 f8 f8
  0x753e43c05000: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
  0x753e43c05080: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
  0x753e43c05100: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==1809738==ABORTING
```

Because this is a classic stack overflow, it can override nearby local variables or return addresses, possibly enabling control-flow alteration. The primary demonstrated impact is crash; full exploitability would require further investigation.

---

## Test

```
$ src/rtl_433 -y @/htp/rtl/overflow.txt
```

[overflow.txt](https://github.com/user-attachments/files/22759886/overflow.txt)


---

## Impact

- **Impact:** Denial of Service (crash), memory corruption; potential for code execution (depending on environment)
- **Attack Vector:** Local or via input from device (malicious RF data)
- **Privileges Required:** None
- **User Interaction:** n/a (processing input unpacked by rtl_433)

**Suggested CVSS v3.1 Base Score:** 7.5 (e.g. `AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)

---

## Fix / Mitigation

- Users should upgrade to versions including commit `25e47f8` (or later).
- The patch bounds input lengths before copying into the stack buffer in `parse_rfraw()`.
- For upstream builds, ensure input from untrusted sources is sanitized, and run inside restricted sandbox if possible.

---


## References

- GitHub Issue: [merbanan/rtl_433 #3375](https://github.com/merbanan/rtl_433/issues/3375)  
- Commit fixing overflow: [25e47f8](https://github.com/dd32/rtl_433/commit/25e47f8932f0401392ef1d3c8cc9ed5595bc894a)
- Tool and project: [rtl_433](https://github.com/merbanan/rtl_433)  

