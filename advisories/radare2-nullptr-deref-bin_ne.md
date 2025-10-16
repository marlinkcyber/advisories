# radare2: NULL Pointer Dereference in `info()` (bin_ne.c) Leads to Denial of Service

- **CVE ID:** *(Pending MITRE Assignment)*
- **Reported:** 2025-10-07
- **Published:** 2025-10-08
- **Fixed:** 2025-10-08
- **Severity:** Low (Denial of Service)
- **CWE:** [CWE-476: NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

A NULL pointer dereference vulnerability was found in the `info()` function of `bin_ne.c` in `radare2`. A crafted binary input can trigger a segmentation fault, leading to a **denial of service** when the tool processes malformed data.

To exploit vulnerability, someone must open a crafted binary file. This could impact automated binary analysis environments or pipelines that rely on radare2.

---

## Affected Versions

| Version | Status |
|----------|---------|
| 6.0.5 (commit 0984df0b5d5d4b8f4b66251a6c762f5d69acb088) | Vulnerable |
| Later commits (Fixed in [6c5df3f8570d4f0c](https://github.com/radareorg/radare2/commit/6c5df3f8570d4f0c360681c08241ad8af3b919fd)) | Fixed |

**Patched in:** [Commit referencing fix on GitHub](https://github.com/radareorg/radare2/issues/24660)

---

## Technical Details

When handling certain malformed NE binaries, the `info()` function dereferences a NULL pointer during string handling operations (`strdup`, `strlen`).

This leads to a crash confirmed under AddressSanitizer.

```
$ binr/radare2/radare2 ../crash_002.bin
ERROR: variable 'asm.cmtright' not found
/htp/radare2/radare2/libr/..//libr/bin/p/bin_ne.c:83:11: runtime error: null pointer passed as argument 1, which is declared to never be null
AddressSanitizer:DEADLYSIGNAL
=================================================================
==2047918==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x73115bf19d06 bp 0x7fff86df1770 sp 0x7fff86df0ef8 T0)
==2047918==The signal is caused by a READ memory access.
==2047918==Hint: address points to the zero page.
    #0 0x73115bf19d06 in __sanitizer::internal_strlen(char const*) ../../../../src/libsanitizer/sanitizer_common/sanitizer_libc.cpp:176
    #1 0x73115bef72f6 in strdup ../../../../src/libsanitizer/asan/asan_interceptors.cpp:574
    #2 0x73114fc73182 in info /htp/radare2/radare2/libr/..//libr/bin/p/bin_ne.c:83
    #3 0x73114f8d7599 in r_bin_object_set_items /htp/radare2/radare2/libr/bin/bobj.c:359
    #4 0x73114f8d4dcf in r_bin_object_new /htp/radare2/radare2/libr/bin/bobj.c:234
    #5 0x73114f8c604b in r_bin_file_new_from_buffer /htp/radare2/radare2/libr/bin/bfile.c:832
    #6 0x73114f872a5d in r_bin_open_buf /htp/radare2/radare2/libr/bin/bin.c:307
    #7 0x73114f873a31 in r_bin_open_io /htp/radare2/radare2/libr/bin/bin.c:372
    #8 0x7311572301fd in r_core_file_load_for_io_plugin /htp/radare2/radare2/libr/core/cfile.c:482
    #9 0x7311572334e9 in r_core_bin_load /htp/radare2/radare2/libr/core/cfile.c:737
    #10 0x73115a90a411 in binload /htp/radare2/radare2/libr/main/radare2.c:582
    #11 0x73115a916cf5 in r_main_radare2 /htp/radare2/radare2/libr/main/radare2.c:1552
    #12 0x63d3dfec0ecb in main /htp/radare2/radare2/binr/radare2/radare2.c:119
    #13 0x731159c2a1c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #14 0x731159c2a28a in __libc_start_main_impl ../csu/libc-start.c:360
    #15 0x63d3dfec03c4 in _start (/htp/radare2/radare2/binr/radare2/radare2+0x23c4) (BuildId: 99cbb694fbce63e8ffc91cf194fc060daf3c1a4b)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV ../../../../src/libsanitizer/sanitizer_common/sanitizer_libc.cpp:176 in __sanitizer::internal_strlen(char const*)
==2047918==ABORTING
```

## Test

$ binr/radare2/radare2 ../crash_002.bin

[crash_002.zip](https://github.com/user-attachments/files/22732782/crash_002.zip)


---

## Impact

- **Impact:** Denial of Service (crash)
- **Attack Vector:** Local / crafted input
- **Privileges Required:** None
- **User Interaction:** Required

**CVSS v3.1 Base Score:** 5.5
Vector: `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H`

---

## Fix

The vulnerability was resolved by adding a null check in `bin_ne.c` before accessing fields in `info()`.
See [patch discussion and confirmation](https://github.com/radareorg/radare2/issues/24660).

Fixed in commit [6c5df3f8570d4f0c](https://github.com/radareorg/radare2/commit/6c5df3f8570d4f0c360681c08241ad8af3b919fd).

---

## References

- [GitHub Issue #24660](https://github.com/radareorg/radare2/issues/24660)
- [CWE-476: NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)

