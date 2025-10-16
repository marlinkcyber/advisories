# radare2: NULL Pointer Dereference in `load()` (bin_dyldcache.c) Leads to Denial of Service

- **CVE ID:** *(Pending MITRE Assignment)*
- **Reported:** 2025-10-07
- **Published:** 2025-10-08
- **Fixed:** 2025-10-08
- **Severity:** Low (Denial of Service)
- **CWE:** [CWE-476: NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

A NULL pointer dereference vulnerability exists in `radare2` within the `load()` function of `bin_dyldcache.c`.
Processing a crafted file can cause a segmentation fault and crash the program.

To exploit vulnerability, someone must open a crafted binary file. This could impact automated binary analysis environments or pipelines that rely on radare2.

---

## Affected Versions

| Version | Status |
|----------|---------|
| 6.0.5 (commit 0984df0b5d5d4b8f4b66251a6c762f5d69acb088) | Vulnerable |
| Later commits | Fixed |

**Patched in:** [Commit referencing fix on GitHub](https://github.com/radareorg/radare2/issues/24661)

---

## Technical Details

The crash occurs when `load()` attempts to access a field through a NULL pointer of type `struct RIODesc`.
ASAN reports a segmentation fault at `bin_dyldcache.c:1159`.

```
$ ./poc crash_001.bin
/htp/radare2/radare2/libr/..//libr/bin/p/bin_dyldcache.c:1159:81: runtime error: member access within null pointer of type 'struct RIODesc'
AddressSanitizer:DEADLYSIGNAL
=================================================================
==2378621==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000030 (pc 0x7c95809ce8db bp 0x7ffca9cd3350 sp 0x7ffca9cd3300 T0)
==2378621==The signal is caused by a READ memory access.
==2378621==Hint: address points to the zero page.
    #0 0x7c95809ce8db in load /htp/radare2/radare2/libr/..//libr/bin/p/bin_dyldcache.c:1159
    #1 0x7c95808d4aa3 in r_bin_object_new /htp/radare2/radare2/libr/bin/bobj.c:219
    #2 0x7c95808c604b in r_bin_file_new_from_buffer /htp/radare2/radare2/libr/bin/bfile.c:832
    #3 0x7c9580872a5d in r_bin_open_buf /htp/radare2/radare2/libr/bin/bin.c:307
    #4 0x5e86d88b170f in fuzz_buffer (/htp/radare2/radare2/poc+0x170f) (BuildId: 617844968f9f200c1ab60a183109e999d0481ccf)
    #5 0x5e86d88b1993 in main (/htp/radare2/radare2/poc+0x1993) (BuildId: 617844968f9f200c1ab60a183109e999d0481ccf)
    #6 0x7c957d22a1c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #7 0x7c957d22a28a in __libc_start_main_impl ../csu/libc-start.c:360
    #8 0x5e86d88b13a4 in _start (/htp/radare2/radare2/poc+0x13a4) (BuildId: 617844968f9f200c1ab60a183109e999d0481ccf)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /htp/radare2/radare2/libr/..//libr/bin/p/bin_dyldcache.c:1159 in load
==2378621==ABORTING
```

## Test

```
$ ./poc crash_001.bin
```

[crash_001.zip](https://github.com/user-attachments/files/22733337/crash_001.zip)


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

The patch adds checks to ensure the pointer to `RIODesc` is valid before dereferencing it.
See the confirmed fix in the [GitHub issue](https://github.com/radareorg/radare2/issues/24661).

Fixed in commit [e37e15d10fd8a19](https://github.com/radareorg/radare2/commit/e37e15d10fd8a19c3e57b3d7735a2cfe0082ec79).

---

## References

- [GitHub Issue #24661](https://github.com/radareorg/radare2/issues/24661)
- [CWE-476: NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)


