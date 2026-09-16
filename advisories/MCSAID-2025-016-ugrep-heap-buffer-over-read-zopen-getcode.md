# ugrep: Heap Buffer Over-read in `getcode()` (zopen.c) during .Z decompression

- **Advisory ID:** MCSAID-2025-016
- **CVE ID:** [CVE-2025-15614](https://www.cve.org/CVERecord?id=CVE-2025-15614)
- **Reported:** 2025-10-15
- **Published:** 2026-09-16
- **Severity:** Low (CVSS 3.3 – AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L)
- **Vulnerability type:** Heap buffer over-read, Denial of Service (DoS)
- **Current state:** Fix released by vendor in ugrep 7.6.0
- **Exploitation:** Easy, not seen in the wild
- **Software:** [ugrep](https://github.com/Genivia/ugrep)
- **CWE:** [CWE-125: Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

ugrep bundles a third-party `zopen.c` implementation (the BSD/NetBSD `compress`/LZW decompressor) to support searching inside `.Z` archives with the `-z` (`--decompress`) option. When decompressing a crafted `.Z` file, `getcode()` reads one byte past the end of the `zs_gbuf[]` buffer inside the heap-allocated `struct s_zstate`.

Because `zs_gbuf[]` is the last member of the state structure, the read goes past the end of the `calloc()`-ed allocation, which AddressSanitizer reports as a heap-buffer-overflow (read). On a normal build the out-of-bounds byte is discarded by the decoder logic, but the read can fault when the allocation ends on a page boundary, terminating the process.

As the code originates from the widely redistributed BSD `zopen.c`, other programs embedding the same file are likely affected as well.

---

## Affected Versions

| Version | Status |
|---------|--------|
| ugrep <= 7.5 (and git master up to `d624720b3cb4aa84b0f9cede51f90f9cc42473d8`) | Vulnerable |
| ugrep 7.6.0 and later | Fixed |

Only builds with `.Z` (LZW `compress`) decompression support and invocations using `-z`/`--decompress` are affected.

---

## Impact

Processing an untrusted `.Z` file with `ugrep -z` causes a one-byte heap out-of-bounds read. The primary impact is a potential process crash (denial of service) when searching attacker-supplied archives, e.g. in automated scanning, indexing or CI pipelines that run ugrep over untrusted input. There is no evidence that the over-read leaks data to the output: the maintainer verified that the `gcode` values returned by `getcode()` are unchanged by the fix, so the byte never influences decompressed output.

---

## Exploitation

Exploitation only requires convincing a user or automated process to search a crafted `.Z` file with decompression enabled. Arbitrary code execution is not considered feasible; the impact is limited to an out-of-bounds read and possible crash.

---

## Details

### Root cause

In `getcode()` (`src/zopen.c`), the high-order bits of the next LZW code are assembled with:

```c
/* High order bits. */
gcode |= (*bp & rmask[bits]) << r_off;
```

`bp` walks the `zs_gbuf[]` buffer (`char_type zs_gbuf[BITS]`) held in the decompressor state. For certain bit offsets near the end of the buffer, `bp` is advanced to `gbuf + sizeof(gbuf)` and dereferenced anyway, reading one byte past `zs_gbuf[]` — and, since the buffer is the final member of the heap-allocated `struct s_zstate`, past the end of the allocation made in `z_open()`.

This is a logic error inherited from the original BSD implementation; the value read is not used in a way that affects the decompressed stream.

### Proof of Concept

```bash
unzip crash-11.zip
src/ugrep -z x 11-0_full.Z
```

The PoC archive is attached to the upstream issue: [crash-11.zip](https://github.com/user-attachments/files/22917614/crash-11.zip)

### ASan output

```
=================================================================
==1423354==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x789f047ff020 at pc 0x644e430ed148 bp 0x789f01ffe8f0 sp 0x789f01ffe8e0
READ of size 1 at 0x789f047ff020 thread T1
    #0 0x644e430ed147 in getcode /htp/ugrep/ugrep/src/zopen.c:673
    #1 0x644e430ee401 in z_read /htp/ugrep/ugrep/src/zopen.c:557
    #2 0x644e42feb503 in zstreambuf::next(unsigned char*, unsigned long)
    #3 0x644e43054a77 in Zthread::decompress()
    #4 0x644e42fd35b0 in std::thread::_State_impl<...>::_M_run()
    #5 0x789f056ecdb3  (/lib/x86_64-linux-gnu/libstdc++.so.6+0xecdb3)
    #6 0x789f05a5ea41 in asan_thread_start ../../../../src/libsanitizer/asan/asan_interceptors.cpp:234
    #7 0x789f0529caa3 in start_thread nptl/pthread_create.c:447
    #8 0x789f05329c6b in clone3 ../sysdeps/unix/sysv/linux/x86_64/clone3.S:78

0x789f047ff020 is located 0 bytes after 690208-byte region [0x789f04756800,0x789f047ff020)
allocated by thread T0 here:
    #0 0x789f05afd340 in calloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:77
    #1 0x644e430eec3c in z_open /htp/ugrep/ugrep/src/zopen.c:750
    #2 0x644e4300f792 in zstreambuf::open(char const*, _IO_FILE*)
    #3 0x644e43025cd4 in Zthread::start(unsigned long, char const*, _IO_FILE*, char const*)
    #4 0x644e430495e8 in Grep::open_file(char const*, char const*)
    #5 0x644e42f9f545 in Grep::search(char const*, unsigned short) /htp/ugrep/ugrep/src/ugrep.cpp:10426
    #6 0x644e42f9ea47 in Grep::ugrep() /htp/ugrep/ugrep/src/ugrep.cpp:9149
    #7 0x644e42fc5d03 in ugrep() /htp/ugrep/ugrep/src/ugrep.cpp:8974
    #8 0x644e42fc7851 in main /htp/ugrep/ugrep/src/ugrep.cpp:4715

SUMMARY: AddressSanitizer: heap-buffer-overflow /htp/ugrep/ugrep/src/zopen.c:673 in getcode
==1423354==ABORTING
```

Build and test platform: Ubuntu 24.04.3, ugrep built with `-fsanitize=address`.

---

## Mitigations

The vendor fix bounds-checks the pointer before dereferencing it (`src/zopen.c`):

```c
/* High order bits. fixed by RvE to avoid reading a byte past gbuf[] */
if (bp < gbuf + sizeof(gbuf))
  gcode |= (*bp & rmask[bits]) << r_off;
```

- Upstream fix: [c12849a11264e2c81c860bf78ee9039772f307a4](https://github.com/Genivia/ugrep/commit/c12849a11264e2c81c860bf78ee9039772f307a4)
- Released in [ugrep 7.6.0](https://github.com/Genivia/ugrep/releases/tag/v7.6.0)

---

## Recommendations

- Upgrade to ugrep 7.6.0 or later.
- If an upgrade is not immediately possible, avoid `-z`/`--decompress` on untrusted `.Z` files, or build ugrep without `compress`/LZW support.
- Maintainers of other projects embedding the BSD `zopen.c` / `compress.c` decompressor should apply the same bounds check.

---

## Timeline

- 2025-10-15 – Vulnerability reported to the ugrep maintainers (GitHub issue #511)
- 2026-02-26 – Maintainer confirmed the root cause and published a patch
- 2026-02-26 – Fix committed upstream (`c12849a`)
- 2026-03-05 – ugrep 7.6.0 released with the fix
- 2026-09-16 – Public advisory released

---

## References

- GitHub Issue: [heap-buffer-overflow in getcode (src/zopen.c:673)](https://github.com/Genivia/ugrep/issues/511)
- Upstream fix commit: [c12849a](https://github.com/Genivia/ugrep/commit/c12849a11264e2c81c860bf78ee9039772f307a4)
- Release notes: [ugrep v7.6.0](https://github.com/Genivia/ugrep/releases/tag/v7.6.0)
- Marlink Cyber Security Advisory: [MCSAID-2025-016](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2025-016-ugrep-heap-buffer-over-read-zopen-getcode.md)
- Software: [ugrep](https://github.com/Genivia/ugrep)
