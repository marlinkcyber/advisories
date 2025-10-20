# scrcpy: Global-Buffer Overflow in `sc_read32be` via `sc_device_msg_deserialize` / `process_msgs`

- **Advisory ID:** MCSAID-2025-003
- **CVE ID:** *(pending)*
- **Product:** [scrcpy](https://github.com/Genymobile/scrcpy)
- **Reported:** 2025-10-09
- **Published:** 2025-10-09
- **Fixed:** Fixed in commit [3e40b2473772cea3a23d4932088fd0bc4cc0f52c](https://github.com/Genymobile/scrcpy/commit/3e40b2473772cea3a23d4932088fd0bc4cc0f52c)
- **Severity:** High (Memory corruption / crash)
- **CWE:** [CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119.html) (or global buffer overflow)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

A global buffer overflow vulnerability has been discovered in `scrcpy` in the function `sc_read32be`, invoked via `sc_device_msg_deserialize()` and `process_msgs()`.

When processing crafted messages, the code may read beyond the bounds of a global buffer, leading to memory corruption or crashes. Under AddressSanitizer (ASan), the flaw is reproducible, showing a “global-buffer-overflow” error.

---

## Affected Versions

| Version / Commit  | Status                                |
| ----------------- | ------------------------------------- |
| 3.3.3 and earlier | Vulnerable                            |
| prior to commit 3e40b2473772cea3a23d4932088fd0bc4cc0f52c  | Vulnerable             |
| commit 3e40b2473772cea3a23d4932088fd0bc4cc0f52c applied  | Not vulnerable |

The issue is present in stable release 3.3.3 and also in git master until 3e40b2473772cea3a23d4932088fd0bc4cc0f52c patch.

---

## Technical Details

In `sc_device_msg_deserialize()` (in `device_msg.c`, around line 24), the code reads a 32-bit big-endian integer via `sc_read32be` without sufficient bounds checking. Because the buffer is a global array in `receiver.c` (variable `buf`), a malformed payload may lead to reading past the end of that buffer, triggering a global-buffer-overflow.

Under ASan, the overflow was detected with a stack trace similar to:

```
AddressSanitizer: global-buffer-overflow on address ... in sc_read32be ../app/src/util/binary.h:56  
#1 sc_device_msg_deserialize ../app/src/device_msg.c:24  
#2 process_msgs ../app/src/receiver.c:161  
...
```

The overflow arises because the code logic uses an `if (size < len - 5)` check; the proposer of the issue suggests this should be inverted to `if (size > len - 5)` (rejecting too-large sizes) and handling of zero, negative, or overflow cases.

In debug builds, an assertion `head <= len` may also fail, causing an abort.

Because this is a global buffer overflow, it may corrupt adjacent global data, potentially impacting control flow, though only crash/DoS is demonstrated so far.

Full Asan Output:
```
$ ./run_scrcpy_poc2.sh device_msg_crash_0.bin
scrcpy 3.3.3 <https://github.com/Genymobile/scrcpy>
INFO: No video mirroring, SDK mouse disabled
INFO: ADB device found:
INFO:     -->   (usb)  POC_SERIAL                      device
ERROR: Received unexpected HID output message
=================================================================
==1465725==ERROR: AddressSanitizer: global-buffer-overflow on address 0x56a187db0aa0 at pc 0x56a187cb70a1 bp 0x777d123e90c0 sp 0x777d123e90b0
READ of size 1 at 0x56a187db0aa0 thread T4
    #0 0x56a187cb70a0 in sc_read32be ../app/src/util/binary.h:56
    #1 0x56a187cb71d2 in sc_device_msg_deserialize ../app/src/device_msg.c:24
    #2 0x56a187cc9a26 in process_msgs ../app/src/receiver.c:161
    #3 0x56a187cc9c01 in run_receiver ../app/src/receiver.c:200
    #4 0x777d21766365  (/lib/x86_64-linux-gnu/libSDL2-2.0.so.0+0x142365) (BuildId: 832936b3309cbf275a4c7cb4f642c4fea4cbf33f)
    #5 0x777d2445ea41 in asan_thread_start ../../../../src/libsanitizer/asan/asan_interceptors.cpp:234
    #6 0x777d2149caa3 in start_thread nptl/pthread_create.c:447
    #7 0x777d21529c6b in clone3 ../sysdeps/unix/sysv/linux/x86_64/clone3.S:78

0x56a187db0aa0 is located 32 bytes before global variable 'scrcpy' defined in '../app/src/scrcpy.c:382:26' (0x56a187db0ac0) of size 2200
0x56a187db0aa0 is located 0 bytes after global variable 'buf' defined in '../app/src/receiver.c:184:20' (0x56a187d70aa0) of size 262144
SUMMARY: AddressSanitizer: global-buffer-overflow ../app/src/util/binary.h:56 in sc_read32be
Shadow bytes around the buggy address:
  0x56a187db0800: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x56a187db0880: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x56a187db0900: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x56a187db0980: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x56a187db0a00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x56a187db0a80: 00 00 00 00[f9]f9 f9 f9 00 00 00 00 00 00 00 00
  0x56a187db0b00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x56a187db0b80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x56a187db0c00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x56a187db0c80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x56a187db0d00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
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
Thread T4 created by T0 here:
    #0 0x777d244f51f9 in pthread_create ../../../../src/libsanitizer/asan/asan_interceptors.cpp:245
    #1 0x777d216bb3b0  (/lib/x86_64-linux-gnu/libSDL2-2.0.so.0+0x973b0) (BuildId: 832936b3309cbf275a4c7cb4f642c4fea4cbf33f)
    #2 0x56a187cee7c9 in sc_thread_create ../app/src/util/thread.c:20
    #3 0x56a187cc9d37 in sc_receiver_start ../app/src/receiver.c:223
    #4 0x56a187cb36e7 in sc_controller_start ../app/src/controller.c:197
    #5 0x56a187cd2846 in scrcpy ../app/src/scrcpy.c:792
    #6 0x56a187c9a2c9 in main_scrcpy ../app/src/main.c:92
    #7 0x56a187c9a3f6 in main ../app/src/main.c:109
    #8 0x777d2142a1c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #9 0x777d2142a28a in __libc_start_main_impl ../csu/libc-start.c:360
    #10 0x56a187c99dc4 in _start (/htp/strcpy/scrcpy/buildrelease/app/scrcpy+0x21dc4) (BuildId: 58e69225e2793836157c6e4496cd9b3c0205ec23)

==1465725==ABORTING
```

---

## Impact

* **Impact:** Denial of Service (crash), memory corruption; potential for further exploitation depending on environment
* **Attack Vector:** Via processing of a malicious device message (e.g. HID / control channel)
* **Privileges Required:** None (scrcpy client is already running and receiving messages)
* **User Interaction:** n/a (automatic handling of incoming messages)
* **Suggested CVSS v3.1 Base Score:** 7.5 (e.g. `AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`) — *to be calibrated*

Because the vulnerability is in message deserialization, a remote or local attacker able to inject device messages (e.g. via a compromised device or proxy) could trigger the overflow.

---

## Fix / Mitigation

* Users should upgrade to versions including commit `3e40b2473772cea3a23d4932088fd0bc4cc0f52c` (or later).
* Run scrcpy in restricted environments where possible (e.g. sandboxing, SELinux, AppArmor) to limit impact of memory corruption.

---

## References

* [GitHub Issue: Genymobile/scrcpy #6415](https://github.com/Genymobile/scrcpy/issues/6415)
* Fixed commit: [3e40b2473772cea3a23d4932088fd0bc4cc0f52c](https://github.com/Genymobile/scrcpy/commit/3e40b2473772cea3a23d4932088fd0bc4cc0f52c)
---

