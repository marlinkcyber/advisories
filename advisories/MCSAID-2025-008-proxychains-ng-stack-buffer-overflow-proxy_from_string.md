# proxychains-ng: Stack-based buffer overflow in `proxy_from_string()` (src/libproxychains.c)

- **Advisory ID:** MCSAID-2025-008
- **CVE ID:** *(Pending)*
- **Product:** [proxychains-ng](https://github.com/rofl0r/proxychains-ng)
- **Reported:** 2025-10-18.
- **Published:** 2025-10-20.
- **Fixed:** commit [cc005b7132811c9149e77b5e33cff359fc95512e](https://github.com/httpsgithu/proxychains-ng/commit/cc005b7132811c9149e77b5e33cff359fc95512e)
- **Severity:** High (Memory corruption / crash)
- **CWE:** [CWE-120: Buffer Copy without Checking Size of Input (Classic Buffer Overflow)](https://cwe.mitre.org/data/definitions/120.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

A stack-based buffer overflow is present in `proxychains-ng` in the function `proxy_from_string()` (file `src/libproxychains.c`). A missing bounds check allows HTTP proxy username and/or password fields in the configuration to exceed the 256-byte local buffers, enabling overwrites of stack data when parsing configs. This can lead to crashes (Denial of Service) and - depending on environment and exploitability - possible memory corruption leading to code execution.

---

## Affected Versions

| Version                                       | Status                    |
| --------------------------------------------- | ------------------------- |
| v4.17 (latest release at time of reporting)   | Vulnerable |
| Git master prior to commit `cc005b7`          | Vulnerable |
| Including and after commit `cc005b7132811c9…` | Patched  |

---

## Technical Details

In `proxy_from_string()` the code previously performed a bounds check only for SOCKS5 proxy types while parsing username (`u`) and password (`p`) lengths (`ul` and `pl`). The original check was effectively:

```c
/* original logic — only checked for SOCKS5 */
if (proxytype == RS_PT_SOCKS5 && (ul > 255 || pl > 255))
    return 0;
```

When parsing HTTP proxy entries the `proxytype == RS_PT_SOCKS5` condition was false and the length check was skipped. Subsequent `memcpy()` calls copied `ul`/`pl` bytes into 256-byte local buffers `user_buf`/`pass_buf` without a prior unconditional size check:

```c
/* vulnerable copy (user_buf and pass_buf are 256 bytes) */
memcpy(user_buf, u, ul);
memcpy(pass_buf, p, pl);
```

Because `ul` or `pl` may be larger than 255, an attacker-controlled or maliciously-crafted config file (or otherwise-controlled input) can cause a stack overflow. The upstream patch removes the proxy-type condition and enforces the length check unconditionally:

```c
/* patched logic */
if (ul > 255 || pl > 255)
    return 0;
```

This prevents copying more than the intended buffer size. The fix is available in commit `cc005b7132811c9149e77b5e33cff359fc95512e`.

Full ASAN output:
```
$ LD_PRELOAD="$(gcc -print-file-name=libasan.so)" ./proxychains4 -f ../proxychains-ng/poc_config_minimal.conf /bin/true
[proxychains] config file found: ../proxychains-ng/poc_config_minimal.conf
[proxychains] preloading ./libproxychains4.so
=================================================================
==846625==ERROR: AddressSanitizer: stack-buffer-underflow on address 0x7a6c09700000 at pc 0x7a6c0b6a1a6a bp 0x7ffe8a7b83f0 sp 0x7ffe8a7b7b68
READ of size 5 at 0x7a6c09700000 thread T0
    #0 0x7a6c0b6a1a69 in printf_common ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors_format.inc:563
    #1 0x7a6c0b6ce5f6 in vsnprintf ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:1652
    #2 0x7a6c0b6d08b6 in __snprintf_chk ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:1728
    #3 0x55888e2bf1a6 in snprintf /usr/include/x86_64-linux-gnu/bits/stdio2.h:54
    #4 0x55888e2bf1a6 in main src/main.c:154
    #5 0x7a6c0b22a1c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #6 0x7a6c0b22a28a in __libc_start_main_impl ../csu/libc-start.c:360
    #7 0x55888e2be3e4 in _start (/htp/proxychains/proxychains-ng-4.17-main/proxychains4+0x23e4) (BuildId: 9eb84dc99b231e9e4e6a5509ad4032e767c37c20)

Address 0x7a6c09700000 is located in stack of thread T0 at offset 0 in frame
    #0 0x55888e2bea41 in main src/main.c:68

  This frame has 3 object(s):
    [32, 64) 'dli' (line 116)
    [96, 352) 'buf' (line 70)
    [416, 672) 'pbuf' (line 71)
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-underflow ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors_format.inc:563 in printf_common
Shadow bytes around the buggy address:
  0x7a6c096ffd80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7a6c096ffe00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7a6c096ffe80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7a6c096fff00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7a6c096fff80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x7a6c09700000:[f1]f1 f1 f1 00 00 00 00 f2 f2 f2 f2 00 00 00 00
  0x7a6c09700080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7a6c09700100: 00 00 00 00 00 00 00 00 00 00 00 00 f2 f2 f2 f2
  0x7a6c09700180: f2 f2 f2 f2 00 00 00 00 00 00 00 00 00 00 00 00
  0x7a6c09700200: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7a6c09700280: 00 00 00 00 f3 f3 f3 f3 f3 f3 f3 f3 00 00 00 00
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
==846625==ABORTING
```

---

## Proof / Test

Repro steps and PoC are described in the issue thread.

Example (as reported in the issue):

```sh
LD_PRELOAD="$(gcc -print-file-name=libasan.so)" ./proxychains4 -f poc_config_minimal.conf /bin/true
# ASan reports stack-buffer-underflow/overflow in vulnerable builds
```

---

## Impact

* **Primary impact:** Denial of Service (crash) due to stack memory corruption.
* **Secondary impact:** Potential memory corruption that may be leveraged for code execution in some environments (depends on compiler, mitigations, and calling context).
* **Attack Vector:** Local (untrusted config file) or any attack surface that allows an attacker to supply a crafted proxy configuration (for example, by supplying config files to a user or compromising configuration distribution).
* **Privileges Required:** None (the parsing happens in-process when proxychains reads its configuration).
* **User Interaction:** Required only to cause proxychains to read a supplied malicious configuration file (no interactive user approval required once config is read).
* **Suggested CVSS v3.1 Base Score (example):** 7.5 (High) — e.g. `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` (adjust as appropriate for your environment).

---

## Fix / Mitigation

**Upgrading / Applying the Fix**

1. **Upgrade** to a version including commit `cc005b7132811c9149e77b5e33cff359fc95512e` or later. The commit implements the unconditional bounds check preventing buffer overflow.

2. If you maintain a packaged distribution and cannot immediately upgrade, **backport** the patch by applying the single-line change in `src/libproxychains.c`:

```diff
- if(proxytype == RS_PT_SOCKS5 && (ul > 255 || pl > 255))
+ if(ul > 255 || pl > 255)
     return 0;
```

Then rebuild/install.

---

## References

* [Stack Buffer Overflow in proxy_from_string() in libproxychains.c:254 · Issue #606](https://github.com/rofl0r/proxychains-ng/issues/606)
* Commit fixing the issue: [`cc005b7132811c9149e77b5e33cff359fc95512e` — “fix potential buffer overflow in config file parsing”](https://github.com/httpsgithu/proxychains-ng/commit/cc005b7132811c9149e77b5e33cff359fc95512e.patch)


