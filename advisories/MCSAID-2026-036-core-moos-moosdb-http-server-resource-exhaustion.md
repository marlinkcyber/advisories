# MOOS core-moos: MOOSDB HTTP Server Resource Exhaustion

- **Advisory ID:** MCSAID-2026-036
- **CVE ID:** [CVE-2026-85450](https://www.cve.org/CVERecord?id=CVE-2026-85450)
- **Published:** 2026-09-01
- **Severity:** High (CVSS 7.5 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **CVSS 4.0:** 8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Allocation of Resources Without Limits or Throttling
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #79](https://github.com/themoos/core-moos/pull/79) (not merged)
- **Software:** [MOOS core-moos](https://github.com/themoos/core-moos)
- **CWE:** [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

The HTTP server allocates one OS thread per accepted socket with no cap, and reads request lines one byte at a time with no maximum length and no deadline. 200 idle sockets took the MOOSDB from 12 to 212 threads, and one connection that never sends a carriage return grows the process heap without bound.

---

## Affected Versions

| Version | Status |
|---------|--------|
| core-moos <= 10.4.0 | Vulnerable |

Tested against: core-moos `v10.4.0-49-gec9c77c` (commit `ec9c77c68fcbdef8f5e4c60fe243acd223433f0c`), latest master; and MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master, which bundles the same code.

---

## Impact

Thread, descriptor, CPU and heap exhaustion of the MOOSDB process - i.e. of the
whole mission bus, since the HTTP server lives inside it.

---

## Exploitation

Any network client that can reach an enabled HTTP listener.

Preconditions:

* `WEBSERVERPORT` set. Off by default.

---

## Details

### Affected code

Each affected file is listed twice: first at its path in **core-moos** git master (commit `ec9c77c`), which is where a fix has to land, then at its path inside the copy bundled in MOOS-IvP under `MOOS_Jul2724/MOOSCore`. The two copies are byte-identical unless stated otherwise.

* **`Core/libMOOS/DB/MOOSDBHTTPServer.cpp`** - lines 124-163: one CHTTPConnection and one thread per accepted socket, with no cap, no per-IP limit, and reaping only of connections that already completed
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/DB/MOOSDBHTTPServer.cpp`** - lines 124-163: one CHTTPConnection and one thread per accepted socket, with no cap, no per-IP limit, and reaping only of connections that already completed
* **`Core/libMOOS/DB/HTTPConnection.cpp`** - lines 234-270: ReadLine(): a blocking one-byte recv in a loop, appending to a std::string until '\r', with no maximum length and no deadline
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/DB/HTTPConnection.cpp`** - lines 234-270: ReadLine(): a blocking one-byte recv in a loop, appending to a std::string until '\r', with no maximum length and no deadline

### Root cause

Every accepted socket gets its own OS thread and lives until the client
cooperates.  `ReadLine` reads one byte at a time with no size limit and no
timeout, so a client that never sends a carriage return keeps a thread and a
file descriptor forever while growing a `std::string` without bound.

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

Yes - reproduced against standalone core-moos `v10.4.0-49-gec9c77c` (commit `ec9c77c`), default production build (`cmake .. && make`, Release -O2, hardened PIE), and against the copy bundled in MOOS-IvP.

### Steps and results

* 200 sockets, one byte each, no CR: MOOSDB went from 12 threads / 12 fds to
  **212 threads / 211 fds**, one per idle connection, and they stayed.
* One connection with no CR at all: 26.8 MB pushed into a single request line
  grew MOOSDB's RSS from 6156 kB to 31520 kB, unbounded and still climbing.
  (The byte-at-a-time read caps the rate at a few MB/s, not the total.)

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #79](https://github.com/themoos/core-moos/pull/79)
- Proposed fix commit: [dfef92b3bc31](https://github.com/themoos/core-moos/commit/dfef92b3bc31886bc47e4d680aef583b78cb8d72)

### Recommended fix

Use a bounded worker pool or event-driven I/O, cap concurrent connections
globally and per source address, impose maximum request-line and header sizes
(8 KB is generous), and apply both an idle timeout and an absolute request
deadline.  Read in buffered chunks rather than one byte per syscall.

---

## Recommendations

- Apply the proposed fix from [Pull Request #79](https://github.com/themoos/core-moos/pull/79) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-01 – CVE-2026-85450 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85450](https://www.cve.org/CVERecord?id=CVE-2026-85450)
- VulnCheck advisory: [MOOS core-moos through 10.4.0 MOOSDB HTTP Server Resource Exhaustion](https://www.vulncheck.com/advisories/moos-core-moos-through-10.4.0-moosdb-http-server-resource-exhaustion)
- Upstream pull request: [Pull Request #79](https://github.com/themoos/core-moos/pull/79)
- Proposed fix commit: [dfef92b3bc31886bc47e4d680aef583b78cb8d72](https://github.com/themoos/core-moos/commit/dfef92b3bc31886bc47e4d680aef583b78cb8d72)
- Marlink Cyber Security Advisory: [MCSAID-2026-036](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-036-core-moos-moosdb-http-server-resource-exhaustion.md)
- Software: [MOOS core-moos](https://github.com/themoos/core-moos)
