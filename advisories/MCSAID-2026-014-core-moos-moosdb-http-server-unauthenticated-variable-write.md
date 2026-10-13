# MOOS core-moos: MOOSDB HTTP Server Unauthenticated Variable Write

- **Advisory ID:** MCSAID-2026-014
- **CVE ID:** [CVE-2026-85428](https://www.cve.org/CVERecord?id=CVE-2026-85428)
- **Published:** 2026-09-01
- **Severity:** Critical (CVSS 9.8 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **CVSS 4.0:** 9.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Missing Authentication for Critical Function
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #77](https://github.com/themoos/core-moos/pull/77) (not merged)
- **Software:** [MOOS core-moos](https://github.com/themoos/core-moos)
- **CWE:** [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

When the optional HTTP server is enabled it binds all interfaces and maps URL query parameters straight onto `Notify`. `GET /ANY_VARIABLE?NewValue=x` - one request line, no headers, no token - creates or overwrites any MOOS variable. Because it is a plain GET with no CSRF defence, a web page an operator visits can drive it from the operator's browser.

---

## Affected Versions

| Version | Status |
|---------|--------|
| core-moos <= 10.4.0 | Vulnerable |

Tested against: core-moos `v10.4.0-49-gec9c77c` (commit `ec9c77c68fcbdef8f5e4c60fe243acd223433f0c`), latest master; and MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master, which bundles the same code.

---

## Impact

Creation and overwrite of arbitrary MOOS variables - including helm, override
and mission commands - by any network peer, and browser-assisted attack into an
otherwise unreachable autonomy network.

---

## Exploitation

Any network client that can reach the HTTP port, or any web page an operator with network access happens to open.

Preconditions:

* `WEBSERVERPORT` set in the mission file or `--webserver_port` on the command line. Off by default; no checked-in mission enables it.

---

## Details

### Affected code

Each affected file is listed twice: first at its path in **core-moos** git master (commit `ec9c77c`), which is where a fix has to land, then at its path inside the copy bundled in MOOS-IvP under `MOOS_Jul2724/MOOSCore`. The two copies are byte-identical unless stated otherwise.

* **`Core/libMOOS/DB/MOOSDB.cpp`** - lines 318-326: WEBSERVERPORT (or --webserver_port) > 0 starts CMOOSDBHTTPServer
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/DB/MOOSDB.cpp`** - lines 318-326: WEBSERVERPORT (or --webserver_port) > 0 starts CMOOSDBHTTPServer
* **`Core/libMOOS/DB/MOOSDBHTTPServer.cpp`** - lines 100-135: the listen socket is created with no bind-address restriction, i.e. INADDR_ANY
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/DB/MOOSDBHTTPServer.cpp`** - lines 100-135: the listen socket is created with no bind-address restriction, i.e. INADDR_ANY
* **`Core/libMOOS/DB/HTTPConnection.cpp`** - lines 160-213: ReadRequest(): HandlePoke(sFormContents) is called from the request line, before any header is read
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/DB/HTTPConnection.cpp`** - lines 160-213: ReadRequest(): HandlePoke(sFormContents) is called from the request line, before any header is read
* **`Core/libMOOS/DB/HTTPConnection.cpp`** - lines 305-351: HandlePoke(): m_pMOOSComms->Notify(sVar, ...); the DoPoke token is required only when no focus variable is present in the path
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/DB/HTTPConnection.cpp`** - lines 305-351: HandlePoke(): m_pMOOSComms->Notify(sVar, ...); the DoPoke token is required only when no focus variable is present in the path

### Root cause

When enabled, the HTTP server binds every interface and maps URL query
parameters directly onto `CMOOSCommClient::Notify`.  `GET /ANY_VARIABLE?NewValue=x`
is enough: the focus-variable form skips the `DoPoke` confirmation token
entirely.  Because it is a plain `GET` with no custom headers and no CSRF token,
a malicious page can drive it from an operator's browser with a single `<img>`
tag.  The same server exposes the whole database for reading.

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

With `WEBSERVERPORT` set:

* `ss -ltnp` shows `LISTEN 0.0.0.0:<port> ... users:(("MOOSDB",...))`.
* `GET /DEPLOY?NewValue=true`, `GET /MOOS_MANUAL_OVERRIDE?NewValue=false`,
  `GET /RETURN?NewValue=false`, `GET /DESIRED_SPEED?NewValue=9.5` - each a
  single request line with no headers - all landed in the database with
  `src='DBWebServer'`.
* `GET /?VariableToPoke=MISSION_ABORT&NewValue=NOW&DoPoke=1` also worked.
* `GET /` listed live variables (`DEPLOY`, `DESIRED_SPEED`, `DB_CLIENTS`,
  `DB_TIME`) without authentication.

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #77](https://github.com/themoos/core-moos/pull/77)
- Proposed fix commit: [7e3aecdbf5fe](https://github.com/themoos/core-moos/commit/7e3aecdbf5fe47980ea9399340c77940991a6fa5)

### Recommended fix

Make the web interface read-only by default and bind it to loopback.  If write
access is wanted: require TLS and authentication, accept pokes only over `POST`
with an anti-CSRF token, enforce a per-variable allow-list, and reject requests
whose `Origin`/`Referer` is not expected.  Also stop acting on the request line
before the headers have been read - that is what makes the one-line attack
possible.

---

## Recommendations

- Apply the proposed fix from [Pull Request #77](https://github.com/themoos/core-moos/pull/77) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-01 – CVE-2026-85428 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85428](https://www.cve.org/CVERecord?id=CVE-2026-85428)
- VulnCheck advisory: [MOOS core-moos through 10.4.0 MOOSDB HTTP Server Unauthenticated Variable Write](https://www.vulncheck.com/advisories/moos-core-moos-through-10.4.0-moosdb-http-server-unauthenticated-variable-write)
- Upstream pull request: [Pull Request #77](https://github.com/themoos/core-moos/pull/77)
- Proposed fix commit: [7e3aecdbf5fe47980ea9399340c77940991a6fa5](https://github.com/themoos/core-moos/commit/7e3aecdbf5fe47980ea9399340c77940991a6fa5)
- Marlink Cyber Security Advisory: [MCSAID-2026-014](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-014-core-moos-moosdb-http-server-unauthenticated-variable-write.md)
- Software: [MOOS core-moos](https://github.com/themoos/core-moos)
