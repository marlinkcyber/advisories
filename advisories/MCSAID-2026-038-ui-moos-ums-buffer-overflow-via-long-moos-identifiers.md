# MOOS ui-moos: uMS Buffer Overflow via Long MOOS Identifiers

- **Advisory ID:** MCSAID-2026-038
- **CVE ID:** [CVE-2026-85452](https://www.cve.org/CVERecord?id=CVE-2026-85452)
- **Published:** 2026-09-02
- **Severity:** High (CVSS 8.8 – CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **CVSS 4.0:** 8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Out-of-bounds Write
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #5](https://github.com/themoos/ui-moos/pull/5) (not merged)
- **Software:** [MOOS ui-moos](https://github.com/themoos/ui-moos)
- **CWE:** [CWE-787: Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

MOOS imposes no length limit on client names or variable names, and uMS formats them into fixed 1024-byte `static` buffers with `sprintf`. A 3000-byte identifier therefore overflows static memory in the operator's scope tool. Exploitation needs one operator interaction - selecting the process, or control-clicking a variable - after the identifier appears.

---

## Affected Versions

| Version | Status |
|---------|--------|
| ui-moos up to and including commit `50b9c6c` (no tagged release exists; master also affected) | Vulnerable |

Tested against: ui-moos `(untagged)` (commit `50b9c6c65169c501f746cfef1e167f74a7735e74`), latest master; and MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master, which bundles the same code.

---

## Impact

Static-memory corruption and a crash of the operator's scope tool, with code
execution potential in the operator's process.  The operator-interaction
requirement is what keeps this at medium rather than higher.

---

## Exploitation

A network peer choosing a long handshake name, or any publisher creating a long variable key, in a database an operator is scoping with uMS.

Preconditions:

* uMS in use, and an operator interaction after the malicious identifier appears: selecting the process in the process list, or control-clicking a variable to poke it.

---

## Details

### Affected code

Each affected file is listed twice: first at its path in **ui-moos** git master (commit `50b9c6c`), which is where a fix has to land, then at its path inside the copy bundled in MOOS-IvP under `MOOS_Jul2724/MOOSToolsUI`. The two copies are byte-identical unless stated otherwise.

* **`Core/libMOOS/Comms/MOOSCommServer.cpp`** _(core-moos)_ - lines 944-970: HandShake() accepts any client name of any length after only a uniqueness check
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/Comms/MOOSCommServer.cpp`** - lines 944-970: HandShake() accepts any client name of any length after only a uniqueness check
* **`Tools/Graphical/uMS/ScopeTabPane.cpp`** - lines 242-245: static char sPubTxt[1024]; sprintf(sPubTxt,"%s Publishes",sFocus.c_str()); static char sSubTxt[1024]; sprintf(...)
* **`MOOS_Jul2724/MOOSToolsUI/Tools/Graphical/uMS/ScopeTabPane.cpp`** - lines 242-245: static char sPubTxt[1024]; sprintf(sPubTxt,"%s Publishes",sFocus.c_str()); static char sSubTxt[1024]; sprintf(...)
* **`Tools/Graphical/uMS/ScopeGrid.cpp`** - lines 113-115: static char Name[1024]; sprintf(Name,"new value for %s is....",m_sName.c_str());
* **`MOOS_Jul2724/MOOSToolsUI/Tools/Graphical/uMS/ScopeGrid.cpp`** - lines 113-115: static char Name[1024]; sprintf(Name,"new value for %s is....",m_sName.c_str());
* **`Core/libMOOS/DB/MOOSDB.cpp`** _(core-moos)_ - lines 480-491: UpdateDBClientsVar() broadcasts the raw names in DB_CLIENTS
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/DB/MOOSDB.cpp`** - lines 480-491: UpdateDBClientsVar() broadcasts the raw names in DB_CLIENTS

### Root cause

MOOS imposes no length limit on client names or variable names.  uMS formats them
into fixed 1024-byte `static` buffers with `sprintf`, which has no bound.  A
3000-byte identifier writes ~3 kB into a 1 kB static buffer, corrupting whatever
follows it in the data segment.

Note that `sPubTxt`/`sSubTxt` are written and never read - they are dead stores -
so the overflow is pure collateral damage with no functional purpose.

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

The affected code lives in **ui-moos** (`(untagged)`, commit `50b9c6c`) and is also bundled inside MOOS-IvP under `MOOS_Jul2724/MOOSToolsUI`. Both copies were checked; unless noted otherwise in the text they are byte-identical, so a fix belongs in ui-moos and MOOS-IvP needs to pick it up.

#### Tested / reproduced

Yes, end to end - reproduced against ui-moos `50b9c6c`, **default production build**: the identifiers were planted remotely and pre-auth against a real MOOSDB, and one operator click on the over-long process entry crashed the shipped uMS with `Segmentation fault (core dumped)`. The sanitised build names the site: `ScopeTabPane.cpp:243`.

### Steps and results

Two halves.

*Network*: MOOSDB accepted a 3000-character client name, stored a 3000-character
variable name, returned both in `VAR_SUMMARY`/`PROC_SUMMARY`, and broadcast the
client name in `DB_CLIENTS` to every subscriber - uMS included.

*Sink*: the two `sprintf` calls, reproduced verbatim under ASan:

    ERROR: AddressSanitizer: global-buffer-overflow ... WRITE of size 3011
        #2 scope_tab_pane_sink   (ScopeTabPane.cpp:243 pattern)
    ERROR: AddressSanitizer: global-buffer-overflow ... WRITE of size 3022
        #2 scope_grid_sink       (ScopeGrid.cpp:114 pattern)

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #5](https://github.com/themoos/ui-moos/pull/5)
- Proposed fix commit: [a6ebc0bc6cb3](https://github.com/themoos/ui-moos/commit/a6ebc0bc6cb360315ce620e865f996d189cddb0e)

### Recommended fix

Replace both `sprintf` calls with `snprintf(buf, sizeof(buf), ...)` or with
`std::string` formatting - and drop the dead `sPubTxt`/`sSubTxt` stores
entirely.  Separately and more importantly, enforce a protocol-wide identifier
limit in `CMOOSCommServer::HandShake` and in `CMOOSDB::GetOrMakeVar`
(for example 64 or 128 bytes, matching `[A-Za-z0-9_.-]`), which also fixes
[MCSAID-2026-012](./MCSAID-2026-012-moos-ivp-umemwatch-command-injection-via-moos-client-names.md) at its source.

---

## Recommendations

- Apply the proposed fix from [Pull Request #5](https://github.com/themoos/ui-moos/pull/5) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.
- Treat MOOS variable contents and client names as untrusted in operator tools.

---

## Timeline

- 2026-09-02 – CVE-2026-85452 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85452](https://www.cve.org/CVERecord?id=CVE-2026-85452)
- VulnCheck advisory: [MOOS ui-moos through 50b9c6c uMS Buffer Overflow via Long MOOS Identifiers](https://www.vulncheck.com/advisories/moos-ui-moos-through-50b9c6c-ums-buffer-overflow-via-long-moos-identifiers)
- Upstream pull request: [Pull Request #5](https://github.com/themoos/ui-moos/pull/5)
- Proposed fix commit: [a6ebc0bc6cb360315ce620e865f996d189cddb0e](https://github.com/themoos/ui-moos/commit/a6ebc0bc6cb360315ce620e865f996d189cddb0e)
- Marlink Cyber Security Advisory: [MCSAID-2026-038](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-038-ui-moos-ums-buffer-overflow-via-long-moos-identifiers.md)
- Software: [MOOS ui-moos](https://github.com/themoos/ui-moos)
