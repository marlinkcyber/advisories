# MOOS core-moos: MOOSDB HTTP Pages Stored Cross-Site Scripting

- **Advisory ID:** MCSAID-2026-039
- **CVE ID:** [CVE-2026-85453](https://www.cve.org/CVERecord?id=CVE-2026-85453)
- **Published:** 2026-09-01
- **Severity:** Medium (CVSS 6.1 – CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)
- **CVSS 4.0:** 5.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N)
- **Vulnerability type:** Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- **Current state:** No fixed release; proposed fix submitted upstream in [Pull Request #78](https://github.com/themoos/core-moos/pull/78) (not merged)
- **Software:** [MOOS core-moos](https://github.com/themoos/core-moos)
- **CWE:** [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

The MOOSDB web pages splice variable values, sources, communities and names into HTML text nodes, into quoted attributes and into URLs with no contextual escaping and no Content-Security-Policy. Any MOOS publisher can therefore store cross-site scripting in the MOOSDB web origin, from which the same-origin poke endpoint of [MCSAID-2026-014](./MCSAID-2026-014-core-moos-moosdb-http-server-unauthenticated-variable-write.md) is directly reachable.

---

## Affected Versions

| Version | Status |
|---------|--------|
| core-moos <= 10.4.0 | Vulnerable |

Tested against: core-moos `v10.4.0-49-gec9c77c` (commit `ec9c77c68fcbdef8f5e4c60fe243acd223433f0c`), latest master; and MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master, which bundles the same code.

---

## Impact

Stored cross-site scripting in the MOOSDB web origin.  From there the script has
same-origin access to the poke endpoint of [MCSAID-2026-014](./MCSAID-2026-014-core-moos-moosdb-http-server-unauthenticated-variable-write.md), so it can write helm and
override variables from the operator's browser, and it can be used to pivot
around the operator's network.  Display forgery (making the operator see wrong
values) is arguably the worse outcome in an autonomy context.

---

## Exploitation

Any MOOS publisher ([MCSAID-2026-010](./MCSAID-2026-010-core-moos-missing-authentication-for-moosdb-publish-subscribe-and-db-clear.md)), or any HTTP client that can poke a variable ([MCSAID-2026-014](./MCSAID-2026-014-core-moos-moosdb-http-server-unauthenticated-variable-write.md)).

Preconditions:

* The optional HTTP server enabled, and an operator viewing the page.

---

## Details

### Affected code

Each affected file is listed twice: first at its path in **core-moos** git master (commit `ec9c77c`), which is where a fix has to land, then at its path inside the copy bundled in MOOS-IvP under `MOOS_Jul2724/MOOSCore`. The two copies are byte-identical unless stated otherwise.

* **`Core/libMOOS/DB/HTTPConnection.cpp`** - lines 428-484: BuildSingleVariableWebPageContents(): CHTMLTag Form(wp,"FORM","action='/"+m_sFocusVariable+"'"); sControl = MOOSFormat("<input name=NewValue value=\"%s\">", Msg.GetAsString().c_str()); and the source/community cells
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/DB/HTTPConnection.cpp`** - lines 428-484: BuildSingleVariableWebPageContents(): CHTMLTag Form(wp,"FORM","action='/"+m_sFocusVariable+"'"); sControl = MOOSFormat("<input name=NewValue value=\"%s\">", Msg.GetAsString().c_str()); and the source/community cells
* **`Core/libMOOS/DB/HTTPConnection.cpp`** - lines 490-577: BuildFullDBWebPageContents(): the same pattern for every row
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/DB/HTTPConnection.cpp`** - lines 490-577: BuildFullDBWebPageContents(): the same pattern for every row
* **`Core/libMOOS/DB/HTTPConnection.cpp`**: no Content-Security-Policy header is emitted
* **`MOOS_Jul2724/MOOSCore/Core/libMOOS/DB/HTTPConnection.cpp`**: no Content-Security-Policy header is emitted

### Root cause

Variable values, sources, communities and names are concatenated straight into
HTML - into element bodies, into a double-quoted `value=` attribute, into a
single-quoted `action=` attribute and into an `href=` URL - with no contextual
encoding and no CSP.  A value of `"><script>...</script>` closes the `value`
attribute and the tag and executes.

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

One MOOS publication with
`sval='"><script>fetch("/MOOS_MANUAL_OVERRIDE?NewValue=false")</script>'`,
`src='<img src=x onerror=alert(document.domain)>'`,
`community='<svg onload=alert(1)>'` produced, verbatim in the served page:

    <TD ><input name=NewValue value=""><script>fetch("/MOOS_MANUAL_OVERRIDE?NewValue=false")</script>"></TD>
    <TD ><img src=x onerror=alert(document.domain)></TD>
    <TD ><svg onload=alert(1)></TD>

Response headers carried no `Content-Security-Policy`.  A variable *name*
containing `'><script>alert('name')` was also reflected into the `FORM action=`
and `A href=` attributes (the request parser strips `/` from the path, so a
closing `</script>` becomes `<script>`, but the tag injection stands).

---

## Mitigations

A fix has been proposed upstream but has not been merged at the time of writing:

- Pull request: [Pull Request #78](https://github.com/themoos/core-moos/pull/78)
- Proposed fix commit: [a3f26f099bb0](https://github.com/themoos/core-moos/commit/a3f26f099bb08decb143f704d8b1ca16ae405b44)

### Recommended fix

Escape at the point of output, per context: HTML-escape text nodes
(`& < > " '`), attribute-escape and always quote attribute values, and
URL-encode anything placed in a URL.  Introduce a tiny helper and use it
everywhere rather than fixing individual sites.  Send
`Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'` (or
similar) and `X-Content-Type-Options: nosniff`.

---

## Recommendations

- Apply the proposed fix from [Pull Request #78](https://github.com/themoos/core-moos/pull/78) until an official upstream release contains it.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.
- Treat MOOS variable contents and client names as untrusted in operator tools.

---

## Timeline

- 2026-09-01 – CVE-2026-85453 published
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85453](https://www.cve.org/CVERecord?id=CVE-2026-85453)
- VulnCheck advisory: [MOOS core-moos through 10.4.0 MOOSDB HTTP Pages Stored Cross-Site Scripting](https://www.vulncheck.com/advisories/moos-core-moos-through-10.4.0-moosdb-http-pages-stored-cross-site-scripting)
- Upstream pull request: [Pull Request #78](https://github.com/themoos/core-moos/pull/78)
- Proposed fix commit: [a3f26f099bb08decb143f704d8b1ca16ae405b44](https://github.com/themoos/core-moos/commit/a3f26f099bb08decb143f704d8b1ca16ae405b44)
- Marlink Cyber Security Advisory: [MCSAID-2026-039](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-039-core-moos-moosdb-http-pages-stored-cross-site-scripting.md)
- Software: [MOOS core-moos](https://github.com/themoos/core-moos)
