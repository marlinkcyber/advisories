# MOOS-IvP: Out-of-Bounds Read in isBraced, isQuoted and isChevroned

- **Advisory ID:** MCSAID-2026-030
- **CVE ID:** [CVE-2026-85444](https://www.cve.org/CVERecord?id=CVE-2026-85444)
- **Published:** 2026-09-02
- **Severity:** High (CVSS 7.5 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **CVSS 4.0:** 8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Out-of-bounds Read
- **Current state:** Fixed upstream in `main` by [Pull Request #128](https://github.com/moos-ivp/moos-ivp/pull/128) (merged 2026-09-11); not yet in a tagged release (latest release is v24.8.1)
- **Software:** [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
- **CWE:** [CWE-125: Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

`isBraced()`, `isQuoted()` and `isChevroned()` compute the length of the whitespace-stripped string and then index it with the length of the *original* string. Trailing whitespace therefore reads past the buffer by exactly the number of bytes the attacker appended. `string2NodeRecord()` calls `isBraced()` on the raw `NODE_REPORT` value, and the standard contact managers and pHelmIvP hand it that value unstripped. Not in an earlier assessment.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |
| moos-ivp `main` from commit [`f2f8cbebb59b`](https://github.com/moos-ivp/moos-ivp/commit/f2f8cbebb59b048b931f46a511b61df5388e079b) | Fixed |

Tested against: MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master.

---

## Impact

Remote, unauthenticated denial of service of pContactMgrV20,
pBasicContactMgr, pHelmIvP, uFldNodeComms and pMarineViewer - the contact and
helm path, i.e. the part of the stack that decides where the vehicle goes.  No
information disclosure: the function returns only a `bool`, so the
out-of-bounds byte never reaches the attacker.

Small over-reads are silent (they land on the same heap page), so on a stock
build the attacker needs a large amount of trailing whitespace to leave a mapped
page; measured on this build the crash threshold for a real app was around
100 MB of trailing spaces. Every smaller payload is still undefined behaviour.

---

## Exploitation

Any publisher of NODE_REPORT - i.e. any peer that can reach the MOOSDB port ([MCSAID-2026-010](./MCSAID-2026-010-core-moos-missing-authentication-for-moosdb-publish-subscribe-and-db-clear.md)), or anything upstream of a field bridge ([MCSAID-2026-016](./MCSAID-2026-016-essential-moos-pshare-unauthenticated-udp-datagram-republishing.md) and [MCSAID-2026-017](./MCSAID-2026-017-essential-moos-pmoosbridge-unauthenticated-udp-packet-injection.md)).

Preconditions:

* One of the standard apps that hands the *unstripped* message value to string2NodeRecord: pContactMgrV20, pBasicContactMgr, pHelmIvP, or anything using ContactLedger (uFldNodeComms, pMarineViewer).
* The value must strip to something whose first character is `{` (or `"` / `<` for the sibling functions), because the `&&` short-circuits.

---

## Details

### Affected code

* **`ivp/src/lib_mbutil/MBUtils.cpp`** - lines 1693-1703: isQuoted(): `mod_str[str.length()-1]` - indexes the stripped string with the original string's length
* **`ivp/src/lib_mbutil/MBUtils.cpp`** - lines 1710-1720: isBraced(): the same bug
* **`ivp/src/lib_mbutil/MBUtils.cpp`** - lines 1727-1737: isChevroned(): the same bug
* **`ivp/src/lib_contacts/NodeRecordUtils.cpp`** - lines 119, 222: string2NodeRecord() calls isBraced() on the raw report string
* **`ivp/src/pContactMgrV20/ContactMgrV20.cpp`** - lines 106, 374: sval = msg.GetString() (unstripped) -> handleMailNodeReport -> string2NodeRecord
* **`ivp/src/pBasicContactMgr/BasicContactMgr.cpp`** - lines 106, 423: the same raw-value path
* **`ivp/src/pHelmIvP/HelmIvP.cpp`** - line 199: sval = msg.GetString() -> node-report processing -> the ledger
* **`ivp/src/lib_geodaid/ContactLedger.cpp`** - lines 190-193: processNodeReport() -> string2NodeRecord(report), so uFldNodeComms and pMarineViewer are on the same path

### Root cause

```cpp
bool isBraced(const string& str) {
  string mod_str = stripBlankEnds(str);        // shorter than str
  string::size_type len = mod_str.length();
  if(len < 2) return(false);
  if((mod_str[0] == '{') && (mod_str[str.length()-1] == '}'))   // BUG
    return(true);
  return(false);
}
```

`len` is computed and then not used for the second index.  When the input has
trailing (or leading) whitespace, `str.length() > mod_str.length()`, so
`mod_str[str.length()-1]` reads past the end of `mod_str`'s buffer.  The
over-read distance is exactly the amount of whitespace the attacker appended, so
this is a chosen-offset out-of-bounds read rather than a fixed off-by-one.

`isQuoted` and `isChevroned` are the same function with `"` and `<`, and have
the same bug on the same lines.

`string2NodeRecord()` calls `isBraced()` as its first operation on the raw
report string, and the standard contact managers and pHelmIvP pass
`msg.GetString()` to it without stripping, so the read happens on receipt,
before any filtering or validation.

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

This is MOOS-IvP specific code. It does not exist in core-moos, essential-moos or ui-moos, so MOOS-IvP is the only affected repository.

#### Tested / reproduced

Yes - reproduced against MOOS-IvP `1de9ae146`, default production build (`./build-moos.sh && ./build-ivp.sh`).

### Steps and results

*Sink in isolation* (`-O2`, no sanitiser - what a normal user runs):

    n=100      -> returns 0, no crash   (silent out-of-bounds read)
    n=5000     -> returns 0, no crash
    n=200000   -> SIGSEGV
    n=5000000  -> SIGSEGV

Under ASan, even `n=100` is named exactly:

    ERROR: AddressSanitizer: heap-buffer-overflow  READ of size 1
        #0 in isBraced(...)  ivp/src/lib_mbutil/MBUtils.cpp:1717

*Live, over the network*, against a stock `pContactMgrV20`: publishing
`NODE_REPORT = "{NAME=ghost,X=0,Y=0}" + " "*5000` from an unauthenticated MOOS
client reaches the bug -

    ERROR: AddressSanitizer: heap-buffer-overflow  READ of size 1
        #0 isBraced(...)                MBUtils.cpp:1717
        #1 string2NodeRecord(...)       NodeRecordUtils.cpp:119
        #2 ContactMgrV20::handleMailNodeReport(...)

and on the stock build:

    5,000         trailing spaces -> survived
    2,000,000     trailing spaces -> survived
    100,000,000   trailing spaces -> SIGSEGV (exit -11)

with a control run that rules out memory pressure: the **same 100 MB payload**
without the `{` prefix (so `isBraced` short-circuits and never evaluates the bad
index) leaves the process alive.

---

## Mitigations

Fixed upstream in the `main` branch; no tagged release containing the fix exists yet.

- Pull request: [Pull Request #128](https://github.com/moos-ivp/moos-ivp/pull/128) (merged 2026-09-11)
- Fix commit: [f2f8cbebb59b](https://github.com/moos-ivp/moos-ivp/commit/f2f8cbebb59b048b931f46a511b61df5388e079b)

### Recommended fix

One-line fix in each of the three functions: use the stripped length.

```cpp
if((mod_str[0] == '{') && (mod_str[len-1] == '}'))
```

Then, defensively, strip the value before handing it to `string2NodeRecord` in
the app-level handlers, and cap the accepted length of a `NODE_REPORT` - a
100 MB node report is not a legitimate input in any case (see also [MCSAID-2026-028](./MCSAID-2026-028-core-moos-moosdb-denial-of-service-via-unbounded-packet-allocation.md),
which is what lets a message that large exist at all).

---

## Recommendations

- Upgrade to a moos-ivp release that includes commit [`f2f8cbebb59b`](https://github.com/moos-ivp/moos-ivp/commit/f2f8cbebb59b048b931f46a511b61df5388e079b) once available, or build from `main` at or after that commit.
- MOOS has no authentication or transport security; only expose MOOSDB and inter-community (pShare / pMOOSBridge / uFld*) ports on isolated, trusted networks and filter them at the network boundary.

---

## Timeline

- 2026-09-02 – CVE-2026-85444 published
- 2026-09-11 – Fix merged upstream in [Pull Request #128](https://github.com/moos-ivp/moos-ivp/pull/128)
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85444](https://www.cve.org/CVERecord?id=CVE-2026-85444)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 Out-of-Bounds Read in isBraced, isQuoted and isChevroned](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-out-of-bounds-read-in-isbraced-isquoted-and-ischevroned)
- Upstream pull request: [Pull Request #128](https://github.com/moos-ivp/moos-ivp/pull/128)
- Fix commit (PR head): [faff8adfa1a69d68614461f679ebbc1d741c51aa](https://github.com/moos-ivp/moos-ivp/commit/faff8adfa1a69d68614461f679ebbc1d741c51aa)
- Marlink Cyber Security Advisory: [MCSAID-2026-030](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-030-moos-ivp-out-of-bounds-read-in-isbraced-isquoted-and-ischevroned.md)
- Merge commit: [f2f8cbebb59b048b931f46a511b61df5388e079b](https://github.com/moos-ivp/moos-ivp/commit/f2f8cbebb59b048b931f46a511b61df5388e079b)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
