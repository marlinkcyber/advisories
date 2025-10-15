# radare2: NULL Pointer Dereference in `load()` (bin_dyldcache.c) Leads to Denial of Service

**CVE ID:** *(Pending MITRE Assignment)*
**Reported:** 2025-10-07
**Published:** 2025-10-08
**Fixed:** 2025-10-08
**Severity:** Low (Denial of Service)
**CWE:** [CWE-476: NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)
**Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

A NULL pointer dereference vulnerability exists in `radare2` within the `load()` function of `bin_dyldcache.c`.
Processing a crafted file can cause a segmentation fault and crash the program.

To exploit vulnerability, someone must open a crafted binary file. This could impact automated binary analysis environments or pipelines that rely on radare2.

---

## Affected Versions

| Version | Status |
|----------|---------|
| 6.0.5 (commit 0984df0b5d5d4b8f4b66251a6c762f5d69acb088) | Vulnerable |
| Later commits | Fixed |

**Patched in:** [Commit referencing fix on GitHub](https://github.com/radareorg/radare2/issues/24661)

---

## Technical Details

The crash occurs when `load()` attempts to access a field through a NULL pointer of type `struct RIODesc`.
ASAN reports a segmentation fault at `bin_dyldcache.c:1159`.

---

## Impact

- **Impact:** Denial of Service (crash)
- **Attack Vector:** Local / crafted input
- **Privileges Required:** None
- **User Interaction:** Required

**CVSS v3.1 Base Score:** 5.5
Vector: `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H`

---

## Fix

The patch adds checks to ensure the pointer to `RIODesc` is valid before dereferencing it.
See the confirmed fix in the [GitHub issue](https://github.com/radareorg/radare2/issues/24661).

Fixed in commit [e37e15d10fd8a19](https://github.com/radareorg/radare2/commit/e37e15d10fd8a19c3e57b3d7735a2cfe0082ec79).

---

## References

- [GitHub Issue #24661](https://github.com/radareorg/radare2/issues/24661)
- [CWE-476: NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)


