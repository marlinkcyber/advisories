# radare2: NULL Pointer Dereference in `info()` (bin_ne.c) Leads to Denial of Service

- **CVE ID:** *(Pending MITRE Assignment)*
- **Reported:** 2025-10-07
- **Published:** 2025-10-08
- **Fixed:** 2025-10-08
- **Severity:** Low (Denial of Service)
- **CWE:** [CWE-476: NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

A NULL pointer dereference vulnerability was found in the `info()` function of `bin_ne.c` in `radare2`. A crafted binary input can trigger a segmentation fault, leading to a **denial of service** when the tool processes malformed data.

To exploit vulnerability, someone must open a crafted binary file. This could impact automated binary analysis environments or pipelines that rely on radare2.

---

## Affected Versions

| Version | Status |
|----------|---------|
| 6.0.5 (commit 0984df0b5d5d4b8f4b66251a6c762f5d69acb088) | Vulnerable |
| Later commits (Fixed in [6c5df3f8570d4f0c](https://github.com/radareorg/radare2/commit/6c5df3f8570d4f0c360681c08241ad8af3b919fd)) | Fixed |

**Patched in:** [Commit referencing fix on GitHub](https://github.com/radareorg/radare2/issues/24660)

---

## Technical Details

When handling certain malformed NE binaries, the `info()` function dereferences a NULL pointer during string handling operations (`strdup`, `strlen`).

This leads to a crash confirmed under AddressSanitizer.

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

The vulnerability was resolved by adding a null check in `bin_ne.c` before accessing fields in `info()`.
See [patch discussion and confirmation](https://github.com/radareorg/radare2/issues/24660).

Fixed in commit [6c5df3f8570d4f0c](https://github.com/radareorg/radare2/commit/6c5df3f8570d4f0c360681c08241ad8af3b919fd).

---

## References

- [GitHub Issue #24660](https://github.com/radareorg/radare2/issues/24660)
- [CWE-476: NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)

