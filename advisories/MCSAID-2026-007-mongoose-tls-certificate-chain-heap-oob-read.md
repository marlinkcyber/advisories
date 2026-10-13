# Mongoose: Out-of-Bounds Read in TLS 1.3 Certificate Chain Parsing leads to Denial of Service

- **Advisory ID:** MCSAID-2026-XXX
- **CVE ID:** [CVE-2026-52061](https://www.cve.org/CVERecord?id=CVE-2026-52061)
- **GHSA ID:** [GHSA-pfr9-hqr2-78rq](https://github.com/cesanta/mongoose/security/advisories/GHSA-pfr9-hqr2-78rq)
- **Reported:** 2026-04-27
- **Published:** 2026-08-12
- **Severity:** High (CVSS 7.5 – CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **Vulnerability type:** Out-of-bounds read, Denial of Service (DoS), Service crash
- **Current state:** Fix released by vendor in Mongoose 7.22
- **Exploitation:** Easy, deterministic, not seen in the wild
- **Software:** [Cesanta Mongoose](https://github.com/cesanta/mongoose)
- **CWE:** [CWE-125: Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
- **Discovered by:** Ana Kapulica (ljoer) of Marlink Cyber 

---

## Summary

A malicious TLS server can crash a Mongoose TLS 1.3 client by sending a malformed `Certificate` handshake message. The certificate-chain parser in `mg_tls_recv_cert()` reads a per-certificate length (`certsz`) directly from attacker-controlled message bytes and uses it as an offset to read the two-byte certificate-extensions field, without first checking that the resulting read stays within the decrypted `Certificate` message. The overall `cert_chain_len` is likewise not validated against the actual received length.

Because this parsing happens before any certificate verification, the out-of-bounds read is reachable with attacker-supplied, unauthenticated data. A default Mongoose TLS client, with no CA or hostname configured, hits this code path during a normal handshake and reads past the end of the received payload, crashing the client. The vendor notes the same class of flaw can read up to 16 MB of adjacent heap memory, and that the parser is also reachable on the server side when client certificates are requested (mutual TLS).

---

## Affected Versions

| Version | Status |
|---------|--------|
| Mongoose <= 7.21 (all versions up to and including 7.21) | Vulnerable |
| Mongoose 7.22 and later | Fixed |

Reproduced against Mongoose at commit `edd2d0662718b42baecb9c0f63dc8049a553c411`, built with `clang 18` on Ubuntu 24.04 LTS, x86_64. The vendor verified the issue against master commit `0a3db82`.

---

## Impact

A remote, unauthenticated attacker operating a malicious TLS server (or able to impersonate one) can crash any application that uses the Mongoose built-in TLS 1.3 client, with a single malformed handshake message. No CA, hostname, or other client configuration is required, and the trigger is deterministic rather than racy.

The read goes past the end of the decrypted `Certificate` message into adjacent heap memory. In the observed case this causes an immediate segmentation fault (denial of service). Per the vendor advisory, the same unchecked offset can be used to read up to 16 MB of heap memory, which may contain sensitive data such as keys, tokens, or credentials, so information disclosure cannot be ruled out. The vendor also notes the code path is reachable on the server side in mutual-TLS deployments where a client certificate is requested.

Since Mongoose is widely embedded in networked devices and services, loss or compromise of the TLS client has broad operational impact for affected products.

---

## Exploitation

The attacker must get a Mongoose TLS client to connect to a server they control, or be able to impersonate the server the client connects to. During the normal TLS 1.3 handshake the malicious server sends an encrypted `Certificate` message whose embedded `certsz` (and/or `cert_chain_len`) points beyond the end of the actual message. Because the out-of-bounds read occurs in raw certificate parsing that precedes certificate verification, no valid certificate, chain, or trust configuration on the client is needed.

---

## Details

### Affected code

- **Repository:** `mongoose`
- **Commit checked:** `edd2d0662718b42baecb9c0f63dc8049a553c411`
- **File:** `src/tls_builtin.c`
- **Function:** `mg_tls_recv_cert()`
- **Vendor-cited range:** `tls_builtin.c:1603-1671`

Relevant code as checked locally:

```c
1641    while (p < endp) {
1642      struct mg_tls_cert *ci = &certs[certnum++];
1643      uint32_t certsz = MG_LOAD_BE24(p);
1644      uint8_t *cert = p + 3;
1645      uint16_t certext = MG_LOAD_BE16(cert + certsz);
1646      if (certext != 0) {
1647        mg_error(c, "certificate extensions are not supported");
1648        return -1;
1649      }
```

### Root cause

The `Certificate` parser reads `certsz` from attacker-controlled message bytes and then reads:

```c
MG_LOAD_BE16(cert + certsz)
```

without first checking that `cert + certsz + 2` is still within the decrypted `Certificate` message. In addition, `cert_chain_len` is not validated against the actual decrypted length before `endp` is derived.

Together these allow a malicious TLS server to make the Mongoose TLS client read far past the end of the received `Certificate` payload. The per-certificate size is a 3-byte big-endian value (up to ~16 MB), so the read offset is fully attacker-controlled.

No special client configuration is required: the out-of-bounds read happens in the raw `Certificate` parsing loop, before any certificate-verification logic is reached. A default Mongoose TLS client with no CA or hostname configured still reaches this code path and crashes.

### Trigger path

The crash was verified in the real client handshake path:

```
mg_tls_client_handshake()
  -> mg_tls_recv_cert()
```

The malformed input is an encrypted TLS 1.3 `Certificate` handshake message sent by a malicious server during the normal handshake.

---

## Indicators

**On host:**

- Unexpected termination (`Segmentation fault`) of a process using the Mongoose built-in TLS client, during or immediately after a TLS 1.3 handshake.

**On network:**

- A TLS 1.3 server sending a `Certificate` handshake message whose declared certificate length(s) exceed the size of the message actually sent.
- Malformed or oversized certificate-chain / certificate-size fields in the `Certificate` message that do not match the record length.

---

## Mitigations

Mongoose 7.22 adds bounds validation to the certificate-chain parser so that per-certificate sizes and the overall chain length are checked against the received message length before being used as read offsets.

- Fixed release: Mongoose 7.22 - [github.com/cesanta/mongoose/releases](https://github.com/cesanta/mongoose/releases)

---

## Recommendations

- Upgrade to Mongoose 7.22 or later.
- For products that embed Mongoose and cannot upgrade immediately, restrict which TLS servers the client connects to where feasible; note this does not fully mitigate the issue, since any connection to an attacker-controlled or impersonated server can trigger it.
- In mutual-TLS deployments, be aware the vendor reports the parser is also reachable on the server side when client certificates are requested.

---

## References

- Vendor advisory: [GHSA-pfr9-hqr2-78rq](https://github.com/cesanta/mongoose/security/advisories/GHSA-pfr9-hqr2-78rq)
- CVE record: [CVE-2026-52061](https://www.cve.org/CVERecord?id=CVE-2026-52061)
- Marlink Cyber Security Advisory: [MCSAID-2026-007](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2026-007-mongoose-tls-certificate-chain-heap-oob-read.md)
- Software: [Cesanta Mongoose](https://github.com/cesanta/mongoose)
