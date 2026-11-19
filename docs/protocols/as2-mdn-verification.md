# Verify or observe a signed AS2 receipt

`freightctl as2-mdn-verify` checks a captured AS2 message disposition
notification (MDN) against the sender's saved message and its configured peer.
The default profile requires an unqualified `processed` receipt for
that exact message ID and the digest of its signed MIME entity. Both receiver
durability and business acceptance remain `unknown`. [RFC 4130,
sections 5.3.3 and 7](https://www.rfc-editor.org/rfc/rfc4130.html#section-7)

Save the complete `multipart/signed` MIME entity in a protected file. Include
the outer `Content-Type` header, the blank line and the untouched MIME body.
Keep the original CRLF framing around the MIME parts. The certificate file
contains the peer's reviewed leaf certificate in DER format.

```sh
freightctl as2-mdn-verify \
  --request-file .private/as2-original.json \
  --receipt-file .private/as2-receipt.mime \
  --signer-certificate-file .private/as2-peer.der
```

If you already have the two parts, pass the exact signed MIME entity and
decoded CMS signature separately. Both forms produce the same verified
result. The command requires exactly one input form.

```sh
freightctl as2-mdn-verify \
  --request-file .private/as2-original.json \
  --report-file .private/as2-receipt.mime \
  --signature-file .private/as2-receipt.der \
  --signer-certificate-file .private/as2-peer.der
```

The request is a JSON object with exactly these fields.

| Field | Value from the original message or configuration |
| --- | --- |
| `schema_version` | `1` |
| `original_message_id` | The original Message-ID with its original spelling and bracket syntax. |
| `final_recipient` | The exact configured value after `rfc822;` in the peer's signed Final-Recipient. |
| `content_mic_sha256` | The 64 lowercase hex digits of the sender's saved SHA-256 over the canonical signed MIME entity, including its MIME headers. |
| `signer_certificate_sha256` | The 64 lowercase hex digits of the configured certificate's DER digest. |

The verifier checks the configured certificate and the embedded signer
certificate byte for byte. It requires a currently valid digital-signing leaf
with an RSA key of 3072 through 8192 bits, and one detached SHA-256 RSA
PKCS#1 v1.5 signature. It verifies the signature over the supplied bytes
before reading the signed disposition, recipient, message ID, or MIC.
Supported MIC labels are `sha-256` and `sha256`. A changed digest, changed
peer or ambiguous receipt returns a nonzero exit code and produces no
verified receipt. [RFC 5652, section 5](https://www.rfc-editor.org/rfc/rfc5652.html#section-5)

The local JSON result carries the processed disposition, original message ID
digest, MIC, signed report digest, signature digest and certificate digest.
The complete capture is bounded to 128 KiB, the request to 4 KiB, the signed
report to 64 KiB, the CMS signature to 32 KiB and the certificate to 16 KiB.
The capture, signature part and signed report each have a 4 KiB top-header
limit. The machine-readable notification is bounded to 8 KiB.

The container must declare `multipart/signed` with a SHA-256 `micalg` and a
matching PKCS#7 signature protocol. The verifier uses the first of exactly two
parts as the signed bytes, including the part's headers and any final CRLF.
Only the CRLF introducing the next delimiter belongs to the delimiter.
The signature part can contain binary DER or base64, including LF or CRLF
folds in the base64. This decoding applies to the signature part only. The
free-text note stays out of the result. [RFC 1847, section 2.1](https://www.rfc-editor.org/rfc/rfc1847.html#section-2.1) · [RFC 2046, section 5.1.1](https://www.rfc-editor.org/rfc/rfc2046.html#section-5.1.1)

## Observe a signed warning or failure

Add `--receipt-profile as2-signed-disposition-sha256-v1` to either input form
to inspect an authenticated warning or failure. Exit zero confirms that the
signed outcome matches the configured peer and original message. Read
`disposition` to determine the outcome the peer reported.

| `disposition` | Signed observation |
| --- | --- |
| `processed` | Unqualified processing with a matching MIC. |
| `processed/warning` | Processing with a peer-reported warning. |
| `processed/error` | A processing error. A recognized standard code appears as `error_code` when available. |
| `failed` | The peer reported failure. |

A warning, error or failure can omit its MIC. The result then has
`content_mic_status: "absent"` and omits the digest. When a MIC is present, it
must match the original and the status is `matched`. Receiver durability
and business acceptance remain `unknown`. The peer's prose stays out of the
result. [RFC 4130, sections 7.5.3–7.5.6](https://www.rfc-editor.org/rfc/rfc4130.html#section-7.5.3)

AS2 HTTP sending and receiving, CMS encryption, synchronous and asynchronous
receipt persistence and recovery, reviewed certificate rotation and stock
AS2 application interoperability remain required. Track them in the
[AS2 acceptance contract](../qualification/protocol-profiles.json).
