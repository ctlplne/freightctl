# Verify a detached AS2 receipt

`freightctl as2-mdn-verify` checks a captured positive AS2 message disposition
notification (MDN) against the sender's saved message and its configured peer.
A positive result means the peer signed an unqualified `processed` receipt for
that exact message ID and the digest of its signed MIME entity. Both receiver
durability and business acceptance remain `unknown`. [RFC 4130,
sections 5.3.3 and 7](https://www.rfc-editor.org/rfc/rfc4130.html#section-7)

Save four protected input files before running the command. The receipt MIME
entity is the exact signed first part of the captured `multipart/signed` MDN.
Keep its CRLF line endings and MIME headers. The detached signature file
contains the decoded CMS bytes from the signature part. The certificate file
contains the peer's reviewed leaf certificate in DER format.

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
Supported MIC labels are `sha-256` and `sha256`. A failure, warning, changed
digest, changed peer or ambiguous receipt returns a nonzero exit code and
produces no verified receipt. [RFC 5652, section 5](https://www.rfc-editor.org/rfc/rfc5652.html#section-5)

The local JSON result carries the processed disposition, original message ID
digest, MIC, signed report digest, signature digest and certificate digest.
The request is bounded to 4 KiB, the signed report to 64 KiB, the CMS signature
to 32 KiB and the certificate to 16 KiB. Inside the report, the top headers
and machine-readable notification are bounded to 4 KiB and 8 KiB. The
verifier accepts two MIME parts and keeps the free-text note out of its result.

This profile covers local verification of a positive receipt from protected
files. AS2 HTTP sending and receiving, CMS encryption, synchronous and
asynchronous receipt recovery, negative receipt persistence, reviewed
certificate rotation and stock AS2 application interoperability remain
required. Track them in the [AS2 acceptance contract](../qualification/protocol-profiles.json).
