# Open a signed and encrypted AS2 message

`freightctl as2-message-open` takes captured CMS DER and verifies two layers.
The outer encrypted envelope must match the configured recipient certificate
and private key. The inner detached signature must match the separately pinned
sender certificate and the exact signed MIME entity, including its headers
and line endings. Only then does the command publish the signed entity.

```sh
freightctl as2-message-open \
  --request-file .private/as2-message.json \
  --message-file .private/capture.p7m \
  --recipient-certificate-file .private/recipient.der \
  --recipient-key-file .private/recipient.pkcs8 \
  --signer-certificate-file .private/sender.der \
  --output .private/verified-message.mime
```

The protected request has `schema_version` set to `1` and two lowercase
SHA-256 hex digests. Use `recipient_certificate_sha256` for the configured
recipient DER certificate and `signer_certificate_sha256` for the configured
sender DER certificate. Use the certificates established for those roles
before processing the capture. The recipient file contains a current
key-encipherment leaf certificate and its separate key reference contains the
matching RSA key as protected PKCS#8 DER. The sender leaf must be a current
digital-signing certificate.

The profile uses CMS AuthEnvelopedData with one issuer-and-serial recipient,
RSA-OAEP with SHA-256 and MGF1-SHA-256, and AES-256-GCM with a 12-byte nonce
and 16-byte tag. It admits the empty OAEP label and the attribute-free
`id-data` envelope. The inner SHA-256 RSA signature uses the same
verification boundary as the signed receipt command. [RFC 5083](https://www.rfc-editor.org/rfc/rfc5083.html) · [RFC 5084](https://www.rfc-editor.org/rfc/rfc5084.html) · [RFC 4055, section 4](https://www.rfc-editor.org/rfc/rfc4055.html#section-4)

Pass the decoded binary CMS envelope. The command handles a buffered signed
entity up to 8 MiB, with bounded room for its MIME and CMS wrappers, a single
signature, and bounded headers. It writes a new owner-read-only file in a
private directory, verifies its digest while writing, syncs it, and links
it into place without overwriting another file. The JSON output records
the envelope digest, both certificate digests, the signed entity digest
and its length. Those bytes are the input to a future custody decision.

HTTP sending and receiving, admission into durable custody, receipt creation
and recovery, certificate rollover, large-file streaming and independent
stock AS2 application qualification remain required. The acceptance matrix
also tracks the reviewed encryption suites needed by those peers.
[AS2 acceptance contract](../qualification/protocol-profiles.json)
