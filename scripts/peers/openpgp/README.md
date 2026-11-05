# Independent OpenPGP recipient fixture

This is a test-only OpenPGP.js 6.3.2 peer. The server and browser do not import
this package. Its npm lock binds the published package integrity and records
LGPL-3.0+; its Node26.13.0/trixie image is pinned by the multi-architecture manifest digest.
Installation/audit run in a separate stage. The recipient image copies only its
locked runtime dependencies and removes unused global npm/corepack tools. Every
remaining OS/library package still participates in the full exact-image scan.
No peer artifact is published or included in a release bundle.

GitHub builds the image and audits its JavaScript dependencies. Test execution
uses no IP network, a read-only container root, no Linux capabilities, one CPU,
192 MiB RAM, a 128 MiB JavaScript heap, 32 processes and a 30-second deadline.
Only synthetic recipient files and one bounded result directory are mounted.
The private recipient stays in that peer; product registration receives only
its public key. No local image build, container execution or inference is needed.

The peer creates a v4 Curve25519 recipient advertising AES-256/OCB preferences.
It decrypts independently reopened ciphertext, requires a version-2 SEIPD packet
with AES-256/OCB and the exact recipient, and refuses corrupt or truncated bytes
before writing plaintext. GnuPG separately covers the version-1 envelope.
The wire formats are defined in [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580.html);
the independent implementation's behavior is documented in the
[OpenPGP.js source](https://github.com/openpgpjs/openpgpjs/tree/v6.3.2).

Code presence and syntax checks do not establish interoperability. Native
results, image identity, exact fingerprints and source/ciphertext digests must
be retained before this profile is called qualified. The native Linux job now
prepares an exact-image vulnerability gate after runtime tests. Source6d30476
completes both native scans and reports blocking findings; the Node patch/runtime
cleanup leaves1critical/33high findings in source4d89fca. The replacement Debian13/trixie profile is prepared, not a clean-image claim. Trivy runs offline against an immutable image
archive with OS and discovered-library inventory, a fresh hash-bound feed and
strict evidence validation. Raw inputs remain private, and nothing is uploaded.
Larger files, v6 keys, other peers, scanner coverage and finding assessment remain
separate qualification work. See [F075](../../../docs/qualification/evidence/F075-peer-image-security.json).
