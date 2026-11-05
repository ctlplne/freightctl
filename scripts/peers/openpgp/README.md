# Independent OpenPGP recipient fixture

This is a test-only OpenPGP.js 6.3.2 peer. The server and browser do not import
this package. Its npm lock binds the published package integrity and records
LGPL-3.0+. Installation/audit use the pinned official Node26.13.0/trixie builder.
The `6.3.2-r2` candidate pins Distroless Node26/Debian13;its ARM64/x86_64
manifest annotations identify Node26.13.0,which actual native proof must verify. It copies only locked runtime dependencies
and the fixture/proof scripts. Builder shells,package managers and unrelated
general utilities are absent from this actual runtime. All base package metadata
and every remaining OS/library package still participate in the full exact-image
scan. No findings,inventory entries or severities are removed from reports.

The exact runtime index is
`sha256:9b945e92c1b5463a4b75f11e8417515e4bea7355f6adfd79ec220fbbe905dda8`.
Its two native manifest annotations name Node26.13.0. An offline native build
probe independently checks the actual binary/version,UID/GID,OpenPGP import,
retained Debian package metadata and absent unneeded programs. The scan verifier
also pins profile/base provenance and absolute entrypoint. Registry metadata and
stand-ins are not runtime,scan or interoperability qualification.
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
cleanup leaves1critical/33high findings in source4d89fca. The full Debian13/trixie
profile completes scans with45high/6unknown findings on each native architecture.
The minimal Distroless replacement is prepared,not a clean-image claim. Actual
runtime/scans and original independent AEAD decryption/corruption/recovery replay
are owed. Trivy runs offline against an immutable image
archive with OS and discovered-library inventory, a fresh hash-bound feed and
strict evidence validation. Raw inputs remain private, and nothing is uploaded.
Larger files, v6 keys, other peers, scanner coverage and finding assessment remain
separate qualification work. See [F075](../../../docs/qualification/evidence/F075-peer-image-security.json).
