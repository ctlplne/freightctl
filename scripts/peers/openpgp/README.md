# Independent OpenPGP recipient fixture

This is a test-only OpenPGP.js 6.3.2 peer. The server and browser do not import
this package. Its npm lock binds the published package integrity and records
LGPL-3.0+. Installation/audit use the pinned official Node26.13.0/trixie builder.
The `6.3.2-r3` candidate uses a pinned Distroless Debian13 no-SSL base and copies
the complete `/nodejs` tree from the pinned Distroless Node26 input. It assembles
four complete, SHA-256-pinned Debian packages per native architecture:
`gcc-14-base`, `libgcc-s1`, `libstdc++6` and `libatomic1`. Package data, licenses,
original control records and installed-file hashes stay in the final image.
The build verifies package digests before extraction and checks package name,
version and architecture before copying data. No maintainer scripts execute.
The assembler checks the manifest hash required by the image provenance guard.

The base index is
`sha256:e6b0f82595aa1edde72c8054de7a9dca30f0f8f54820c37a167c0ddfc21c5c67`;
the separate Node input index is
`sha256:9b945e92c1b5463a4b75f11e8417515e4bea7355f6adfd79ec220fbbe905dda8`.
The package manifest is [runtime-dependencies.json](runtime-dependencies.json),
derived from the public Distroless Debian13 package lock. Its two architectures
use exact package version14.2.0-19. The actual native build probe must verify
Node26.13.0, embedded zlib1.3.2.1-motley-456ae73, no shared SSL/zlib linkage, UID/GID65532,
OpenPGP6.3.2 imports, retained package metadata and absent unneeded libraries/tools.
The report guard pins both image inputs, the package manifest and absolute Node
entrypoint. Every remaining OS/library package and finding participates in the
complete final-image scan; no report inventory or severity is removed.

The exact embedded version comes from Node26.13.0's generated
[`src/zlib_version.h`](https://github.com/nodejs/node/blob/v26.13.0/src/zlib_version.h).
Its updater appends the imported source commit to the dependency header version.
F120 preserves the first native failure caused by expecting only the header's
shorter string. The corrected assertion still requires the exact full version;
native green and complete scans remain owed.

This changes the actual runtime dependencies. It does not waive the prior
CVE-2026-76844 finding against the Debian zlib package: F114 preserves the
original native failures. Registry metadata and stand-ins establish no runtime,
scan or interoperability result. Both native candidate builds, complete scans
and original independent AEAD decryption/corruption/recovery replay are owed.
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
be retained before this profile is qualified. Trivy scans the complete immutable
image archive offline using a fresh hash-bound feed and OS/discovered-library
inventory. HIGH, CRITICAL, UNKNOWN, suppression and incomplete evidence fail.
Raw inputs remain private; nothing is uploaded. All original scan/resource
failures remain in [F075](../../../docs/qualification/evidence/F075-peer-image-security.json).
Larger files, v6 keys, other peers, shipped product images and full SBOM/license
qualification remain separate work.
