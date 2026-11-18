# Independent OpenPGP recipient fixture

This is a test-only OpenPGP.js 6.3.2 peer. Its npm lock binds the published
package integrity and records the LGPL-3.0+ license. The server and browser use
their own cryptographic implementation.

The `6.3.2-r4` candidate uses the pinned official Node 26.13.0 image on Alpine
3.24.4 for dependency installation, npm audit, and runtime assembly. The final
image starts from `scratch`. The offline assembler copies the stock Node binary
and every file from `alpine-release`, `musl`, `libgcc`, and `libstdc++`. The x86
executable also needs `libatomic`. It checks the SHA-256-pinned package records
and verifies each required file against the exact checksum in its original
record. It copies the full records into `/lib/apk/db/installed` so Trivy can
identify every shipped package by name, source, version, and architecture.

[runtime-dependencies.json](runtime-dependencies.json) pins the official image
index, native platform manifests, executable and installed package records.
The nonroot runtime probe imports OpenPGP.js, checks the exact mapped libraries,
and verifies the Node executable, Alpine release and package record digests in
the finished image. It checks that the shell and package managers are absent.
The enforcing report guard requires the exact runtime profile, Alpine release,
native APK package inventory, and OpenPGP.js dependency. Every reported finding
still reaches the severity and suppression checks.

The exact embedded version comes from Node26.13.0's generated
[`src/zlib_version.h`](https://github.com/nodejs/node/blob/v26.13.0/src/zlib_version.h).
Its updater appends the imported source commit to the dependency header version.
F120 preserves the first native failure caused by expecting only the header's
shorter string. The corrected assertion still requires the exact full version;
the corrected native probes and full image gates pass at02140e7. Original
independent interoperability/recovery and final-source qualification remain owed.

The earlier Debian image passed both native image gates at `02140e7`. Five
glibc advisories subsequently blocked both architectures on `b7b0eb5`. The
Alpine peer at `f58dd14` passed all eight dedicated encrypted FTPS cases and
fresh enforcing scans on both architectures with zero findings or suppressions.
Both broader PostgreSQL suites failed. Final-source replay remains due.
[Earlier Debian pass](../../../docs/qualification/evidence/F124-native-peer-image-gate-passed.json)
[Original Debian failures](../../../docs/qualification/evidence/F501-portability-native-batch-terminal.json)
[Original Alpine outcomes](../../../docs/qualification/evidence/F507-alpine-peer-native-batch-terminal.json)

GitHub builds the image and audits its JavaScript dependencies. Test execution
uses no IP network, a read-only container root, no Linux capabilities, one CPU,
192 MiB RAM, a 128 MiB JavaScript heap, 32 processes and a 30-second deadline.
Only synthetic recipient files and one bounded result directory are mounted.
The private recipient stays in that peer; product registration receives only
its public key. The native GitHub jobs build, exercise and scan this fixture.

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
