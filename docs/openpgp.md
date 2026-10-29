# OpenPGP verification for held intake

A detached signature is a separate, small proof about exact file bytes. The partner administrator enrolls a public key with its full fingerprint, then selects that exact key version in the intake policy. The uploader attaches the signature to its held file. Both CSV validation and signature verification must pass, and an operator must approve the resulting report before the file becomes available. No model participates.

This profile verifies detached binary-document signatures using the [RFC 9580](https://www.rfc-editor.org/info/rfc9580/) OpenPGP packet model, including supported version-4 keys. The bounds below define the narrower application profile; full RFC conformance is not claimed. Outbound encryption is described in [encrypted delivery](encrypted-delivery.md). Decryption, private signing keys, malware scanning, attached/cleartext signatures, text canonicalization, general workflow crypto tasks and complete business-file journeys remain required work. A verified signature proves the selected key signed those bytes; it does not prove the contents are safe or the receiver accepted a business transaction.

## Enroll and select a signer

Use ordinary tenant, partner, protected token and storage selectors. `pgp-key-register` requires the root mount, `admin` and `pgp_manage`. Obtain the complete primary fingerprint through an independently trusted partner channel. Names and email addresses inside a key block do not establish trust. There is no key-server lookup, certificate discovery or web-of-trust inference.

Create a bounded metadata request:

```json
{"expected_version":0,"fingerprint":"FULL_PRIMARY_FINGERPRINT"}
```

Run `pgp-key-register --request-file REQUEST --pgp-public-file PUBLIC_KEY --idempotency-key KEY`. Protect the public-key input file with the same restrictive local file permissions required by other identity import commands. The key may be binary or ASCII armored. Secret-key packets are rejected. `pgp-key-status --pgp-key-id ID --version N` returns the fingerprint, algorithm family, packet version, creation/expiry, definition hash, revision and active/revoked state. It omits user IDs and packet contents.

HTTPS uses `POST .../pgp-keys` with `public_key` containing base64-encoded public bytes and the same metadata; `GET .../pgp-keys/ID/N` returns the sanitized view. Registration canonicalizes armor to public packet bytes before hashing. Replaying the same registration through CLI and HTTPS returns the original result. The request body remains bounded to 32 KiB, including JSON/base64 overhead.

Add this field to the existing [CSV intake definition](intake.md), using actual values returned at enrollment:

```json
"signature": {
  "key": {"id":"KEY_UUID","version":1,"hash":"EXACT_KEY_DEFINITION_SHA256"},
  "max_age_seconds":3600
}
```

`max_age_seconds` is optional; zero applies no additional age window. Key revocation, key expiry and a signature's own expiry still apply. PostgreSQL time supplies the current decision time. An expired, revoked or unavailable selected key prevents new policy activation and current checking/release. It cannot silently fall back to CSV-only intake. Omitting `signature` preserves the previous CSV policy encoding and scope.

## Attach, verify and approve

Find the actor-owned held file with `check-list`/`check-status`. Before its first check attempt, run:

```sh
freightctl check-signature --file-id FILE_ID --signature-file SIGNATURE \
  --data-sha256 EXACT_ACCEPTED_SHA256 --policy-hash EXACT_POLICY_SHA256 \
  --expected-revision CURRENT_CHECK_REVISION --idempotency-key KEY
```

Include ordinary scope/token/storage selectors. HTTPS provides `PUT .../checks/FILE_ID/signature` with the raw signature body, `Idempotency-Key`, `X-Data-SHA256`, `X-Policy-Hash` and `If-Check-Revision` headers. Attachment requires `write` and the original check owner. The artifact binds immutable source digest, policy, key definition and storage UUID. It is synced before its attachment event and receipt commit together. An uncertain/failed commit leaves inspectable orphan bytes; it does not expose an accepted signature. A different signature cannot overwrite an attachment. Correcting a rejected signature or source requires a new file revision.

Missing required signatures refuse `check-run` before spending an attempt. Attachment checks the packet shape and hash algorithm; it does not declare the signature valid. During `check-run`, verification reads the entire exact accepted source and the retained signature. A required scanner then reads that same immutable revision; CSV validation follows those checks. It checks primary and actual signing-subkey identity, cryptographic proof, binding signatures, revocation, time and source length/digest. A wrong signer, changed line ending or expired/aged signature cannot pass. A nonmatching signature produces `rejected/signature_invalid`; unavailable custody/state produces a failed attempt. No failed or unavailable check becomes a clean result.

The report records backend, primary/signer fingerprints, signature wire digest, hash/packet version, creation, verification and effective expiry times. The file stays held after a pass. `check-release` requires the exact file/policy/report hashes and revision; it re-verifies the actual source and signature, current key, policy and authority before atomic release/publication/receipt. Approval creates no external business acknowledgment. Ordinary approved delivery follows separately.

`GET .../checks/FILE_ID/signature` retrieves the bounded, hash-verified original artifact for the original authorized owner while its context remains current. Other actors and raw artifact IDs cannot retrieve it. Read-only reconciliation recognizes `verified_signature`, `signature_integrity_mismatch` and `missing_signature_bytes` under the existing byte/entry/time budgets. Raw signatures and file contents stay out of journals and Git.

## Rotation, revocation and persistence

Register a new version using the existing `key_id` and exact `expected_version`. Versions are immutable. Registration leaves previous versions active for explicit overlap; a policy freezes one version and hash. Changing a policy does not rebind old held jobs. Retire an old key explicitly with `pgp-key-revoke --pgp-key-id ID --version N --definition-hash HASH --expected-revision REV --idempotency-key KEY`, or `POST .../pgp-keys/ID/N/revoke` with that decision. Revocation is terminal for that version.

Current availability checks include the selected key and proof expiry. Revocation blocks checking/release and subsequent reads or delivery of its controlled revisions, including the next bounded read from an already opened file. Bytes already received cannot be recalled. Historical integrity-only files keep their original scope. Signature refresh, re-scan, retrospective policy, delegated approval, retention and recovery/rebind remain open.

Migration 11 adds partner-scoped `pgp_keys` and actor-bound `file_signatures`, both with forced row security and exact immutable event guards. The public key packet block is bounded public cryptographic configuration, like an SSH public identity; it contains no secret key or document payload. Public bytes are part of the definition hash and registration event. Signatures are durable filesystem artifacts with metadata references in PostgreSQL. SQL release and publication/delivery guards require the matching proof and active unexpired signer. Migration 12 adds one ciphertext relation; all thirty domain relations are checked live. The explicit `pgp_manage` grant is added only to new development administrators, bringing their default count to nineteen; existing account grants are preserved.

## Library boundary, limits and evidence

All OpenPGP library imports stay under `internal/crypto`; architecture tests enforce that boundary. Production verification uses [ProtonMail/go-crypto](https://github.com/ProtonMail/go-crypto), pinned to v1.5.2, package `openpgp/v2`, with Cloudflare CIRCL v1.6.3 transitively. Both use BSD-3-Clause licensing; their license files remain in the checksum-verified module cache. No OpenPGP operation imports the deprecated `golang.org/x/crypto/openpgp`, starts GnuPG, accesses a network or handles a private signing key. No FIPS, HSM or external custody certification is claimed.

Admission accepts at most 32 KiB wire / 16 KiB decoded packets, 64 definite-length packets, one primary, eight identities and eight subkeys. It rejects secret/compressed/literal/unknown packets, partial/indeterminate lengths, mixed armored blocks and multiple signatures before cryptographic parsing. The library performs cryptography; the local framing guard only bounds input. Key packet versions 4 and 6 are accepted. Algorithm admission permits RSA 3072–8192, Ed25519/Ed448, v4 Curve25519 EdDSA and supported NIST ECDSA; encryption-only ECDH/X25519/X448 subkeys may occur in a public block. Message signatures require SHA-256/384/512; weak self/message hashes are rejected. Admission is broader than the independently tested peer profiles.

Verification uses the existing two check slots, three-attempt budget, fenced 70-second database lease and bounded processing context. Source reads stream in at most 32 KiB pieces; no source-size buffer is allocated. These are implementation limits, not production throughput or resource qualification.

`scripts/prepare-pgp-fixture.py` creates synthetic independent [GnuPG](https://www.gnupg.org/documentation/manuals/gnupg/GPG-Examples.html) artifacts in a task-owned Linux aarch64 container: 128 MiB, one CPU, 64 PIDs, no network, read-only root and a 64 MiB temporary key home. GnuPG 2.4.9-r1 is installed in a locally built labeled image `freightctl-pgp-peer:2.4.9-r1` from immutable Alpine base `alpine@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6`; fixture execution resolves its image ID. Initial image acquisition/build needs connectivity. This fixture is a development prerequisite, not an offline product installer. Its empty `common.conf` selects a flat keyring; the application adds no SQLite or Redis. The fixture agent exists only inside its ephemeral container. Synthetic secret packets are retained only in protected ignored negative-test data.

Build that task-owned development image once from this repository root:

```sh
docker build --label "freightctl.workspace=$PWD" \
  --label freightctl.purpose=pgp-interoperability \
  --tag freightctl-pgp-peer:2.4.9-r1 - <<'DOCKERFILE'
FROM alpine@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache gnupg=2.4.9-r1
DOCKERFILE
```

The pinned package must be available from that base's repository; acquisition failure is a visible prerequisite failure. No image is published by this command. Runtime qualification records the resolved image, GnuPG version and package inventory.

`scripts/qualify-pgp.py` exercises CLI/HTTPS enrollment and idempotency, stock SFTP held intake/restart, missing and invalid signatures, exact release, independent receiver bytes, retrieval of the retained signature, independent GnuPG verification, revocation and explicit RSA policy rotation. Real PostgreSQL tests exercise RLS, immutable metadata, receipt rollback and revocation during an open read. GnuPG v4 Ed25519 signing-subkey and RSA3072/SHA256 profiles have independent evidence. V6 has library/unit coverage only. This macOS application plus Linux peer exercise does not qualify a native Linux server, other peers/algorithms, independent operator adoption, a complete journey or enterprise readiness. Local inference stays off.

## Explicit native macOS qualification peer

When another Docker peer cannot start, the macOS arm64 development host can use a separately acquired native GnuPG peer. This runs stock GnuPG, not the application's OpenPGP implementation. It creates synthetic keys in a new private scratch directory, exports only protected fixture artifacts, stops its own agents, and removes only its scratch directory. It never uses the owner's ordinary GnuPG home. Existing Docker peers and earlier fixture/evidence records remain available.

Acquire the [official Homebrew bottles](https://formulae.brew.sh/formula/gnupg) explicitly into the task cache. A bottle is a prebuilt program package. Its digest is a byte fingerprint; acquisition checks that fingerprint against the package manifest before extracting it. Homebrew may fetch build dependencies too; the extraction command uses only the declared runtime dependency closure. It does not install formulas, run post-install hooks, link programs globally or start services:

```sh
umask 077
mkdir -p .cache/freightctl-brew .private/freightctl-brew-tmp
HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 \
  HOMEBREW_CACHE="$PWD/.cache/freightctl-brew" \
  HOMEBREW_TEMP="$PWD/.private/freightctl-brew-tmp" \
  brew fetch --deps --force-bottle gnupg
python3 scripts/acquire-gnupg-native.py
export FREIGHTCTL_GNUPG_NATIVE_CONFIG="$PWD/.private/freightctl-gnupg-native.json"
python3 scripts/qualify-pgp-native.py
python3 scripts/qualify-foundation.py
```

Run at the repository root after the normal development setup. The acquisition manifest pins the actual bottle versions/digests, executable bytes and native library bytes. A later package update cannot silently replace an existing manifest or dependency cohort; select a new `--output` reference after reviewing acquisition. The current acquired peer is GnuPG 2.5.24 on macOS arm64. Cached binaries, library files, synthetic private keys and raw reports stay out of Git. These bottles are qualification tools, not part of a freightctl distribution or an offline installation bundle.

Native execution is an explicit profile choice. `FREIGHTCTL_GNUPG_NATIVE_CONFIG` selects a protected owner-only manifest, not an arbitrary executable from an imported document or model response. Each invocation verifies its binaries/libraries again. Without that selector the existing Docker profile remains the default; a failed native run never falls back to another peer and reports success.

A default-deny macOS sandbox allows the selected runtime/system reads, exact fixture inputs, exact output and its `.part` staging filename, and private scratch writes. Only scratch Unix sockets are permitted; IP networking is denied. Signal permission is restricted to processes in the same sandbox: the worker may stop its own children, and a refusal probe checks that it cannot signal the outside controller. GnuPG's explicit `--homedir`, empty `common.conf`, disabled autostart and manually supervised agents keep keyring selection local to the test. Standard GnuPG batch and machine status options are described in [the GnuPG manual](https://www.gnupg.org/documentation/manuals/gnupg/GPG-Configuration-Options.html). No permissive MDC, weak verification, fake application clock or signature-age override is added.

The parent samples the child process group's combined resident memory every 100 ms. A worker-side guard also checks its parent every 100 ms and kills only its own group if the controller dies; a regression kills the actual controller while its supervised GnuPG agent is alive. It terminates the group above 128 MiB, after 120 seconds, or on excessive output; it also verifies that the group is empty afterward. Abrupt controller death can retain protected scratch evidence; a lifecycle record identifies the exact group and directory for inspection. The crash regression waits for group exit and removes only its verified task scratch. This is a watchdog, not a kernel memory quota. Short peaks between samples, the observer's memory and OS costs are separate. Operations run serially; no kernel CPU quota is claimed for this native profile. The Docker profile retains its original kernel limits. The native constraints command uses a deliberately tiny budget with an ordinary sleeping interpreter to prove shutdown without allocating a large payload. It also tests a live IP listener, unrelated private reads/writes, data-volume aliases, modified library hashes and unsafe configuration permissions.

Both peers retain the original independent signature, source-digest, recipient, AES256/MDC and negative-ciphertext assertions. The native receiver adapter decrypts into private scratch because GnuPG can leave plaintext while returning BADMDC. It requires successful exit and authenticated status before copying in 64 KiB chunks to an exclusive staged result and linking a new output. BADMDC means the encrypted message failed its integrity check; plaintext must stay unaccepted even when the tool wrote bytes. Failed authentication produces no receiver result; an existing result is never overwritten. Message integrity is separate from the enrolled detached signature and from a business acknowledgment. These extra refusal assertions are exercised in the encrypted-delivery journey. Fresh signatures satisfy the existing one-hour application policy; an old fixture is never made fresh by editing its timestamp. The native peer does not load a model, ClamAV engine or standard scanner database. Application private signing/decryption, broader algorithm/peer/platform coverage, genuine malware detection and complete business outcomes remain separate required work.

The [combined signed/scanned exchange](signed-scanned-exchange.md) exercises this order with genuine ClamAV, separate exact release, recipient encryption, a receiver outage and restart, independent stock-SFTP/GnuPG verification and signed audit export. Its selected local profile does not establish general malware coverage or the complete customer journey.
