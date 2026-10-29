# freightctl status

- Updated: 2026-10-28
- Phase: Stage 1, locally tested custody and namespace foundations; full product goal active
- Workspace: /Users/shankar/Desktop/ctlplne-freightctl
- Commit identity: `imfeelingtheagi <288773099+imfeelingtheagi@users.noreply.github.com>` for author and committer
- Branch: local main; no new push authorized

## Current evidence

F001 in `docs/qualification/evidence/` identifies the exact source hashes, native binary digest, environment, commands and limits. Real PostgreSQL 16.15 tests cover forced tenant/partner row policies, runtime grants, concurrent idempotency, transactional rollback, orphan visibility/quotas, corrupt bytes, revocation during staging and blocked replay, clean migrations and v1 upgrade. Stock curl verifies a synthetic HTTPS upload/download, ranges, retries, isolation and retrieval after process restart. Unit/race, vet, architecture import checks and bounded name fuzzing pass.

F002 adds scoped read-only reconciliation through the same CLI/API service, with byte, entry, response and time budgets. Real filesystem/database tests cover missing/corrupt objects, unsafe entries, isolation, truncation, failed-hash accounting, cancellation and no domain mutations. Stock curl observed a partial upload, the harness killed its exact server process, and restart reported those unreferenced bytes without publishing them. Retrying created a separate accepted revision while preserving the partial object. This tests the staging crash boundary; sync/commit ambiguity and approved cleanup remain open.

F003 adds bounded signed audit snapshots from one PostgreSQL view, exact actor/resource evidence, current-authority rechecks and required preparation-journal persistence. Stock OpenSSL independently verifies CLI/HTTPS artifacts and rejects modified payloads, forged signatures, wrong trust keys/scopes and substituted embedded keys. Migration 3 bounds journal records. A reproduced live-policy gap is repaired by locking relations and checking forced row security within every scoped transaction. Prior database tampering, protected retention, full-estate export and stronger signing-key custody remain open.

F004 adds virtual folders, explicit account grants and mounted roots. Namespace changes, publication receipts and retained revision indexes commit with their exact events. Local tests exercise folder movement, modes, Unicode retries, page bounds and raw-ID denial across mounts. F005 adds the real bounded SFTP server and registered-key lifecycle. Stock OpenSSH sftp and modern scp exchange exact bytes with the same HTTPS namespace. Tests cover strict host trust, identity/mount/tenant/partner denial, malformed frames and handle limits, active key revocation, disconnect cleanup and restart after a staging crash. Client exit-status and prompt-revocation failures are repaired and rerun under their original budgets. Interrupted-session resume, outbound SFTP, enterprise peers and full journeys remain open.

F006 adds actor-private durable upload tickets shared by CLI, HTTPS and stock SFTP. Sealed chunks and exact progress receipts survive process restart; the final path remains unavailable until full verification and publication commit. Reproduced wrong-store and folder-revocation failures are repaired with storage UUID and parent/revision checks. Complete-prefix recovery has an explicit bound-target completion action. Retention/cleanup/rebinding, browser UX, larger-file and distributed-storage gates remain open.

F007 adds locally approved outbound SFTP intents. A separate stock OpenSSH receiver and independent stock client verify exact bytes; two workers compete for one intent, an actual staging-worker kill recovers under a new fence, and a failed local receipt commit after remote publication remains ambiguous until read-only observation. Source, authority, storage identity and pinned receiver trust bind every attempt. The profile requires file-sync and atomic hardlink extensions; it does not establish business acceptance. Versioned reusable connections, typed multi-step workflows, API/browser approval, unattended scheduling, remote retention and production networks remain open.

F008 adds registered connection versions and shared CLI/HTTPS typed workflow validation, offline preview, draft/diff/approval/revocation, frozen run creation and ordered dispatch. All run intents commit atomically; a stable dispatch key cannot advance the next step after restart or a lost reply. Native recovery covers remote success with a failed receipt commit and delivery receipts with a failed run projection. Current authority and whole-run connection revocation apply to direct workers too. A zero-attempt status error and an artificial short-lease fixture race are repaired without changing production limits. Broader task types, scheduling, browser UI and private-model planning/diagnosis remain open.

The original fixture failure is repaired without relaxing private-directory permissions. Regression tests found and repaired projection/event binding, disabled-RLS startup and stale replay authority. Govulncheck found two reachable text-library vulnerabilities; upgrading to x/text v0.41.0 produces zero findings on the native source configuration. The current SSH build has one module advisory for unimported x/crypto/OpenPGP packages, with no affected package in the native dependency inventory; the advisory is retained. Native logs and secrets stay ignored; safe manifests record scanner coverage and limits.

This proves a narrow service-account custody exercise. It does not qualify a complete customer journey, malware scanning, signatures, downstream business receipt, complete SFTP parity, browser onboarding, large-file/browser resume qualification, AI, HA, performance, offline installation or a release. All 83 baseline rows and 12 complete journeys remain open.

## Repository and readiness

The owner-requested recreation is complete. New local history starts at `e1eab1a`. The recreated private GitHub repository has ID `1437631520` and default branch main. The latest read-only observation advertises main `b48fe6bd0720b99b6489a051945bebaf5ee74527`; local main has advanced. All nine commits inspected before F008 use the required identity for both author and committer. The CLI and connector identify the owner as `imfeelingtheagi` (ID `288773099`). Implementation, credentials and task-owned PostgreSQL data were preserved. This verification performed no push, deletion or further recreation; the origin already matches the requested repository.

- Assisted design-partner deployment: Not qualified.
- Ordinary operator adoption: Not qualified.
- Enterprise or release qualification: Not qualified.

## Next work

Finish approved custody recovery, protected audit retention and larger exports, and remaining crash boundaries; finish browser/ordinary-operator resume and onboarding, the broader outbound profile and client qualification. Continue through broader typed workflow tasks, fair scheduling and the first bounded private-model proposal/diagnosis against these real records. See `remaining.json` for the full mandatory work and concrete external dependencies. No unavailable installation, platform, account, model or reference hardware is counted as a pass.
