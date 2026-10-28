# freightctl status

- Updated: 2026-10-28
- Phase: Stage 1, locally tested custody foundation; full product goal active
- Workspace: /Users/shankar/Desktop/ctlplne-freightctl
- Commit identity: `imfeelingtheagi <288773099+imfeelingtheagi@users.noreply.github.com>` for author and committer
- Branch: local main; no push authorized

## Current evidence

F001 in `docs/qualification/evidence/` identifies the exact source hashes, native binary digest, environment, commands and limits. Real PostgreSQL 16.15 tests cover forced tenant/partner row policies, runtime grants, concurrent idempotency, transactional rollback, orphan visibility/quotas, corrupt bytes, revocation during staging and blocked replay, clean migrations and v1 upgrade. Stock curl verifies a synthetic HTTPS upload/download, ranges, retries, isolation and retrieval after process restart. Unit/race, vet, architecture import checks and bounded name fuzzing pass.

F002 adds scoped read-only reconciliation through the same CLI/API service, with byte, entry, response and time budgets. Real filesystem/database tests cover missing/corrupt objects, unsafe entries, isolation, truncation, failed-hash accounting, cancellation and no domain mutations. Stock curl observed a partial upload, the harness killed its exact server process, and restart reported those unreferenced bytes without publishing them. Retrying created a separate accepted revision while preserving the partial object. This tests the staging crash boundary; sync/commit ambiguity and approved cleanup remain open.

The original fixture failure is repaired without relaxing private-directory permissions. Regression tests found and repaired projection/event binding, disabled-RLS startup and stale replay authority. Govulncheck found two reachable text-library vulnerabilities; upgrading to x/text v0.41.0 produces zero findings on the native source configuration. Native logs and secrets stay ignored; safe manifests record scanner coverage and limits.

This proves a narrow service-account custody exercise. It does not qualify a complete customer journey, malware scanning, signatures, downstream business receipt, SFTP, browser onboarding, upload resume, AI, HA, performance, offline installation or a release. All 83 baseline rows and 12 complete journeys remain open.

## Repository and readiness

The owner-requested recreation is complete. New local history starts at `e1eab1a`. The recreated private GitHub repository has ID `1437631520`, default branch main and no published refs at last verification. Implementation, credentials and task-owned PostgreSQL data were preserved. Nothing from this chat has been pushed.

- Assisted design-partner deployment: Not qualified.
- Ordinary operator adoption: Not qualified.
- Enterprise or release qualification: Not qualified.

## Next work

Finish approved custody recovery, independently verifiable audit export and remaining crash boundaries; add real SFTP exchange and first-admin/partner onboarding. Continue through typed workflow execution and bounded private AI. See `remaining.json` for the full mandatory work and concrete external dependencies. No unavailable installation, platform, account, model or reference hardware is counted as a pass.
