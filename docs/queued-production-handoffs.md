# Preserve queued work after key or credential rotation

A queued handoff replaces an untouched production run with one separately identified successor. It keeps the original dispatch definition, accepted file and audit history. The operator reviews the old and new bindings, approves that exact definition, then executes a metadata transaction that cancels the old intent and queues its successor together. Separate ordinary execution sends the successor's bytes.

The default `untouched-production-handoff-v1` profile requires zero delivery attempts, zero fence, no lease, no ciphertext artifact and a still-queued delivery intent. A dispatcher may already have prepared its workflow receipt; it cannot claim or send that cancelled intent later. Any recorded attempt, retry, publication or ambiguous outcome blocks this default profile. A failed connection is still an attempt. Inspect the original outcome; a new key does not prove that resubmission is safe.

The separate [pre-publication recovery profile](prepublication-recovery.md) requires a complete bounded immutable journal proving that publication never started. It can preserve quiescent retry/blocked work or an expired staging lease, including retained ciphertext/remote partials. It makes no receiver business-acceptance claim. Publishing, ambiguous or live-leased work remains ineligible. Downstream systems must ignore reserved staging names; otherwise reconcile their business outcome first.

For an expired publication or ambiguous SFTP outcome, a separately [reviewed read-only receipt observation](receipt-observations.md) can inspect the exact original final bytes using current tested SSH trust. It preserves original execution and records recovered integrity evidence without a replacement transfer. Missing or different bytes remain unresolved and never grant resend authority.

## Operator sequence

1. Inspect the original production run and keep its UUID, immutable production-definition hash, accepted source and current delivery state. Stop scheduling work against the old activation as appropriate.
2. Register the replacement SSH host/client trust or recipient key through normal protected references. Test the exact registered connection, draft and approve the workflow revision, perform its pre-contact test exchange, then approve and activate a new exact production release. Credential rotation uses the existing second-account-manager policy; an operator cannot rotate their own account through this administrative command. The author identity remains the same while authority revisions change.
3. Retain the original accepted file when its current policy permits. If current policy requires a new checked revision, use the governed re-check workflow: preserve identical bytes, make a linked revision, run fresh checks and separately release it. An unrelated new raw upload, even with the same digest, cannot substitute for that lineage.
4. Open the saved onboarding draft's **Queued work after rotation** section. Inspect/select the original production run to prefill its ID/hash when available. Supply the tested target release UUID, exact activation revision/hash and accepted replacement file UUID. Choose **Preview queued handoff**.
5. Review the original run/delivery revisions, zero attempts/fence, original and target activation, authority change, accepted file identities/digests/policies, SSH host/client fingerprints and encryption recipient. The plan, requirement, receiver address/account/directory/filename, workflow family and encryption mode/profile must remain the same. A changed requirement or recipient path requires a different governed decision; this operation cannot silently alter it.
6. Choose **Save reviewed handoff**. This creates a private proposal without cancellation, replacement run or receiver contact. Choose **Approve handoff** separately and review the same definition hash. Approval does not reserve a worker or remote state.
7. Choose **Execute approved handoff**. The server rechecks the exact source and current tested target while holding the source run and delivery row. If an attempt or binding change won the race, it refuses. Otherwise source cancellation, successor run/delivery intent, immutable production link, completed handoff, events and retry receipt commit in one PostgreSQL transaction. A failure rolls back both sides and preserves the original queue entry.
8. Inspect private handoff history after reload. A completed record identifies its replacement run. Choose **Inspect replacement run**, then **Execute replacement transfer** separately. Inspect its actual receipt and source hash before recovery. Lost responses are recovered using the original reviewed operation key or exact durable run state; they do not prove that no bytes arrived.

## What remains unchanged and what is renewed

The source's immutable dispatch, source metadata, original acceptance and historical receipts keep their meanings. Its mutable run/intent projections become `cancelled` with an explicit handoff reference. The successor gets a fresh run/delivery identity and the exact reviewed target activation, workflow, source policy, authority and protected key references. One source run can have only one completed handoff successor. A later handoff uses that successor as its own explicit source; it cannot rewrite the first link.

SSH and recipient fingerprints may change only through the new tested and approved target. Encryption cannot be removed or have its profile changed through this handoff. Bytes and length must remain identical. A changed accepted file UUID requires a completed governed re-check link from the original file and current release of the new checked revision. No old signature, scanner verdict, ciphertext or business acceptance is invented or carried over as a fresh result.

Suspended or revoked old bindings can remain inspectable. The target must be a current active tested release for the same exact saved plan and requirement. Its storage and namespace stay bound. Any later target suspension, revocation or authority/policy change also gates ordinary successor execution. The original prepared worker cannot turn the cancelled source back into a valid queued intent.

## API and CLI

All routes use the ordinary tenant/partner prefix, TLS, scoped authentication and browser CSRF controls. Preview/read use the existing onboarding-management, connection-management, read and workflow permissions. Proposing/cancelling requires `workflow_manage`; approval requires `workflow_approve`; metadata execution requires `workflow_execute` and `deliver`. No new or default grant is added. Records and retry receipts remain author-private; ordinary event feeds and signed audit projections redact their private payloads.

| Action | API suffix | CLI command |
| --- | --- | --- |
| Preview exact before/after | `POST /onboarding-handoffs/preview` | `partner-onboarding-handoff-preview` |
| Save proposal | `POST /onboarding-handoffs` | `partner-onboarding-handoff-propose` |
| Inspect handoff | `GET /onboarding-handoffs/HANDOFF_UUID` | `partner-onboarding-handoff-status` |
| Private paginated history | `GET /onboarding-plans/PLAN_UUID/handoffs` | `partner-onboarding-handoff-list` |
| Approve/cancel/execute metadata | `POST /onboarding-handoffs/HANDOFF_UUID/{approve,cancel,execute}` | `partner-onboarding-handoff-decide` |
| Inspect successor | `GET /onboarding-production/RUN_UUID` | `partner-onboarding-production-status` |
| Execute successor transfer | `POST /workflow-runs/RUN_UUID/work` | `workflow-work` |

Preview accepts `{source_run_id, source_hash, target_release: {id, revision, hash}, file_id}`. Proposal accepts `{definition: PREVIEW_DEFINITION}`. Decisions accept `{definition_hash, expected_revision}`. Mutations require an `Idempotency-Key`; repeated original receipts never repeat their effects. Request decoding retains existing 32 KiB/depth/token/duplicate-key bounds and ten-second service deadlines. History is bounded to 1–100 summaries per page. Queue handoff frees the original queue slot inside the same transaction before applying ordinary replacement admission; it does not introduce extra unbounded processing slots.

CLI uses protected `--dsn-file`, `--token-file`, `--tenant`, `--partner`, `--storage` and `--request-file` references. Use `--onboarding-handoff-id` and `--onboarding-handoff-action` for decisions, `--onboarding-id` for history, `--onboarding-after`/`--onboarding-limit` for pagination, and `--idempotency-key` for mutation recovery. Successor status uses `--run-id`. Raw credentials and private keys never belong in these request definitions.

Migration 24 adds one actor-private forced-RLS relation, for 48 domain tables. It keeps existing grants/data, enforces immutable before/after definitions and one completed successor per source, and rejects handoff-labelled cancellations unless their approved completed successor is committed atomically. Apply it through normal `freightctl init`.

## Qualification

Targeted real PostgreSQL/race tests exercise prepared-worker fencing, exact-byte/source preservation, eight-way completion replay, original receipt recovery, atomic rollback and deferred cancellation guards, attempted/unlinked-source refusal, stale bindings, private history and client-key/credential rotation through the existing manager policy. Seeded coordinator observations establish these transaction guards, not interoperability.

The native `--handoffs` journey retains earlier onboarding tests and uses real stock SFTP, native Chromium and independent authenticated GnuPG decryption. It prepares an actual workflow while crypto capacity is unavailable, observes zero delivery attempts, rotates synthetic SSH host/client, recipient and operator credentials, derives a linked checked revision, runs fresh checks/separate release, and exercises ordinary handoff and successor interfaces. [F031](qualification/evidence/F031-queued-production-handoffs.json) passes 249 steps in 47.662 seconds on 292 unchanged inputs, with 17 selected WCAG states across earlier and new paths. Browser proposal/approval/metadata-execution response loss recovers the original keys and one successor; reload and lost completed-transfer response recover its exact receipt. Independent stock SFTP/new-recipient decryption proves unchanged bytes, while the old client and old recipient fail. The first late atomicity-observer failure is retained; its check now runs before ordinary transfer changes the successor projection. This path does not load a scanner or model.

Six new real PostgreSQL/race cases pass within 24 focused workflow tests (21 database cases and three shared Go/browser goldens). Three real migration/delivery regressions, six affected Go unit/race packages, 34 frontend contracts and typecheck/build/reproducible-assets checks also pass. Normal init upgrades the retained database from schema 23 to 24, preserving event/file/credential counts and its non-bypass runtime role. The exact task PostgreSQL returns to its original stopped state with its volume and configured 512 MiB/one CPU preserved. The scanner remains stopped. These are selected assisted same-host results, not complete J05 or production qualification.

```sh
PYTHONDONTWRITEBYTECODE=1 \
FREIGHTCTL_GNUPG_NATIVE_CONFIG="$PWD/.private/freightctl-gnupg-native.json" \
python3 scripts/qualify-onboarding-exchange.py \
  --postgres-container-id EXACT_TASK_POSTGRESQL_CONTAINER_ID \
  --handoffs
```

This uses a disposable database on the exact existing task-owned PostgreSQL and loopback fixture peers. It changes only task-owned receiver trust/credentials and owns only its fixture processes/database. Retained volumes, model files and protected evidence remain preserved. The full replay remains owner-deferred. Active/publication/ambiguous key rotation, receiver business idempotency contracts, general algorithms/protocols/platforms, cross-person delegation, environment promotion, independent adoption and complete J05/product qualification remain open.
