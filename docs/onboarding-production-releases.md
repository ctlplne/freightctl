# Approve and activate tested onboarding releases

A production release binds every saved requirement to a completed pre-contact test and exact receipt snapshot. Saving a proposal records those references. Approval accepts that exact definition. Activation separately enables its explicit production dispatch route. Queueing a production dispatch records the activation revision, source file, workflow and receiver before contact. Only separate execution sends bytes.

These controls govern the **Production releases** route. Existing ordinary approved manual workflows remain available for their existing jobs. Activation does not deploy a server, change permissions, enroll a credential, start a model or send a file. The first profile, `sftp-outbound-production-v1`, covers saved outbound SFTP requirements using the current one-step test profile. Every requirement must have one successful test; unsupported requirements and missing business receipts block the release rather than disappearing from it.

## Operator sequence

1. Save the complete partner requirements, responsible contacts and receiver agreement. Review free-text obligations yourself; the engine does not infer business acceptance from those words.
2. Complete a [recorded test exchange](onboarding-test-exchanges.md) for each requirement. Its exact saved plan, probe, approved workflow, receiver, source, storage and authority must remain current. Inspect the strongest receipt. Remote file integrity is not downstream business acceptance.
3. In the saved draft, open **Production releases**. Enter one completed test UUID for each requirement, then **Preview release proposal**. Review every receiver, filename, host/client fingerprint, optional encryption recipient, source digest and required receipt. Preview makes no contact.
4. Choose **Save release proposal**. It starts as `proposed`, with a private original-key receipt. It grants no production execution. If the response is lost, retry the same reviewed command/key; inspect history after reload before creating another proposal.
5. Inspect the proposal and choose **Approve release**. Review the exact definition hash and revision, then confirm. The engine recomputes all test/receipt bindings in the same scoped transaction before recording approval. It stays inactive.
6. Choose **Activate release** separately and confirm the exact approved revision. At most one stored active release exists for this actor and plan. Suspend or revoke an existing active release before promoting another one. These controls use existing workflow approval/execution grants; this first profile is actor-private and does not implement cross-person approval delegation.
7. Under the active release, choose a requirement and accepted production file. **Preview production dispatch** freezes the exact accepted source revision/hash/policy, tested workflow, readable receiver/encryption effect, storage, authority and activation revision. **Queue reviewed production run** atomically commits an ordinary run/delivery intent, immutable production link, events and retry receipt. This still makes no receiver contact.
8. Use **Execute production run** separately. Inspect private production history after reload, including the exact run, source digest, activation revision, worker state, attempt count and observation code. Use its ordinary workflow and recorded review interfaces for complete receipt interpretation and recovery. A lost response does not prove that no bytes arrived; recover the same run rather than submitting the file again.

## Suspension, reactivation and changes

**Suspend release** blocks new production attempts through the workflow worker, direct delivery worker and SQL effect transitions. Already sent bytes cannot be recalled. Historical receipts remain evidence of what happened. Suspension and revocation remain available to a currently authorized operator even when the release's saved authority or evidence is stale.

Reactivation rechecks the unchanged approved definition and creates a new activation revision. Old queued runs keep their original revision and stay blocked. They cannot silently adopt the new activation. Inspect/cancel or reconcile the original run before making any new submission, especially if it has an ambiguous outcome. This profile does not yet implement a reviewed queued-run rebind or zero-loss key rotation.

Changed requirements, revoked connections/workflows/recipient keys, stale permissions/authority, inaccessible checked source or changed protected scanner configuration make bindings stale. A stored state of `active` then has `current_bindings: false` and `production_active: false`. Historical evidence and approvals keep their original meanings. Build and test a new exact release when security meaning changes; changing a source/recipient does not update an old approval.

## API and CLI

Routes use the existing `/v1/tenants/{tenant}/partners/{partner}` prefix, TLS, scoped authorization and ordinary browser CSRF checks. Read/preview requires root onboarding/account management, connection management, read and an existing workflow role. Proposing additionally requires `workflow_manage`; approval/revocation requires `workflow_approve`; activation/suspension and production queueing require `workflow_execute` and `deliver`. No new or default grant is added. Only the author can inspect these release/dispatch records; ordinary event feeds and signed audit snapshots redact their private payloads.

| Action | API suffix | CLI |
| --- | --- | --- |
| Preview complete evidence | `POST /onboarding-releases/preview` | `partner-onboarding-release-preview` |
| Save proposal | `POST /onboarding-releases` | `partner-onboarding-release-propose` |
| Inspect release | `GET /onboarding-releases/RELEASE_UUID` | `partner-onboarding-release-status` |
| Private release history | `GET /onboarding-plans/PLAN_UUID/releases` | `partner-onboarding-release-list` |
| Review lifecycle action | `POST /onboarding-releases/RELEASE_UUID/{approve,activate,suspend,revoke}` | `partner-onboarding-release-decide` |
| Preview production source/effects | `POST /onboarding-releases/RELEASE_UUID/production-preview` | `partner-onboarding-production-preview` |
| Queue production run | `POST /onboarding-production` | `partner-onboarding-production-start` |
| Inspect exact production run | `GET /onboarding-production/RUN_UUID` | `partner-onboarding-production-status` |
| Private production history | `GET /onboarding-releases/RELEASE_UUID/runs` | `partner-onboarding-production-list` |
| Execute separately | `POST /workflow-runs/RUN_UUID/work` | `workflow-work` |

Release preview accepts `{plan: {id, version, hash}, test_ids: [UUID, ...], expected_authority_revision}`. Proposal accepts `{selection: PREVIEW_SELECTION, definition_hash: PREVIEW_HASH}`. Lifecycle commands accept `{definition_hash, expected_revision}`. Production preview accepts those lifecycle selectors plus `requirement_id` and `file_id`; production start accepts `{definition: PRODUCTION_PREVIEW_DEFINITION}`. Mutations require an `Idempotency-Key`. Each original receipt is historical and private; replay never repeats its effects. Inspect current state before a later action.

CLI commands use protected `--dsn-file`, `--token-file`, `--tenant`, `--partner`, `--storage` and `--request-file` references. Use `--onboarding-release-id` for a release, `--onboarding-id` for plan history, `--onboarding-release-action` for lifecycle actions and `--run-id` for production status. History uses `--onboarding-after` and `--onboarding-limit` (1–100). Mutation keys use `--idempotency-key`. Credentials and private keys stay behind references.

Requests retain existing 32 KiB/depth/token/duplicate-key limits and ten-second service deadlines. Definitions support all 64 saved requirements within the existing event budget, using compact immutable proof references; readable effects are resolved from their hashed tests. Queueing uses ordinary bounded delivery admission, worker slots, leases, fencing and source checks. The browser independently reconstructs the Go-compatible definition hash and binds readable details to their tests. Models grant no authority and remain unnecessary for this path.

Migration 23 adds actor-private forced-RLS release and immutable dispatch relations, for **47 domain tables**, preserving existing grants, runs and test records. Apply it with ordinary `freightctl init`; no history reset is needed.

## Qualification scope

The new targeted PostgreSQL/race cases exercise lifecycle ordering, original-key concurrency, missing requirements/business receipts, stale plans, immutable SQL, atomic receipt rollback, private history, permission removal, redacted audit and suspension through ordinary/direct/SQL workers. Their seeded coordinator observations qualify transaction guards rather than a network peer.

The native `--releases` journey retains the earlier onboarding tests and adds actual probes, safe plaintext/encrypted test exchanges, complete evidence review, separate approval/activation, production queue/execution, lost committed responses, reload, suspension/reactivation and stale-binding refusal. Independent stock SFTP and authenticated GnuPG decryption verify actual receiver bytes. The first empty queued-observation browser failure and original sources are retained. The final [F030 journey](qualification/evidence/F030-onboarding-production-releases.json) passes 170 steps in 43.622 seconds on 279 unchanged inputs, with 12 selected WCAG states across the retained and new browser paths. This uses synthetic 73-byte data; full J05, independent adoption, all whole baseline rows/journeys and production/platform qualification remain open.

```sh
PYTHONDONTWRITEBYTECODE=1 \
FREIGHTCTL_GNUPG_NATIVE_CONFIG="$PWD/.private/freightctl-gnupg-native.json" \
python3 scripts/qualify-onboarding-exchange.py \
  --postgres-container-id EXACT_TASK_POSTGRESQL_CONTAINER_ID \
  --releases
```

This uses a fresh disposable database on the exact existing task-owned PostgreSQL prerequisite and loopback HTTPS/stock SFTP/native Chromium. It owns only its fixture processes and database; it does not manage shared Docker lifecycle. PostgreSQL retains its configured 512 MiB/one CPU; native crypto retains its sampled 128 MiB child-family watchdog with observer/OS costs separate. No scanner or model is loaded. The owner-deferred complete replay remains pending. Independent adoption, environment separation/promotion, cross-person delegation, queued-work key lifecycle, broader protocols/peers/platforms and the full J05/product gates remain open.
