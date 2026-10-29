# Review a new checked revision

A check report describes one immutable accepted file under one exact policy. Changing the policy does not make that old report current. A re-check request creates a linked revision with the same bytes and a fresh check record. The original receipt, verdict, release proof and queued jobs keep their original file IDs.

The current surface requires a root-mounted account with `admin`, `read`, `write`, `intake_manage`, `check_run` and `check_release`. It accepts only files originally accepted by that account. It is not a delegated exception or a way to waive a detection. Existing accounts receive no additional grants.

In **Intake checks**, enter the source revision, an optional target path, signature handling and a reason. Preview shows the exact source digest and length, original check, selected policy and current authority. Compare the original and selected policy definitions before saving. Saving records the immutable request and three staging identity pairs; it reads no payload bytes. Open its private history, review its fingerprint and approve separately. Then review and create the held copy. Nothing is published by these steps.

Open the resulting checked revision. Attach a new detached signature if selected, run the ordinary required checks, and review the resulting exact report before a separate release. An explicitly reused signature is copied from the exact retained artifact and verified again; no old clean verdict is reused. A target can be absent or point to the original source. The later release conditionally changes that exact target. An unrelated file, changed parent or changed target refuses the operation.

A live original check worker blocks preview, approval and copying. A changed policy, signer/scanner profile, protected scanner configuration, storage identity, account authority or namespace binding requires a fresh review. The selected policy cannot remove an originally required signature or scanner, or loosen the original signature age. Original failed, detected, expired and retired-policy files do not become available because a child exists. Original queued jobs require their own future recovery decision; they never follow the new revision automatically.

The CLI uses the same commands and authority. Supply the normal protected `--dsn-file`, `--token-file`, `--tenant`, `--partner` and existing `--storage` references to each command:

```text
check-recheck-preview --file-id SOURCE --request-file options.json
check-recheck-propose --file-id SOURCE --request-file reviewed-plan.json --idempotency-key SAVE_KEY
check-recheck-list --file-id SOURCE --check-limit 20
check-recheck-status --recheck-id REQUEST
check-recheck-decide --recheck-id REQUEST --request-file approval.json --idempotency-key APPROVE_KEY
check-recheck-copy --recheck-id REQUEST --idempotency-key COPY_KEY
```

`options.json` contains `target_path`, `signature_mode` (`not_required`, `reuse_exact` or `require_new`) and a short `reason`. Save the returned `plan` unchanged inside `{"plan": ...}` for `reviewed-plan.json`. Approval contains `operation: "approve"`, the returned `definition_hash` and `expected_revision`. Cancellation uses `operation: "cancel"` and is terminal. A changed request needs a distinct idempotency key. Reasons and private plans are sensitive metadata; keep local request files protected. Ordinary event/audit feeds redact their payloads.

The corresponding partner-scoped HTTPS endpoints are `POST /checks/{source}/recheck-preview`, `POST /checks/{source}/rechecks`, `GET /checks/{source}/rechecks`, `GET /rechecks/{request}`, `POST /rechecks/{request}/decide` and `POST /rechecks/{request}/copy`. Copy has an empty body. Mutations use `Idempotency-Key`; browser mutations also require the existing same-origin session and CSRF proof. History uses bounded `limit` and `after` pagination.

If a response is lost, retry the same reviewed command with its original key or reload private history. A recovered receipt describes the earlier operation; it does not certify current availability. The browser preserves a save operation key and plan fingerprint in session storage, without storing the plan or credentials there. Approval and copy keys bind the session, request hash and reviewed revision. After reconnecting, inspect history and review current state.

Copy has two separate PostgreSQL admission slots and a 60-second operation context. Existing storage, entry and pending-check limits still apply. A transaction holds the approved intent while bounded local copy/sync runs; it makes no network or model call. Complete reserved objects can be recovered only after digest, length, mode and persistence checks. Interrupted partial objects remain untouched. A retry can use another of the three reviewed staging pairs. If all are exhausted, cancel and prepare a fresh request. Retained bytes still consume storage quota. Reconciliation observes unreferenced bytes and never silently deletes or adopts them. General orphan disposition, retention/legal-hold cleanup, remote storage and host I/O failure recovery remain separate work.

This mechanism does not load a model. Genuine scanner qualification remains limited to the separately recorded runtime evidence and the owner's 4 GiB/one-CPU allowance. Local inference remains off. See [the architecture](architecture/0013-file-rechecks.md) and the qualification records for measured coverage and open product requirements.
