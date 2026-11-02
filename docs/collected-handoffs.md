# Replace untouched collected work with a reviewed successor

A collected input retains its original job, producer manifest, local file and first run as immutable history. Editing the workflow or enrolling a replacement key does not change that run. A handoff is a separate recorded decision: cancel its untouched delivery intents and create one successor using a specifically approved workflow revision and the same original source facts.

The current `untouched-collected-handoff-v1` profile supports schema-2 collected runs whose intents are all queued, with zero attempts, no lease or fence and no prepared ciphertext. It can replace a run whose routing decision or recipient key was revoked. Its target must be another approved revision in the same workflow family, with the same collection source and current recipient/key/connection authority. The original collection cutoff, calendar, file checks, sibling hold, namespace access, storage identity and actor authority still apply. A handoff does not extend a deadline or restore revoked source authority.

For a claimed, attempted, partial, ambiguous or already encrypted effect, this profile refuses replacement. An existing receiver copy cannot be recalled by changing local records. Governed recovery of those outcomes, rechecked child files, changed source/operator authority, schema-1 work and expired collections remain required work. This profile does not narrow the full GOAL.md contract.

## Review, approve and execute

1. Inspect the original collection and run. Select the exact owned input and source run. For a later rotation, select the completed handoff's successor as the next source; the original input assignment remains unchanged.
2. Enroll the intended replacement key or connection through its ordinary lifecycle, and separately approve the exact target workflow revision. Inspect its destination, host identity, recipient fingerprint, filename and encryption profile. Enrollment and workflow approval alone grant no permission to replace existing work.
3. Request the handoff preview. It contains the original source run/plan, every old intent and revision, the target workflow reference and an independently compiled target plan. Original producer facts select the branches; callers cannot submit invented facts or recipient choices. Preview makes no external contact.
4. Propose the exact preview hash. A separate `approve` command records consent for that immutable definition under the current authority revision. Neither proposal nor approval cancels work or reserves a worker lease.
5. Execute the exact approved handoff revision. The service rechecks authority, state, checks and cutoff under database locks. One transaction cancels every untouched old intent, cancels the old run, creates the exact successor and its ordinary intents, completes the handoff link and records the original request's receipt. A failure rolls all of it back.

The successor follows ordinary worker checks and any independent dispatch-review policy. Handoff approval is not a substitute for the receiver's configured consent. Creating a successor does not send bytes, encrypt a file or establish transport or business acceptance. The new delivery's generated remote name is distinct from the cancelled intent's name.

Approval can become stale while a worker claims the old intent. Execution then refuses; it cannot cancel that worker's effect. Withdrawal of a stale proposal only changes the proposal record. It does not reverse an executed handoff or alter a receiver.

## API and CLI

Use the ordinary authenticated tenant/partner prefix, followed by `/workflow-collections/{collection}/handoffs`:

| Request | Behavior |
| --- | --- |
| `POST /preview` | Read-only preview from the selection below. |
| `POST /proposals` | Body: `selection` plus the preview's `definition_hash`. |
| `POST /{handoff}/approve`, `/cancel`, `/execute` | Body: exact `definition_hash` and `expected_revision`. |
| `GET /{handoff}` | Actor-private definition, state and current-binding indication. |
| `GET ?after={UUID}&limit=20` | Actor-private history; maximum 100 records per page. |
| `GET /receipts/{original-key}/result` | Read the original command receipt without retrying a mutation. |

Each mutation requires its own `Idempotency-Key`. An identical replay returns the original receipt; a key with changed meaning is rejected. After a lost response, use the saved original key or the read-only receipt endpoint before starting a different operation. Historical receipt reads grant no execution authority. History, status, cancellation and receipt reads do not require opening a payload store.

The selection is bounded metadata, not a supplied execution plan:

```json
{
  "input_id": "exact-owned-input-UUID",
  "source_run_id": "exact-source-run-UUID",
  "workflow": {"id": "same-workflow-family-UUID", "version": 2, "hash": "exact-approved-workflow-SHA256"},
  "expected_authority_revision": 1
}
```

The CLI exposes `workflow-collection-handoff-preview`, `-propose`, `-approve`, `-cancel`, `-execute`, `-status`, `-list` and `-receipt`. Supply `--collection-id` and ordinary protected `--dsn-file`, `--token-file`, tenant/partner and `--storage` references. Use `--collection-handoff-id` for an existing handoff, `--request-file` for the corresponding selection/proposal/decision, and `--idempotency-key` for mutations or receipt lookup. History uses `--collection-after` and `--collection-limit`. Keep saved requests and receipts in protected `.private` files. The native CLI test replays an executed command and reads history/receipts with an intentionally unavailable storage path.

## Persistence and qualification boundary

Migration 034 adds the tenant/partner/actor-scoped handoff journal projection with forced row security. PostgreSQL independently reconstructs each eligible definition from durable rows, recompiles the target plan and checks its exact hash. Deferred constraints reject a cancelled source without its completed handoff and exact successor. Existing run/step/source/routing guards remain in force. The original `workflow_collection_inputs.run_id` is never reassigned; completed links explain subsequent replacements.

Migration 035 adds an index for completed links by input. Collection status returns optional `replacements` metadata: original job/input/run, latest completed successor, last source run and handoff. One SQL snapshot finds the leaf of each completed chain; proposed, approved and withdrawn links cannot appear as current work. A later collection that recognizes the same original input sees the original job's latest completed successor. The input row itself remains unchanged. This view grants no execution authority.

Private proposals, command receipts and handoff cancellation observations are redacted to exact source-payload digests in ordinary event feeds and audit exports. The protected journal retains the originals.

F052 binds the engine candidate `5535b7d` to passing source/security, both full native Linux PostgreSQL/race suites (545 case/subcase pass records each, zero skips/failures), eight fuzz targets, existing stock-peer regressions and both synthetic schema-34 metadata restores. These stock cases predate the handoff browser path.

F053 adds the successor view and browser controls with selected actual ARM PostgreSQL/race and independent browser contract evidence. Native x86 `handoff-routing` CI is prepared to exercise the full browser and encrypted receiver path; it has no passing claim until the candidate actually runs. Broader recovery profiles and all whole product journeys remain open.

## Browser operation and interrupted responses

Inspect an assigned collection and use **Replace untouched collected work**. Select the input and an approved workflow version, preview, then inspect both plans and recipient catalogs. The review includes SSH accounts, pinned hosts, client public-key fingerprints, OpenPGP recipients, exact file facts and old intent revisions. Check the fingerprint-specific review box before proposing. Proposal, approval and execution each have a separate confirmation; withdrawal changes only the pending handoff.

Only an opaque operation key and scoped request fingerprint enter browser session storage. After a lost response, keep the confirmation open to retry the same key. After reloading, inspect the record in handoff history and choose **Look up saved … handoff receipt**. That GET reads the original receipt without retrying a mutation or depending on current execution bindings. If storage is unavailable, the interface explains that the open review retains the key only in memory. A confirmed command clears its saved key.

After completion, **Inspect downstream run** follows the latest completed successor. **Inspect original run** retains the cancelled run's evidence. The sending confirmation uses the successor's validated run ID, plan and recipient catalog; it still requires the ordinary independent dispatch policy where configured. Creating a successor, reading its receipt or inspecting historical revoked metadata never sends bytes.
