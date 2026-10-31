# Recover an original receipt after trust rotates

A lost acknowledgment does not mean a file was never published. After SSH host/client credentials, operator authority or recipient keys rotate, the original execution remains bound to its old approval. It cannot silently adopt new keys. A **read-only receipt observation** uses current tested SSH trust to inspect the exact original final file, without sending, decrypting, replacing, renaming or removing receiver bytes.

This is the `sftp-published-observation-v1` profile. It covers an explicit actor-private outbound SFTP production dispatch whose delivery is `ambiguous`, or `publishing` after its original lease expires. Live publication, staged/queued work, completed/cancelled work, unrelated connections and changed receiver paths refuse this path. Use the separately reviewed [queued handoff](queued-production-handoffs.md) for eligible work that never published.

“Wire bytes” means the exact bytes sent over SFTP: plaintext for an ordinary exchange, ciphertext for a recipient-encrypted exchange. A later re-encryption is a different wire object even when its plaintext is identical.

The result is separate, immutable evidence. A confirmed observation records the exact original wire SHA-256 and length, current observer trust, authority, time and approval. The production status joins that receipt as a recovered transport outcome. Original dispatches, runs, delivery states, attempts, approvals and retry receipts retain their meanings. Existing execution guards remain unchanged; observing a file does not revive an old workflow or authorize a resend.

## Review, approve and observe

1. Inspect the original production run and its immutable dispatch hash. Keep its accepted source, original receiver/filename and expected plaintext or ciphertext identity. Wait for its original publication lease if it is still live; this operation never shortens it.
2. Register the replacement connection version in the **same connection family** and complete a current successful read-only connectivity probe. Address, account and directory must remain the same as the original. Host/client trust may rotate through normal protected enrollment. A probe proves connectivity, not the original file's integrity.
3. Select a currently readable authorized source with the same original plaintext digest and length. It may be the original accepted file or its completed direct governed re-check child after fresh checks and separate release. An unrelated equal-byte upload cannot substitute for that lineage. No old signature or scanner verdict is invented as fresh evidence.
4. In the saved plan, open **Recover a receipt after rotation**. Supply the published run UUID/hash, current successful probe UUID and authorized same-byte file UUID. Preview freezes both historical and current references without contact. Current plan versions may change while retaining that plan/requirement identity; the old source/receipt requirement stays explicit.
5. Review the original run/delivery revisions and publication state, original connection and SSH fingerprints, exact reserved final path, original plaintext and wire digest/length, optional retained ciphertext identity/recipient, authorized source policy/re-check link and current tested observer/authority. The OpenPGP recipient may now be revoked: the product hashes the already recorded ciphertext without loading a recipient private key. SSH authentication uses only the current observer's approved key reference.
6. Choose **Save reviewed observation**, then **Approve receipt observation** separately. These are metadata decisions with stable original-key retry receipts. Approval binds the exact definition, and grants no file transfer.
7. Choose **Review read-only observation**, review the same definition and confirm. The server commits one durable observation intent and worker fence before contact, then reads only that original final path. It checks authority, exact source/observer and its live lease during the bounded stream and again before committing a result.
8. Inspect the original production outcome and private observation history. A lost completed response is recovered using the same observation and work key, or by reading its durable status after reload. Terminal replay makes no contact. An expired worker becomes `expired`; a fresh contact requires a fresh reviewed proposal and separate approval.

## Interpret the result

`succeeded` means the original final path yielded a regular file of the exact original wire length and SHA-256 at the recorded time. Encrypted exchanges compare the original stored ciphertext, not newly encrypted bytes or a newly accepted plaintext digest. The receipt establishes point-in-time file integrity. It does not observe a new file-fsync acknowledgment, directory power-loss durability or downstream business acceptance; those remain false, not established and unknown respectively.

`unconfirmed` means the postcondition was not confirmed. Missing, different, unreadable or symlinked files, protocol failures and deadlines cannot prove that the receiver never consumed a file. They do not authorize re-submission, cancellation or a business retry. Reconcile downstream acceptance under the receiver's actual contract before risking another business effect.

`blocked` means a reviewed binding changed before or during observation. `expired` means the original observation lease expired before its result could commit. These are terminal records, not replacement transfer intents. Existing workflows and ordinary recovery work with AI disabled.

Historical successful observations remain evidence after later file removal or observer revocation. Their recorded time is part of their meaning. A newer unconfirmed observation does not erase a real earlier receipt or establish present availability. The old execution projection remains visible alongside recovered evidence.

## Shared API and CLI

All routes use the ordinary authenticated tenant/partner prefix, TLS and browser CSRF controls. Root onboarding/account management, connection management, read and an existing workflow role gate inspection. Proposal/cancellation additionally requires `workflow_manage`, approval requires `workflow_approve`, and observation requires `workflow_execute`. No new or default permission is granted. This is same-actor private review; cross-person delegation remains separate work.

| Action | API suffix | CLI command |
| --- | --- | --- |
| Preview exact observation | `POST /onboarding-observations/preview` | `partner-onboarding-observation-preview` |
| Save proposal | `POST /onboarding-observations` | `partner-onboarding-observation-propose` |
| Inspect exact record | `GET /onboarding-observations/OBSERVATION_UUID` | `partner-onboarding-observation-status` |
| Private paginated history | `GET /onboarding-plans/PLAN_UUID/observations` | `partner-onboarding-observation-list` |
| Approve/cancel | `POST /onboarding-observations/OBSERVATION_UUID/{approve,cancel}` | `partner-onboarding-observation-decide` |
| Observe/recover work | `POST /onboarding-observations/OBSERVATION_UUID/work` | `partner-onboarding-observation-work` |
| Original transport outcome | `GET /onboarding-production/RUN_UUID` | `partner-onboarding-production-status` |

Preview accepts `{source_run_id, source_hash, probe_id, file_id, expected_authority_revision}`. Proposal accepts `{definition: PREVIEW_DEFINITION}`. Decisions use `{definition_hash, expected_revision}`. Work uses `{definition_hash}` and an original `Idempotency-Key`; that record retains one immutable work key. Mutation receipt replay preserves its exact original result. A work response reports `contact_attempted`; status reads and terminal replay report false. Every response keeps `resend_authorized: false` where applicable.

CLI uses protected `--dsn-file`, `--token-file`, `--tenant`, `--partner`, `--storage` and `--request-file` references, plus `--onboarding-observation-id`, `--onboarding-observation-action approve|cancel`, or `--onboarding-id` for history. Pagination uses the existing after/limit options; work/mutations use `--idempotency-key`. Private keys and credential values never belong in these definitions or evidence.

The profile retains ordinary 32 KiB/depth/token/duplicate-key request limits, a bounded immutable definition/event and 1–100 history entries per page. Its operational queue admits at most 128 pending records per actor, protected by a database admission lock. Two separate cross-process observation slots bound streams without consuming transfer, scan, re-check or inference slots. Each network read has a 20-second deadline, a 30-second database worker lease and 32 KiB streaming chunks. Exact lease comparisons preserve PostgreSQL submillisecond timestamp precision in the client. The byte bound is the accepted source limit, plus the existing bounded ciphertext overhead for encrypted files. These are processing controls, not edition limits or whole-machine CPU/RSS guarantees.

Migration 26 adds one actor-private forced-RLS domain table, for 49 total. Immutable source/observer definitions, exact events, separate approval, fenced result transitions and original-key receipts stay under the ordinary non-owner runtime without bypass. Ordinary event feeds and signed audit projections redact private observation and retry payloads. Source and execution tables are preserved.

The [F033 native journey](qualification/evidence/F033-readonly-receipt-observations.json) passes 316 steps in 126.998 seconds on 313 unchanged inputs, with 28 selected WCAG states. It retains prior onboarding/handoff/pre-publication checks and qualifies original ciphertext recovery through current trust, independent stock SFTP/authenticated decryption, lost-response original-key recovery, private reload and original-outcome joins, missing/changed/symlink refusal, actual observer death/lease expiry without recontact, revoked-observer refusal and task-only application restart. Seven new real PostgreSQL/race cases, 38 focused workflow tests, three migration/delivery regressions, six affected Go unit/race packages, 40 frontend contracts and type/build/asset checks pass.

Initial API/fixture/SQL failures and exact original sources remain retained. D068's transient Docker-daemon disconnect occurred before the new native observation cases; its cause stays open. The original replay passes on the identical application binary/source without a shared restart or assertion/deadline/budget change. Retained schema 26 has 49 forced-RLS tables with counts preserved; task PostgreSQL returns to stopped and models/scanner stay off.

```sh
PYTHONDONTWRITEBYTECODE=1 \
FREIGHTCTL_GNUPG_NATIVE_CONFIG="$PWD/.private/freightctl-gnupg-native.json" \
python3 scripts/qualify-onboarding-exchange.py \
  --postgres-container-id EXACT_TASK_POSTGRESQL_CONTAINER_ID \
  --observations
```

This uses only disposable task databases and loopback stock peers. It does not replace the owner-deferred full replay, establish downstream business idempotency, independent adoption, every platform/protocol or the complete product. All whole baseline rows and journeys remain open.
