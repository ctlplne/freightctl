# Outbound SFTP dispatch approval

A partner administrator can require a different authenticated account to approve each exact outbound SFTP delivery. The common sender checks this rule for direct CLI deliveries, ordinary workflows, onboarding tests and onboarding production runs. Approval shares a bounded copy of metadata; it neither grants access to the original file nor sends bytes. Incoming transfers and ordinary downloads have their own existing authorization rules.

This rule is separate from [onboarding production release approval](independent-approvals.md). A release approves a tested configuration. Dispatch approval approves one immutable file delivery under that configuration. When both rules are enabled, both approvals must remain current. Different account IDs do not establish that different human operators control them.

A definition hash is a fingerprint of the selected metadata. Changing the file, destination, policy or other bound field changes that fingerprint, so an approval for the earlier selection cannot authorize it.

## Configure the rule

Sign in with partner-root `admin` and `accounts_manage`, open **Approvals**, and find **Outbound SFTP dispatch approvals**. Inspect the policy revision, choose **Independent named reviewer**, and confirm. Without an explicit policy, revision zero uses ordinary author approval. Every explicit change creates a new immutable policy revision, including a return to author approval.

New deliveries bind the current policy revision in their definition hash. A policy change blocks existing queued deliveries whose bound revision is now stale. Retrying their original creation command returns its original receipt; it never silently changes the recipient, file or policy. Prepare a new reviewed intent under the current policy when the policy itself changes. Already delivered bytes and historical receipts remain intact.

The equivalent CLI commands use protected references:

```sh
freightctl dispatch-policy-status \
  --dsn-file .private/pg-runtime.dsn --token-file .private/operator.token \
  --tenant TENANT_ID --partner PARTNER_ID --storage .private/custody

freightctl dispatch-policy-set \
  --dsn-file .private/pg-runtime.dsn --token-file .private/operator.token \
  --tenant TENANT_ID --partner PARTNER_ID --storage .private/custody \
  --request-file .private/dispatch-policy.json --idempotency-key EXACT_OPERATION_KEY
```

The first policy change takes `{"expected_revision":0,"mode":"independent"}`. The other mode is `author`. Approval permission alone cannot change this administrator rule.

## Review one delivery

1. Prepare the delivery through its ordinary CLI or workflow path. In **Approvals**, enter its **Outbound delivery ID** and inspect it. The author needs partner-root `read` and `deliver`. A review is available only for an untouched draft or queued delivery: zero attempts, zero fence, no lease and no generated ciphertext.
2. Choose an existing different account with partner-root `inspect` and `workflow_approve`. Preview the exact metadata before confirming disclosure. The package binds the source revision, digest, size and intake/check references; delivery hash and revision; receiver address, account, directory and final filename; SSH host/client fingerprints; a hash of the local key reference; optional recipient encryption and workflow bindings; and both accounts' authority revisions. It contains no credential value, private key or raw local SSH key path.
3. Confirm sharing. Only the author and assigned reviewer can inspect this request. Another full manager cannot read it. The reviewer receives no access to the original delivery, private workflow, plan or source file.
4. The reviewer signs in separately, opens **Approvals**, inspects the shared package and confirms approval or rejection. The decision binds its exact hash and revision. The sender separately executes the existing delivery command; review operations make no receiver contact.
5. Retry a lost response with the original operation key. Private history survives reload. A successful historical receipt reports that original decision and cannot restore withdrawn or stale authority.

The author or assigned reviewer can withdraw a pending or approved request. Withdrawal blocks further sending; it cannot recall receiver bytes. Rejection needs a new request. Credential rotation, expiry, revocation or permission changes invalidate the bound authority. If the delivery remains untouched and its policy/source/configuration remain current, withdraw the old request and explicitly obtain a fresh approval for the **same immutable delivery**. An attempted transfer needs its ordinary recovery path; this review interface cannot reset attempts or erase publication history.

The common worker checks approval before taking transfer capacity or making an attempt, and rechecks during streaming, ciphertext binding, lease renewal and publication. SQL guards independently reject unauthorized state/ciphertext writes. Short worker checks use the shared policy lock; account changes take its exclusive side, so a credential change waits for an in-flight guard without blocking ordinary status behind the broad account writer lock.

## Recover an uncertain receipt

An uncertain send may already have published the final file. Withdrawing permission to send must not force a duplicate send to discover what happened. Ordinary bounded, read-only reconciliation can still inspect that exact remote file under current connection, source, storage and file permissions. If its size and digest match, it can record the observed receipt after the original publication lease expires, without another attempt, fence or remote write. This observation does not authorize a resend and does not establish business acceptance. Other recovery/state/lease checks remain in force.

## Interfaces and bounds

The authenticated API uses the ordinary tenant/partner prefix:

- `GET|POST /outbound-dispatch-policy`
- `GET /outbound-deliveries/DELIVERY_ID`
- `POST /outbound-dispatch-reviews/preview`
- `GET|POST /outbound-dispatch-reviews`
- `GET /outbound-dispatch-reviews/REVIEW_ID`
- `POST /outbound-dispatch-reviews/REVIEW_ID/approve|reject|withdraw`

The CLI provides `dispatch-delivery-status --delivery-id`, `dispatch-review-preview`, `dispatch-review-propose`, `dispatch-review-list`, `dispatch-review-status --dispatch-review-id` and `dispatch-review-decide --dispatch-review-id --dispatch-review-action approve|reject|withdraw`. Mutations use `--idempotency-key` and bounded `--request-file`; credentials remain protected file references. Preview takes `delivery_id`, `reviewer_id`, `expected_revision` and the delivery's `definition_hash`. Proposal takes that exact `selection` and the preview's `definition_hash`. Decisions take `expected_revision` and the review's `definition_hash`.

Ordinary strict JSON parsing retains its depth, token, duplicate-key and 32 KiB request limits. Canonical review metadata is limited to 24 KiB before persistence and 32 KiB in SQL; events retain their existing 64 KiB bound. Oversized data is refused without truncation. Each author can have 128 pending requests; history pages contain at most 100 entries; one pending/approved request can bind a delivery at a time. The existing maximum eight delivery attempts remains unchanged. These bounds protect resources and are not edition restrictions.

Migration 28 adds two forced-RLS tenant/partner relations. Policy revisions and review definitions are immutable event-bound records. Decisions and retry receipts commit together. Runtime roles remain non-owner/non-bypass; no new/default permission is granted. Ordinary event/audit feeds redact review packages and command payloads.

The selected [F036 qualification](qualification/evidence/F036-outbound-dispatch-approvals.json) passes 63 focused workflow tests, including nine new real PostgreSQL/race cases; three migration/delivery regressions; six affected Go unit/race packages; and 53 frontend contracts. Its 456-step native journey retains 1,217 verified operation files, all 14 browser invocation summaries and 49 selected accessibility states. It independently retrieves the original 73 bytes across direct, workflow, test and production sends, and recovers an actual uncertain publication after consent withdrawal. First API/SQL failures and original source copies remain retained. No assertion, original lease, attempt limit or resource budget was relaxed.

Full journeys, general workflow-step policies, delegation, environment promotion, independent human operation, adoption, native platform breadth and production qualification remain open. The owner-deferred full replay is separate. Local inference remains off; this path requires neither a model nor a scanner.
