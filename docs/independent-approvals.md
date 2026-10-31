# Independent production approval

For the explicit onboarding production route, a partner administrator can require a different authenticated account to approve an exact outbound SFTP production release. The author prepares the tested release and chooses its reviewer. The reviewer sees the exact metadata package, makes a separate decision, and grants no file access. The author then records that approval and activates production through the ordinary release workflow. None of these metadata operations contacts the receiver.

This policy governs onboarding production releases. The separate [outbound dispatch policy](outbound-dispatch-approvals.md) can also require exact-file approval across direct deliveries, ordinary workflows, onboarding tests and production runs. When both are enabled their checks are cumulative. General workflow-step policies remain required product work.

The rule separates authenticated accounts. It cannot prove that two accounts belong to different human beings. Independent operators, identity-provider policies and the wider delegation/environment-promotion journey remain separate qualification work.

## Set the partner policy

Open **Approvals** as an account with `admin` and `accounts_manage` at the partner root. Inspect the current revision, choose **Independent named reviewer**, then review and confirm the change. The server accepts only the expected current revision. It journals the new policy and its exact retry receipt together.

An unconfigured partner retains author approval at revision zero. Every explicit policy change creates a new immutable revision, including a change back to author approval. Existing production releases and queued work keep their original meanings and fail current-policy checks after a policy revision changes. Already delivered files and historical receipts remain intact. Suspend the old active release, refresh required test evidence, and propose a new release under the current policy; do not attempt to reuse an old approval.

Equivalent CLI operations use protected configuration and credential references:

```sh
freightctl partner-onboarding-approval-policy-status \
  --dsn-file .private/pg-runtime.dsn --token-file .private/operator.token \
  --tenant TENANT_ID --partner PARTNER_ID --storage .private/custody

freightctl partner-onboarding-approval-policy-set \
  --dsn-file .private/pg-runtime.dsn --token-file .private/operator.token \
  --tenant TENANT_ID --partner PARTNER_ID --storage .private/custody \
  --request-file .private/approval-policy.json --idempotency-key EXACT_OPERATION_KEY
```

The bounded request file contains `{"expected_revision":0,"mode":"independent"}` for the first change. The other supported mode is `author`. The administrator controls this rule; a reviewer with approval permission alone cannot relax it.

## Share and review the exact package

1. Prepare the partner plan, current connectivity probe and independently completed test exchanges. Preview and save the normal production release. Its definition hash includes the current policy revision and mode.
2. Inspect that proposed release. Under **Request independent production approval**, enter an existing reviewer account ID. The reviewer needs `inspect` and `workflow_approve`, a current credential, and partner-root scope. The author cannot select their own account.
3. Preview the package before sharing it. It identifies the author and reviewer, reviewer authority revision, exact proposed release, tested source-file IDs/digests/lengths/intake policies, receiver address/account/directory/filename, host/client fingerprints, encryption key references, and exact test/receipt proof references. It includes no credential value or private key.
4. Confirm sharing. The server writes one immutable private request. Only its author and named reviewer can read it; another full manager cannot. Existing private plans, test records, releases, source files and download permissions are unchanged. The copy of metadata in this request is the explicit disclosure.
5. The reviewer signs in separately and opens **Approvals**. Inspect the package and confirm approval or rejection. The decision binds the request's exact hash and revision. Current scope, reviewer authority, policy and author authority are rechecked. A stale package needs a fresh request or release.
6. The author refreshes the proposed release, records its separate approval and activates it. A reviewer decision alone neither activates production nor queues a transfer. File dispatch and worker execution recheck current policy, approval, reviewer authority, source/check/probe/connection bindings and ordinary file permissions.

An uncertain response is not evidence that the server did nothing. Retry the open review with its original operation key. Private history and CLI status show the exact stored result. Reusing the same key with different meaning is refused. An old successful retry receipt describes the original decision; it cannot restore authority after withdrawal or a later policy/credential change.

The author can withdraw a pending or approved review. Withdrawal preserves the history and blocks new production work; it cannot recall receiver bytes. Rejection requires a new request. Rotating, revoking or narrowing the reviewer's account invalidates an existing approval because its original authority revision no longer matches. The system does not silently switch reviewers or credentials.

## Interfaces and bounds

The authenticated API uses the existing tenant/partner prefix:

- `GET|POST /onboarding-approval-policy`
- `POST /onboarding-approval-reviews/preview`
- `GET|POST /onboarding-approval-reviews`
- `GET /onboarding-approval-reviews/REVIEW_ID`
- `POST /onboarding-approval-reviews/REVIEW_ID/approve|reject|withdraw`

The CLI provides `partner-onboarding-approval-review-preview`, `-propose`, `-list`, `-status` and `-decide`. Status/decision use `--onboarding-approval-id`; decision also uses `--onboarding-approval-action approve|reject|withdraw`. Mutations use `--idempotency-key`, and request/credential values stay in protected files. Preview takes `release_id`, `expected_revision`, `definition_hash` and `reviewer_id`. Proposal takes that exact selection plus its preview `definition_hash`. A decision takes `expected_revision` and `definition_hash`.

The request parser keeps ordinary depth/token/duplicate-key and 32 KiB body limits. Review encoding is bounded to 24 KiB before persistence, with a separate 32 KiB SQL JSON bound and the unchanged 64 KiB event limit. An oversized package is refused; it is never truncated. Each author can have at most 128 pending requests, and history pages contain at most 100 entries. One pending/approved request can bind a release at a time. These are processing/admission controls, not edition restrictions.

Migration 27 adds two tenant/partner-scoped forced-RLS relations. Policies and review definitions are immutable event-bound records; terminal transitions and exact retry receipts commit atomically. Account changes, policy changes and approval checks use a consistent lock order. No new/default permission, database owner role or bypass capability is granted. Ordinary event feeds and signed audit views redact the package and command payloads.

The selected [F035 qualification](qualification/evidence/F035-independent-production-approvals.json) passes 54 focused workflow tests (including eight new actual PostgreSQL/race cases), three migration/delivery regressions, six affected Go unit/race packages, 46 frontend contracts and nine evidence refusal contracts. Its 363-step native browser/CLI/API/stock-SFTP journey retains 972 verified operation outputs and all nine invocation-specific browser summaries, with 34 selected accessibility states. Original lock and browser-summary failures remain preserved; no assertions, deadlines, leases or resource budgets were relaxed. Full J05/J06, general workflow approval policies, broader delegation, environment separation/promotion, independent adoption and production/platform qualification remain open. The owner-deferred full replay is separate. Local inference stays off; this path does not need a model or scanner.
