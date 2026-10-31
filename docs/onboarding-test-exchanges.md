# Record an onboarding test before sending bytes

Use **Recorded test exchanges** in a saved onboarding draft to bind a safe test file to the exact requirement, successful probe and approved workflow before receiver contact. Preview reads existing records. Saving commits one immutable test record, ordinary queued run, delivery intent, events and retry receipt in one PostgreSQL transaction. A separate **Execute recorded test exchange** action sends the bytes through the ordinary workflow worker. Saving and executing do not approve onboarding or activate production.

The first profile, `single-sftp-test-v1`, accepts one outbound SFTP step. It binds the exact saved plan/requirement, successful current probe, approved workflow version/hash/revision, registered connection, readable receiver/filename/host/client fingerprints, optional encryption key/profile/primary fingerprint, accepted source revision/hash, storage identity, namespace and authority. It adds no permission or default grant. Ordinary workflows retain their existing multi-step support.

## Operator sequence

1. Save requirements, register the intended receiver and complete its explicit connectivity probe. Use safe test data and keep the receiver agreement under review.
2. Create and approve an ordinary one-step SFTP workflow. Recipient encryption uses its exact enrolled key and profile. Record the accepted source file UUID.
3. Open the saved onboarding draft, then **Prepare a test exchange**. Copy the requirement, successful probe UUID, approved workflow UUID/version/hash and accepted file UUID from their receipts. Select **Preview test exchange**.
4. Review the exact receiver, directory, filename, host/client fingerprints, encryption recipient, source digest, authority and required receipt. Select **Save reviewed test intent**. No receiver contact occurs here. Keep this test/run UUID and definition hash.
5. If saving loses its response, retry the same reviewed command and idempotency key. The dialog retains both. After reload, inspect private test history before creating anything else. A new key creates a new test; it does not recover an old one.
6. Inspect the queued test, then choose **Execute recorded test exchange** separately. Its ordinary workflow executor rechecks current permissions, bindings, source policy/storage, protected credentials and encryption keys. A lost execution response requires inspecting/recovering that same run; it does not establish that the receiver received nothing.
7. Inspect the actual receipt. `GET .../onboarding-tests/TEST_UUID/review` derives the selection from immutable pre-contact lineage and compares the completed evidence. Transport/integrity cannot satisfy a business receipt contract. Explicit onboarding approval, production activation, suspension/promotion and queued-work key rotation remain required.

Plan changes or revoked connections make historical test bindings stale. Unfinished tests show attention and cannot dispatch through either the workflow or direct delivery worker. The original record, run and receipt keep their meanings; replaying the original save receipt never queues another run. These checks do not make an old successful probe a fresh network observation or cancel bytes that were already sent.

## API and CLI

All routes use the existing tenant/partner prefix, TLS, scoped authorization and browser CSRF protection. Preview/read require root-scoped onboarding management, connections management, read and an existing workflow role. Saving additionally requires `workflow_execute` and `deliver`. Test records and retry receipts are private to the author; ordinary event feeds and audit snapshots redact their private payloads.

| Action | API suffix | CLI command |
| --- | --- | --- |
| Preview without contact | `POST /onboarding-tests/preview` | `partner-onboarding-test-preview` |
| Save queued test | `POST /onboarding-tests` | `partner-onboarding-test-start` |
| Private paginated history | `GET /onboarding-plans/PLAN_UUID/tests?limit=50&after=CURSOR` | `partner-onboarding-test-list` |
| Current state | `GET /onboarding-tests/TEST_UUID` | `partner-onboarding-test-status` |
| Compare recorded proof | `GET /onboarding-tests/TEST_UUID/review` | `partner-onboarding-test-review` |
| Execute separately | `POST /workflow-runs/RUN_UUID/work` | `workflow-work` |

Preview accepts `plan: {id, version, hash}`, `requirement_id`, `probe_id`, `workflow: {id, version, hash}`, `file_id` and `expected_authority_revision`. Start accepts only `{ "definition": PREVIEW_DEFINITION }` with an `Idempotency-Key`. It reconstructs the current definition and refuses any change. Endpoints, success flags, receipts, approvals and activation cannot be injected. Requests retain the existing 32 KiB/depth/token/duplicate-key limits; preview/start/status have ten-second service deadlines and ordinary bounded delivery admission. Start uses the same durable workflow receipt transaction and returns its stored representation on first creation and replay.

CLI commands use protected `--dsn-file`, `--token-file`, `--tenant`, `--partner` and `--storage` references. Preview/start read `--request-file`; start takes `--idempotency-key`. History takes `--onboarding-id`, `--onboarding-after`, `--onboarding-limit`; status/review take `--onboarding-test-id`. Do not put raw credentials in arguments or request definitions. Apply migration 22 with normal `freightctl init` before running the new binary against an older installation; it adds one immutable actor-private forced-RLS table, for 45 total, and preserves existing grants/data.

## Selected qualification

[F029](qualification/evidence/F029-onboarding-test-intents.json) passes a 100-step assisted native browser/API/CLI journey with real PostgreSQL/storage, actual probes, stock SFTP and independent authenticated GnuPG decryption. It covers plaintext/encrypted tests, save response loss with the original key and one run, private reload, separate execution, six selected WCAG states, exact evidence comparison, stale-plan refusal and isolated current-connection revocation. Targeted race, migration, immutable SQL, rollback, concurrency, privacy and source/receiver hash contracts pass. The source is a synthetic 73-byte CSV; broader peers, protocols, resources, failure/race coverage, independent adoption and complete J05 remain open.

Reproduce with the existing exact task-owned PostgreSQL prerequisite and explicit native crypto configuration:

```sh
FREIGHTCTL_GNUPG_NATIVE_CONFIG="$PWD/.private/freightctl-gnupg-native.json" \
python3 scripts/qualify-onboarding-exchange.py \
  --postgres-container-id EXACT_TASK_POSTGRESQL_CONTAINER_ID \
  --recorded-tests
```

The qualifier creates/removes only a fresh fixture database and its loopback HTTPS/SFTP/browser processes. It checks the existing PostgreSQL workspace label and 512 MiB/one-CPU configuration; it does not start/stop the container. Native crypto retains its sampled 128 MiB child-family watchdog, with observer/OS costs separate. No scanner or model is loaded. F026's complete replay stays pending at the owner's request; this selected journey does not replace it or establish a complete current-source aggregate.
