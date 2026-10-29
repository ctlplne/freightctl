# Test a saved onboarding connection

The connectivity test records an intent before opening a connection to an already registered SFTP receiver. It checks the pinned SSH host identity, the selected login key, SFTP negotiation, advertised `fsync`/`hardlink` extensions and each directory component. It does not open a payload, list names, write, rename or delete remote files. A successful result is **connectivity evidence**. Write permission, actual extension behavior, file integrity, receiver business acceptance and production activation require their separate tests and decisions.

This is the outbound, numeric-loopback `sftp-readonly-v1` development profile. Other protocols and inbound roles remain required work. Recording an HTTPS or other protocol requirement does not make it eligible for this SFTP test. The full onboarding journey still requires exact account/credential/folder/workflow bindings, an independent file exchange, approval, activation and queued-work key lifecycle.

## Browser

Sign into the intended partner as a root `/` operator with `admin`, `accounts_manage` and `connections_manage`. Open **Onboarding**, then open a saved draft. Tests use that saved version, not edits still in the form.

1. In **Connectivity tests**, choose a saved outbound SFTP requirement.
2. Enter the connection UUID and version from ordinary `connection-register` output. Choose **Read registered connection**. The browser cannot enroll a new endpoint or key path.
3. Choose **Review connectivity test**. Check the saved draft/version/hash, requirement ID, connection/version/hash, current account revision, receiver, directory and host/client fingerprints.
4. Choose **Run reviewed connectivity test**. The server saves a durable intent and its retry receipt, then one worker contacts the receiver under that exact intent.

If a response is lost, recover the same recorded operation. The frozen start key recovers the original intent; the frozen worker key reads the original outcome. A completed result needs no free network-worker slot to recover. A failed test needs an explicitly reviewed new probe to contact the receiver again.

**Refresh probe history** and **Inspect probe** find private records after reload. **Review recorded probe recovery** reads a running/completed result or resolves an expired worker. A queued probe with current bindings can begin its one contact. A probe whose saved requirement, connection or authority changed is blocked. Recovering an expired worker records expiry and starts no new connection. Canceling a review does not undo contact that already began.

The page labels a successful observation as read-only connectivity and keeps the onboarding plan a draft. It explicitly reports whether the recorded bindings still match. A historical success can remain in the journal while becoming unsuitable for the current draft.

## API and CLI

All operations use the same scoped service. Cookie mutations require normal same-origin CSRF proof; all mutations use `Idempotency-Key`. Unknown/duplicate fields and invented endpoints, key paths, approvals or results are refused.

| Job | REST | CLI |
| --- | --- | --- |
| Save an exact probe intent | `POST /v1/tenants/{tenant}/partners/{partner}/onboarding-probes` | `partner-onboarding-probe-start --request-file REF --idempotency-key KEY` |
| Discover private history | `GET /v1/tenants/{tenant}/partners/{partner}/onboarding-plans/{plan}/probes?limit=50&after=UUID` | `partner-onboarding-probe-list --onboarding-id PLAN_UUID --onboarding-limit 50 --onboarding-after PROBE_UUID` |
| Read current/historical result and binding status | `GET /v1/tenants/{tenant}/partners/{partner}/onboarding-probes/{probe}` | `partner-onboarding-probe-status --onboarding-probe-id UUID` |
| Run or recover the same recorded probe | `POST /v1/tenants/{tenant}/partners/{partner}/onboarding-probes/{probe}/work` | `partner-onboarding-probe-work --onboarding-probe-id UUID --definition-hash SHA256 --idempotency-key WORK_KEY` |

All CLI commands also take ordinary `--tenant`, `--partner`, `--dsn-file` and `--token-file` references. No deployment-admin connection or storage path is needed. Set `umask 077` before saving request/result files. The start body is:

```json
{
  "plan": {"id": "PLAN_UUID", "version": 1, "hash": "EXACT_PLAN_SHA256"},
  "requirement_id": "REQUIREMENT_UUID",
  "connection": {"id": "CONNECTION_UUID", "version": 1, "hash": "EXACT_CONNECTION_SHA256"},
  "expected_authority_revision": 1
}
```

Replace placeholders with actual enrollment/status output. The selected plan must be its latest saved version and contain the selected outbound SFTP requirement. The connection must belong to this actor and remain active with the exact hash. A new connection version does not silently replace the selected version. Credential rotation or security-policy changes invalidate the old authority binding.

Start returns the original queued `resource` and `replayed` marker. This receipt is historical; it is not a claim that the intent is still current or has run. Use status for the current result. Work accepts only `{"definition_hash":"EXACT_PROBE_SHA256"}`; the CLI supplies that body from its flag. Repeat the same work key. The probe history contains its original worker key so an authorized operator can recover after losing browser state.

Status contains `probe`, `current_bindings`, `binding_reason`, sanitized connection metadata when current, `evidence_strength: "connectivity_only"`, `file_exchange_performed: false` and `production_active: false`. States are `queued`, `running`, `succeeded`, `failed`, `blocked` or `expired`. Results use bounded codes rather than peer-supplied text. Timestamps are canonical UTC, including after PostgreSQL reload and receipt replay.

## Bounds and evidence

There are two PostgreSQL session-lock slots reserved for probes, separate from transfer, encryption, scanner and model capacity. Each actor can have at most 16 queued/live probes in this initial profile. History is paginated at at most 100 records. These are operational processing bounds, not edition limits.

The network test has a five-second deadline and bounded SFTP packets. A worker has a 20-second lease: temporary ownership of one recorded intent. Its exact owner, operation key, definition and revision must still match when it saves a result, and the database lease must be live. Process death releases its session slot. Expiry can be recorded after the original lease without repeating contact. There is no automatic probe retry or unlimited in-process queue.

Intent, source event and start receipt commit together. Every claim/result requires its exact immutable event. Definition and terminal results cannot be overwritten. The server rechecks current saved requirements, active connection and account authority before contact and before recording success. Short row locks protect decisions; no database row lock is held over network I/O. Probe records are actor-private under forced row policies. Contact text, private key values and remote payloads do not enter probe observations.

The assisted native journey uses stock OpenSSH, native Chromium, real PostgreSQL/storage and stock curl. It drops committed start/work responses, reloads the browser, refuses missing CSRF and wrong scope, tests changed host/login/directory/link cases, kills the actual worker and waits for the original lease, and retains all original independent file-transfer checks. This is local profile evidence; complete onboarding, independent adoption, production network policy and enterprise qualification remain open. No inference is involved.
