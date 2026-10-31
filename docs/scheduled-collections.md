# Scheduled remote collection

A scheduled collection expects one producer ready manifest for each due time. A ready manifest is the producer’s small JSON list of immutable filenames, exact byte lengths and SHA-256 digests. The calendar does not guess that a file is complete because its size stopped changing.

This is the scheduled input of an ordinary workflow. It uses the existing collection, custody, intake, ordered delivery and independent dispatch approval services. Source-only workflows can stop at durable local capture without configuring a dummy receiver. The full J03 journey, broader routing/batch rules and business acceptance remain open.

## Bind the expected input

In Collections, select “Expect a separate manifest for each scheduled due time.” The explicit completion contract is `immutable-files-sha256-scheduled-manifest-v1`. The manifest filename must contain exactly one `{due_utc}` token, for example `settlement-{due_utc}.ready.json`. A due time of `2026-11-01T05:30:00Z` expects `settlement-20261101T053000Z.ready.json`.

The token uses the absolute UTC instant. The two occurrences of a repeated local clock time during a daylight-saving change therefore expect different names. A yesterday manifest cannot satisfy today’s occurrence. This contract still requires the producer to finish and keep the named payload files immutable before publishing the ready manifest. The manifest JSON format is the same as [manual collection](collection-workflows.md).

Approve the workflow, then choose it in Schedules. Its source connection, pinned host identity, target folder, manifest template and byte/file bounds stay fixed by the approved workflow. Review the time zone and frozen offset rules, weekdays, holidays, repeated-time policy, missed-run rule and concurrency bounds before activating the calendar.

## Three time boundaries

The arrival policy has `late_after_seconds`, `arrival_deadline_seconds` and `poll_interval_seconds`. These are measured from the original due time. The arrival cutoff must be later than the late boundary and earlier than the workflow’s execution cutoff. Polling is bounded from one to 3,600 seconds, with at most 65,536 approved probe claims per occurrence.

The server records “on time” or “late” using the immutable ready event’s PostgreSQL clock. An event trigger owns that instant, and the arrival projection must use exactly the same value; neither an API body nor a direct runtime-role write can supply an earlier observation time. Remote modification time and eventual business completion do not establish arrival time. “Missing” means no eligible verified ready manifest was observed by the arrival cutoff. It does not prove that the producer never published a file; an outage or a stopped worker can also prevent observation.

A verified ready manifest is frozen before waiting for collection capacity. Admission uses that exact snapshot, without another manifest read. Collection and downstream sending keep the original due-time execution cutoff. Queueing late does not buy extra time. A frozen but unadmitted manifest becomes expired after that cutoff.

## Durable work and recovery

A due-work decision writes the occurrence, expected arrival and immutable event together. It contacts no source or receiver. A source probe has an original 30-second lease and a 20-second read budget. An abandoned worker’s replacement waits for that recorded lease; it cannot shorten the takeover boundary. Each replacement increments the fencing counter, which makes an old worker’s completion invalid.

An absent manifest returns to waiting at the approved cadence. Connection, host-identity or malformed-manifest failures require attention and an explicit retry. Source probes do not consume the ordinary collection worker’s eight byte-transfer attempts. Once ready, a separate metadata admission creates the ordinary collection job and links the arrival in one transaction.

The collection worker verifies the frozen list’s payload bytes and records ordinary immutable inputs and local custody receipts. Every newly captured sibling must pass its intake policy before routing begins. Each file and step still needs its own current dispatch consent where policy requires it. Calendar suspension, revocation, cancellation and cutoff stop new effects under that occurrence. They cannot recall already captured local bytes or receiver copies. Existing read-only uncertain-delivery reconciliation remains an ordinary workflow operation.

Every mutating command has an idempotency key. Keep the original body and key after a lost response: replay returns the original receipt, even if status has since changed. The browser keeps that exact request in its open confirmation dialog. Closing a dialog does not undo a committed action; reload the private arrival and collection status before choosing another action.

## Interfaces

The tenant/partner API prefix is `/v1/tenants/{tenant}/partners/{partner}`. Arrival and source details remain private to the owning account. Ordinary account, workflow, file, source and namespace checks still apply.

| Method and suffix | Effect |
| --- | --- |
| `GET /workflow-schedule-arrivals/{occurrence}` | Read the exact binding, probe history, timeliness and linked collection. |
| `POST /workflow-schedule-arrivals/{occurrence}/probe` | One bounded source observation, or metadata-only missing settlement after cutoff. Body: `definition_hash`. |
| `POST /workflow-schedule-arrivals/{occurrence}/admit` | Queue the frozen ready snapshot, or record its elapsed execution cutoff. Body: `definition_hash`, `expected_revision`. |
| `POST /workflow-schedule-arrivals/{occurrence}/cancel` | Stop future work for that occurrence. Body: `definition_hash`, `expected_revision`. |

Mutating requests require `Idempotency-Key`. A client cannot submit an observation time, manifest result, lease owner, fencing value or clock override.

The matching CLI commands are `workflow-arrival-status`, `workflow-arrival-probe`, `workflow-arrival-admit` and `workflow-arrival-cancel`, using `--occurrence-id`. Mutations use `--request-file` and `--idempotency-key`, with protected credential and database references as for existing collection commands.

`workflow-schedule-worker --schedule-id … --version …` makes metadata due-work decisions. Explicit `--execute` also coordinates due probes, frozen admission, ordinary collection, intake-ready routing and ordinary delivery. `--schedule-poll` controls read polling; the approved source cadence still applies independently. Readiness polling writes no events or command receipts while a live lease, intake review or full downstream queue prevents useful work. The actual action rechecks all authority and capacity in its own transaction. Attention needs a human retry; the worker cannot grant that retry or dispatch approval to itself.

## Qualification

[F039 evidence](qualification/evidence/F039-scheduled-arrivals.json) records a selected assisted same-host qualification: 105 workflow tests, eight new PostgreSQL cases, three migration/delivery regressions, nine affected unit/race packages, 79 frontend contracts, reproducible assets and the native evidence-refusal contracts pass. The final stock-SFTP/browser replay passes 97 steps in 68.151 seconds on 400 unchanged source inputs, with 267 verified operation outputs and six selected accessibility states.

The replay proves nine absent polls without a byte job, a verified late manifest, original-key browser/CLI recovery, frozen collection after the producer removes the manifest, exact independently retrieved downstream bytes, missing-at-cutoff settlement, cancellation, calendar suspension, foreign-account privacy and takeover at fence 2 after the original 30-second probe lease. Source-only calendar admission is also proven with a nonadmin account lacking deliver permission. D083–D087 retain the original migration, null-schema, target-size, backdating and browser-precision failures and their repairs. Two harness failures also remain visible: JSON-lines parsing and an unregistered asynchronous output were repaired without weakening evidence verification.

Retained schema 30 → 31 adds one actor-private forced-RLS relation, for 61 in total. Existing event/file/credential counts, authority and grants are unchanged; no arrival was implicitly created. The exact task PostgreSQL is restored to its original stopped state. The scanner and inference remain off.

All 83 whole baseline rows and 12 full journeys remain open. Broader connectors, routing and batch rules, business acknowledgments, production platforms, multi-host/scale/endurance and independent adoption remain required. This native arrival replay forwards plaintext; it does not newly qualify an encrypted peer. Ordinary sibling-intake and independent per-file/per-step consent retain F038 native evidence and current regressions, but are not separately requalified with approval policy enabled in this arrival-native replay. The full current-source aggregate replay remains deferred at the owner’s request.
