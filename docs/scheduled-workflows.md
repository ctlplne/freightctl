# Scheduled workflows

A schedule selects complete, published file revisions and queues the same typed workflow used by manual runs. A separate worker executes those intents. It uses the ordinary file permissions, current connection and key checks, transfer leases, retry limits and independent dispatch approval. A schedule cannot approve a file on a reviewer's behalf.

Each schedule family claims a file revision once, including across configuration versions. Renaming a file or keeping its size unchanged does not make it new input. An interrupted upload is not published input. The selector requires the accepted-file event and the current published-path event to precede the occurrence's due time; backdating a file's displayed modification time cannot change that fact. It checks current read/list/traversal permissions and required intake checks before claiming bytes.

## Prepare and activate

Open **Schedules**, choose an approved workflow, source folder and filename pattern, then configure the calendar and processing bounds. The workflow picker shows current-authority approved definitions owned by this account. Preview displays the receiver effects and their fingerprints, local times and corresponding UTC instants. Previewing and saving a draft make no receiver contact.

Review the exact metadata before saving. The definition hash is its fingerprint: changing the source rule, receiver effects, calendar, account authority or processing bounds changes that fingerprint. Saving creates an immutable version. A separate activation decision authorizes a worker to claim matching future file revisions. The reviewer must have the existing workflow approval and execution permissions; a saved draft alone grants no sending authority.

Activation of a newer version suspends the previous active version. Previously claimed revisions and queued delivery meanings stay intact. They are not silently moved to the new settings or claimed again. To roll back configuration, prepare a new reviewed version using the earlier settings. Suspension/revocation stops further sending under that version; it cannot recall receiver bytes.

## Calendar contract

The calendar contains an IANA time-zone name, an explicit UTC start/end horizon, local clock times, permitted weekdays and explicit holiday dates. Weekdays use Sunday=0 through Saturday=6. Clock times use `HH:MM:SS`; holiday dates use `YYYY-MM-DD` in the selected zone. No remote calendar is fetched.

Preview records the selected zone's concrete UTC offset intervals inside the hashed definition. Execution uses those frozen intervals. A host time-zone update cannot silently move an approved job. A changed legal time-zone rule requires a new preview and approval. Go's bundled zone-data fallback is included for installations without host zone files; native minimal-install qualification remains separate.

Missing local times during a forward clock change are skipped. Repeated local times during a backward change explicitly choose `first`, `second` or `both`. The preview shows both the local label and actual UTC instant, so two repeated clock labels cannot be confused. The same mechanism covers changes other than one hour and skipped civil dates.

A calendar horizon is bounded to `5 × 366` days, with at most 96 local clock times, seven weekdays, 512 explicit holidays and 64 frozen offset intervals. Oversized calendars are rejected without truncation. Renew the horizon through a new reviewed version. These are processing bounds, not commercial edition limits.

## Missed runs, cutoffs and capacity

- `skip` discards due starts outside `late_start_grace_seconds`; ordinary polling jitter inside that grace is allowed. A skipped range records its endpoints without inventing a count of individual runs.
- `latest` discards earlier due occurrences and considers only the most recent one. Its execution cutoff still applies.
- `all` considers every due occurrence in order, within `max_catch_up` per request. The durable cursor retains the remaining backlog for another bounded pass.

`execution_deadline_seconds` defines the sender's cutoff after a due time. Admission, direct CLI sending, lease checks, streaming and publication all recheck it. This is a boundary on sender authorization, not proof that a downstream business system finished by a deadline. An expired occurrence records a missed decision and consumes no file revision. A queued intent that reaches its cutoff retains its history; it is not automatically rebound or resent under a later occurrence.

`max_active_runs` and `max_files_per_occurrence` bound admission. The ordinary per-actor delivery capacity also applies. A full queue leaves the due cursor in place; it does not consume a file or acknowledge new work. Replacing a version stops its old queued authority and preserves its input claims. Current active-run accounting does not let an inactive version's unsendable queue occupy the replacement's admission slots.

The configured bounds allow 1–100 catch-up decisions, 1–64 current active runs and 1–64 files per occurrence. The execution cutoff is 1–604800 seconds; skip grace is 1–3600 seconds and cannot exceed that cutoff. The existing eight-attempt transfer budget remains unchanged.

## Run the worker

All CLI operations use protected database/token references and the ordinary tenant, partner and storage flags. Use `workflow-schedule-workflows`, `workflow-schedule-preview`, `workflow-schedule-draft`, `workflow-schedule-status`, `workflow-schedule-list`, `workflow-schedule-history` and `workflow-schedule-occurrence` to inspect metadata. Version controls are `workflow-schedule-activate`, `workflow-schedule-suspend` and `workflow-schedule-revoke`. They require the exact definition hash and expected revision in a bounded `--request-file`, plus `--idempotency-key`.

`workflow-schedule-tick` takes `{"limit":1}` and queues metadata only. The limit cannot exceed the configured catch-up bound. A lost response is retried with its original operation key; the first response and replays use the same stored receipt. A historical receipt cannot restore current authority.

```sh
freightctl workflow-schedule-worker \
  --dsn-file .private/pg-runtime.dsn --token-file .private/operator.token \
  --tenant TENANT_ID --partner PARTNER_ID --storage .private/custody \
  --schedule-id SCHEDULE_ID --version 1 --schedule-poll 1s --execute
```

`--execute` explicitly enables ordinary workflow execution. Without it the worker queues only. Read-only polling adds no event every second while waiting for capacity or independent review. Polling is bounded to 1 second through 1 minute. The worker preserves the original per-step operation key across retries and chooses a different key for the next ordered step. Multiple worker processes still share PostgreSQL admission, unique input claims, transfer leases and fencing.

Stopping a process does not cancel a durable intent or shorten its lease. A replacement waits for the original lease before reclaiming eligible staging work. Publishing/ambiguous outcomes retain their ordinary read-only reconciliation and review requirements. If all transfer receipts succeeded but a worker stopped before updating the run projection, `workflow-refresh` records the ordinary receipt-derived state without sending bytes. It uses an exact retry receipt. A sending cutoff does not prevent that metadata repair or ordinary read-only remote receipt reconciliation; neither operation authorizes a resend.

A lease is a short, recorded right for one worker to handle an intent. Its fence is a counter that increases when another worker takes over; a late worker holding the older counter cannot update the current intent. The receiver must ignore staging names such as `.freightctl-DELIVERY-FENCE.partial`. Only the final name represents publication. Old staging files can remain after an interrupted attempt and are not delivery receipts.

## Interfaces and isolation

The authenticated API uses the existing tenant/partner prefix:

- `GET /workflow-schedule-workflows`
- `GET /workflow-schedules`
- `POST /workflow-schedules/preview|drafts`
- `GET /workflow-schedules/ID/VERSION`
- `POST /workflow-schedules/ID/VERSION/activate|suspend|revoke|tick`
- `GET /workflow-schedules/ID/history`
- `GET /workflow-schedule-occurrences/OCCURRENCE_ID`
- `POST /workflow-runs/RUN_ID/refresh` for metadata-only projection repair.

History and configuration are private to the owning identity as well as tenant/partner scoped. Another full manager cannot read them through these endpoints. Ordinary audit/event views redact the schedule package and command payload. Existing workflow permissions are reused; no new/default permission is granted. Current execution in this initial workflow engine requires partner-root scope.

Migration 29 adds three forced-RLS relations. Occurrence decisions, input claims, ordinary workflow/delivery intents, cursor movement, events and retry receipts commit together. A failed receipt rolls the whole admission back. SQL guards check due times against the frozen calendar, current approval, exact source and receiver bindings, deadlines and capacity. A credential change joins the sending guard; ordinary status observes metadata without acquiring that effect lock.

[F037 qualification](qualification/evidence/F037-scheduled-workflows.json) records the selected assisted local journey: 111 native steps, 285 verified operation files, three browser summaries and 15 accessibility states. Thirteen new real PostgreSQL cases pass within 82 workflow cases; 62 frontend contracts and six calendar cases also pass. An interrupted worker resumes under its original lease, and uncertain receipt recovery succeeds against a stock read-only receiver after cutoff without another sending attempt. Full scheduled remote collection, folder/event trigger breadth, independent operation, native platforms, scale/endurance and the complete customer journeys remain required. The owner-deferred full replay is separate. Local inference remains off; scheduling does not require a model or scanner.
