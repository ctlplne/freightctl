# Deterministic record projection core

The internal primitive, governed metadata review and standalone durable processing
lifecycle are implemented through API and CLI. Preview alone cannot execute.
Execution requires a separately approved immutable intent and a current fenced
attempt. A versioned scoped profile and five metadata-only MCP controls are also
implemented. The typed workflow adapter, browser,
fairness/performance and native application/recovery qualification remain owed.
Neither a valid row nor a completed projection grants execution or forwarding.

## Governed metadata review

`POST /v1/tenants/{tenant}/partners/{partner}/checks/{file}/projection-preview`
accepts `ProjectionOptions`: `reason`, optional `target_path`/`profile`, and the declarative
`definition` described below. The [OpenAPI contract](../api/record-projection.openapi.json)
contains the request rules and complete typed response. It uses ordinary bearer
or browser session authentication. Control JSON has the existing 32 KiB, depth16
and4096-token bounds. Unknown fields, duplicate/case-folded keys and trailing
values refuse. The route accepts no approval, source override, credential,
signature-reuse, shell, recipient or byte-content argument.

The CLI uses the same service:

```sh
freightctl check-projection-preview \
  --dsn-file .private/pg-runtime.dsn --token-file .private/token \
  --tenant '<tenant-id>' --partner '<partner-id>' \
  --storage .private/custody --file-id '<source-file-id>' \
  --request-file .private/projection-options.json
```

The historical default profile requires root administration plus `read`, `write`, `intake_manage`,
`check_run` and `check_release`. The caller must own the original acceptance.
Receiving a view, or simply having a write credential, supplies none of this
processing authority. The source needs a passed or released exact check, with no
live worker or lease. Its original contract, format-specific engine/success code,
full report hash, file identity/size/digest, storage identity, namespace root,
authority revision and captured check revision must agree. Integrity-only,
unchecked, rejected, partial and invented successful reports refuse.

A retired source contract is usable only through this explicitly authorized
processing review. Ordinary current-policy download and release checks stay
unchanged. Mandatory original signatures must still bind the exact attachment,
bytes and live key; mandatory scanner results must still be clean, fresh and bound
to the exact bytes, profile, engine/feed and protected configuration. The preview
reads bounded public/control metadata and protected scanner configuration; it
does not open artifact contents, contact a scanner daemon or start inference.
The earliest source proof expiry joins the immutable plan. Wall-clock observation
alone does not change the hash while the same proof is still valid.

The latest active output policy must have exactly the projection's derived data
shape and explicit processing bounds. It cannot drop required signature/scanner
controls or extend the original nonzero signature age. It may select separately
registered output protections; those do not replace validation of the original
source protections. Changing bytes always requires a new signature when required;
`reuse_exact` refuses. An optional target is create-only: the source and every
other existing destination remain protected from overwrite. Publication still
needs the output's own successful checks and separate exact release.

Schema1 profile `held-record-projection-v1` binds the entire captured source/check/
signature context, original source-policy reference, current output-policy
reference, storage/root/authority and target revisions, normalized mapping/engine/
processing rules, derived data-contract hash, reason and source proof expiry.
Returned pointers and mappings are independently owned, so editing a request
cannot change a completed review. A preview saves no intent, event, receipt,
artifact, check or release. An approved durable intent binds this whole
plan and regenerates it before consequential effects; preview itself grants no
execution permission.

## Scoped processing and model tools

Explicit `profile:scoped-record-projection-v1` selects plan schema2. It requires
`read`, `write`, `check_run` and the appropriate existing workflow grant:
`workflow_manage` for preview/proposal/cancellation, `workflow_approve` for approval,
and `workflow_execute` for starting/working an attempt. Inspection requires one
of these workflow grants. This adds no permission name or implicit grant. The
ordinary account service can delegate these roles within its existing authority.
Administration, policy changes, release and delivery remain separately authorized.

Source ownership, exact successful proof and current protections remain mandatory.
The source binding must match the current actor root and authority. Output targets
are logical paths: `/derived.json` for an actor rooted at `/payroll` means
`/payroll/derived.json`. Parent access and revision are checked at the resolved
location; the held output keeps the logical path plus root binding. Existing
destinations and unsafe paths refuse. Profile/schema pairs are exact: old schema1
`held-record-projection-v1` retains its full root requirements and original hashes.
The scoped grant cannot reinterpret an old root job. Original-key receipt reads
also recheck the stored profile and namespace before disclosing their private plan.

Schema52 appends the scoped actor/action guards without changing earlier migrations
or adding tables. Every transition checks current actor, namespace and the applicable
workflow role, including cancellation and failure recording. Stale source proof
does not have to be made valid merely to cancel an otherwise authorized own job.
Fresh-CI inventory remains73 metadata/72 forced-RLS tables; schema51 stays a
historical profile. Retained schema35 is untouched.

Catalog31, `exchange-tools-v13`, adds `preview_record_projection`,
`propose_record_projection`, `inspect_record_projection`, `start_record_projection`
and `work_record_projection`. They accept only the scoped profile. Preview returns
exact artifact/policy/mapping metadata and a hash binding the complete private
server review. Propose supplies the same options and `review_hash`, then creates
an unapproved intent. Its original key recovers the original proposal before
reopening a changed source. Approval remains a separate ordinary API/CLI action;
there is no model approval or release tool. An approved attempt can then be started
and worked under execution authority. There is no recipient or shell argument.

Model replies omit source/namespace paths, reasons, full definitions, staging IDs
and bytes. They distinguish current observation from an original command receipt
whose current authority has not been checked by that observation. Completed work
reports only exact artifact metadata and held acceptance; failed work reports a
fixed code. Byte retrieval still uses ordinary authorized HTTPS routes after
fresh checks and release. The existing ten-second MCP deadline remains enforced;
it may cancel processing and produce a recorded failure instead of an output.

Focused scoped-role/profile/replay/schema/redaction tests pass locally. Prepared
native tests use real PostgreSQL/storage, a confined actor and the stock MCP SDK
over verified HTTPS, with a separate ordinary approval, held-byte refusal and
original-key recovery after policy change. Compilation is not a native pass.
Delegated independent approvers/workers, the typed workflow adapter, browser,
all protected formats, fairness and complete runtime/recovery profiles remain owed.

## Durable intent and held output

The same API prefix exposes:

| Operation | Request and meaning |
| --- | --- |
| `POST /checks/{file}/projections` | `{plan}` from review; creates a proposed intent and three server-generated private staging IDs. |
| `GET /projections/{projection}` | Owned durable state and a separate current-review observation. Historical receipts do not change when current conditions change. |
| `POST /projections/{projection}/decide` | `operation:approve\|cancel`, exact `definition_hash` and `expected_revision`. Approval revalidates; cancellation can retire stale or expired work without restoring obsolete source proof. |
| `POST /projections/{projection}/start` | Exact `definition_hash` and `expected_revision`; creates a durable attempt with a new worker ID and 71-second lease. |
| `POST /projections/{projection}/work` | Exact `projection_id`, `attempt` and `worker_id` returned by start; processes under the live lease. |

All mutations require an ordinary `Idempotency-Key`. The CLI equivalents are
`check-projection-propose`, `check-projection-status`, `check-projection-decide`,
`check-projection-start` and `check-projection-work`. They use `--projection-id`
after proposal, `--file-id` for proposal, and bounded `--request-file` metadata;
mutation keys use `--idempotency-key`. The API and CLI return the normal
`{resource,replayed}` command envelope; the resource contains the intent and its
observed state. Get returns the separate `ProjectionView`. These are processing
outcomes, not receiver acceptance or business receipts.

An actor can retain at most 16 proposed/approved/running/failed intents. Cancel
unneeded failed work to free admission. Three attempts and three immutable
staging slots bound retries after interruption. A live worker cannot be replaced
or cancelled; expiry or a recorded failure permits a new explicit start. Every
attempt gets a distinct worker ID. A prior start key returns its original start
receipt even after completion; use status for current state. A prior work key
returns its original completion or recorded failure. New attempts use new keys.
Changing command meaning under an existing key refuses.

Processing uses a separate two-slot pool and the existing single custody capacity
reservation. The output's reviewed byte bound must fit the deployment's existing
maximum file allowance; physical capacity includes all retained objects. Processing
does not increase any local allowance. The existing reservation excludes concurrent
custody admission while held; independent fairness/latency and isolated worker
qualification remain mandatory. No general shell, network or model capability is
added. The request deadline is 65 seconds; the deterministic engine keeps its own
reviewed deadline of at most 60 seconds. The live lease is checked from PostgreSQL
before each bounded sequential/random read and output write, and before acceptance.

Graceful generation failure removes only its newly created partial object. A
0600 object surviving process death stays in place; another approved slot is used.
A sealed 0400 object is never overwritten. Recovery recomputes the entire transform
from the exact source, compares its size/digest, verifies and syncs the existing
object, then adopts its original ID. A mismatching sealed object refuses; the
worker cannot hide tampering by choosing a new slot. Slot exhaustion stays visible.
No failed staging result carries a successful output digest.

Schema 51 adds `record_projections` and `record_projection_slots`, with forced
tenant/partner/actor RLS, immutable definitions/slots, exact event guards, bounded
transitions, lease/attempt fencing and deferred atomic-completion constraints.
Acceptance uses a distinct `FileAccepted` schema5 with the intent/definition,
source ID, attempt and projection report. The fresh file, held check, lineage,
completion event and command receipt commit together. A SQL rollback retains the
sealed object for verified adoption. Original source/recheck/received-copy
identities and all earlier migrations stay intact. Retained schema 35 is not upgraded.

The new artifact has its own policy/check and no inherited signature or release.
Run its ordinary fresh check, attach a new signature when required, and make a
separate exact release decision before publication or delivery. A committed
processing failure returns `state:failed` and a fixed code, with no output file or
qualified digest. Lost authority or an expired lease can prevent failure recording;
status then retains the original attempt until explicit recovery. Actual process
death, final-source SQL/restore/lease/protection/ordinary-client proofs and the
broader workflow/exchange journeys remain owed.

## One parsing path

`checks.StreamRecords` uses the same five validators as ordinary held intake:
CSV,flat JSON,fixed-width,scalar XML and the explicit XLSX table profile. The
normalized source contract determines field order,types,padding,namespace and
spreadsheet/date interpretation. A transformation does not have a looser parser.

Every record has a logical ordinal and independently owned cells. Missing,null
and present values are distinct;present empty text is not null. JSON missing
properties and nulls remain distinct. XML missing and empty elements remain
distinct. XLSX missing cells,blank cells and explicit empty strings remain
distinct. CSV/fixed-width empty fields stay present values. Numeric/date scalar
meaning follows the approved source contract without floating point conversion.
Row order and duplicates remain intact;no implicit sorting/filtering/deduplication.

Record values are transient content and are excluded from automatic JSON metadata
serialization. Reports contain fixed codes,positions,counts,identities and hashes.
Trusted consumers may retain their own row copy without changing parser state.
Consumer errors have a fixed outer message;underlying contents are not printed.

Validated prefix rows can arrive before a later error or complete-source digest
failure. Callbacks must only write private staging. The complete report and
current domain authority remain mandatory before any output can be accepted.

## Reviewed definition

`RecordProjection` schema1/kind`record_projection` binds engine
`freightctl-record-projection-v1`,the exact normalized source-policy hash,ordered
source/target column mappings,output kind and processing budgets. Lookup is exact,
case-sensitive and never fuzzy. Unknown sources,duplicate targets,unknown engine,
executable expressions and unsupported operations refuse before writing.

Conversions are explicit: `identity`,`text` and `normalize_lf`. The latter applies
only to text and changes CRLF/bare CR to LF. Independent `missing`,`null` and
`empty` rules default to `preserve`;explicit alternatives choose empty,null,
missing or error where meaningful. Each rule runs once on the ORIGINAL state,
not recursively on its own result. Each rule,field order,engine and budget is in
the definition hash. Normalization clones mapping storage.

JSON output preserves missing properties,nulls and empty text by default. Typed
numbers are serialized without floating point:required JSON numeric syntax
removes a leading plus/excess integer zeros while retaining exact value,sign and
fractional digits. Text identifiers retain their leading zeros. A numeric empty
value requires an explicit null/missing/error rule;it cannot silently become0.

CSV output uses UTF-8 and LF record separators with ordinary structural quoting.
CSV cannot represent missing/null separately from empty fields;such input refuses
unless the operator explicitly chooses a conversion. CRLF scalar text also needs
an explicit newline conversion because ordinary readers normalize it. No rule
silently changes bytes or drops records to fit the output.

Formula-like text/header prefixes,including whitespace/control/format prefixes,
apostrophe hiding and full-width initiating characters,refuse CSV output.
Structural quoting alone does not establish formula safety. Validated numeric
constants remain numeric. The core does not add an escape that changes the value
or offer an unsafe formula bypass. Choose JSON or another qualified output profile
when CSV cannot preserve the required meaning. Generic spreadsheet import guesses
and later rewrites are not a typed receiver contract;no universal Excel claim.

## Private output and failure

Source and projection timeouts,source parser limits and independent output byte,
record-byte and row limits apply. Output rows must remain one-for-one with source
rows. Exceeding a limit refuses the entire result;it never truncates a scalar or
returns a shortened successful dataset. These are product processing controls,
not arbitrary GitHub build or scan ceilings.

`ProjectRecords` returns a non-nil error for EVERY incomplete/rejected output.
The successful digest is set only after complete input validation,matching counts
and successful output closure. Output I/O errors have fixed non-sensitive codes.
Inside existing `Disk.StageGenerated`,an error removes only the new partial file;
complete output is synced,sealed read-only and verified by actual byte readback.
The focused local filesystem proof does not qualify PostgreSQL quota/acceptance,
worker recovery or any application authority/approval path.

The output data-contract hash is not an intake/release policy. The domain caller
must bind the current approved output policy and require fresh signatures/scanning
and separate release. It cannot inherit the input's successful checks. Source
authority and mandatory source protections also remain the caller's obligations.

## Evidence boundary

F168 checkpointed the typed contract with draft persistence disabled. F170 adds
the transactional run/dispatch path,SQL53 and ordinary API/CLI wiring described
below. Native outcomes remain owed;compilation does not qualify PostgreSQL or
served execution. Existing standalone schema1/2 projection profiles remain.

### Typed processing workflow

Workflow schema3 contains `name`,empty `steps` and exactly one `processing` task.
The task contains `id`,kind `records.project`,the complete normalized projection
`definition`,exact `output_policy` (`id`,`version`,`hash`),`target_path` and
`reason`. Every engine/output/row/byte/deadline/presence rule is explicit before
approval. Source collection,programs,delivery steps and arbitrary code refuse.
The approval pins the task and source contract;the executor selects an owned
input that satisfies that contract. Run creation binds the actual immutable input,
successful original checks,namespace,authority,storage and current output policy.
An input may be held with successful checks or use its explicitly retired source
contract. Ordinary downloads still require their ordinary release policy.

Use ordinary workflow validate,draft,approve,run,run-preview,status,work,refresh,
cancel and diff interfaces. The CLI command names are `workflow-validate`,
`workflow-draft`,`workflow-approve`,`workflow-run`,`workflow-run-preview`,
`workflow-run-status`,`workflow-work`,`workflow-refresh`,`workflow-cancel` and
`workflow-diff`. Processing validation/execution/observation needs the configured
storage root. Draft management requires `workflow_manage`;approval or revocation
requires `workflow_approve`;execution requires `workflow_execute`,read,write and
check_run. Confined processing is allowed in the actor's own namespace. Legacy
workflow/connection operations retain their root requirements. No admin,
intake-policy change,release or delivery grant follows from processing approval.

Creation atomically commits the run,event/receipt,one already-approved exact task
intent,three private staging slots and immutable `workflow_processing` binding.
Both directions have deferred SQL membership checks. No delivery intent is made.
Before work,a stable workflow key commits the selected intent hash and revision.
Internal start/work keys recover that exact attempt. An original failed key never
advances to a newer retry;`processing_attempt` is its historical result while
`status.processing` is the current observation. A fresh key can retry within the
ordinary three-attempt/lease/fencing limits. A completed task is never executed
again;new observation work only refreshes its status.

Completion creates a separate held artifact with ordinary immutable provenance.
The run observes `attention`/`output_held`,with no delivery steps. Fresh ordinary
output checks and a separately authorized release are required. Refresh can then
record `succeeded`/`transformed_output_released`. That means processing and release,
with no recipient,transfer or receiver-processing promise. SQL refuses success
based only on an empty delivery list. Onward sending needs a separately approved
workflow and current delivery authority for the newly released artifact.

Workflow revocation blocks direct projection start/work as well as workflow work.
Cancellation retires pending or expired processing in the same transaction;it
refuses an active lease. An already completed held artifact remains ordinary
custody and does not inherit a release. Cancellation never claims to erase it.
Authority,namespace or storage changes refuse private run/receipt access.
SQL53 preserves the existing collection-routing/handoff guards and adds forced
tenant/partner/actor RLS for the new binding. Earlier migrations and retained35
are unchanged. Native SQL,API/CLI,protected formats,process death,restore,
fairness and complete customer outcomes remain owed.

The browser's Record processing page now loads authorized metadata-only contracts
from `GET /v1/tenants/{tenant}/partners/{partner}/checks/{file}/processing-contracts`.
It offers explicit column, conversion and presence rules, reviews the canonical
schema3 definition, and uses ordinary draft, approval, run, work and refresh
commands. Current status is displayed separately from historical work receipts.
The held output opens the ordinary intake-check/release page; receiving or
processing does not authorize onward delivery.

An uncertain browser mutation keeps its original request key and exact normalized
meaning. A compact recovery JSON file is limited to32KiB and bound to the origin,
tenant, partner, actor, authority revision and root digest. It contains no session
credential. Import reviews the actual referenced task configuration and never
executes automatically; explicit confirmation retries the original request.
Session/scope changes reject in-flight results. Existing recheck parsing still
defaults to the root namespace; processing explicitly supplies its authorized
root. Catalog37/exchange-tools-v14 adds schema3 validation/proposal and six
metadata/control tools, with ordinary approval/release kept separate.

F172/F173 record focused contract, privacy, canonical-hash and response-loss
stand-in proof. The stock-SDK and actual Chrome/PostgreSQL/TLS journey are prepared
and compiled, not runtime qualified. GitHub native Chrome will assert committed
response-loss recovery, five accessibility audits, held-byte denial, fresh checks,
separate release and an independent stock-curl exact-output read. All existing
native browser profiles remain selected. No local Chrome, PostgreSQL or inference
runtime is needed for the focused implementation checks.

Native ARM/x86 qualification prepares stock Python CSV/JSON/ElementTree/fixed
fixtures and actual pinned XlsxWriter bytes. Ten JSON/CSV outputs are checked by a
separate Python JSON/Decimal/CSV receiver for byte hashes,exact money and IDs,
dates,order and duplicates. Stock XLSX row-stream assertions also cover rich
strings,literal formula-looking strings,OOXML escapes and both explicit calendars.
At source `036fbd3d896b719f6dbf804ab3c0e73dd80b7e7d`, original run
`42305585988`, jobs `128193962728` (x86) and `128193963340` (ARM), passed these
native race/stock-input assertions and the separate ten-output Python receiver.
F162 preserves exact handles and safe log manifests. These establish the record
primitives at that source, not governed application acceptance or later changes.
The metadata review's native PostgreSQL/source-key/scanner-configuration/grant/
ownership/no-payload assertions are prepared and remain owed; local compilation
does not establish a runtime pass. Served API/CLI/browser/MCP and full executable
workflow, recovery and final-source acceptance also remain owed. F163 adds the
durable service and real local private-slot adoption/refusal checks. Four prepared
native PostgreSQL tests cover held output/separate release, SQL receipt rollback
and adoption, failure-retry fencing and runtime forgery. Their compilation is not
runtime qualification. The standalone native document job now includes the new
focused stage/intent/lease/review contracts on ARM and x86.

The source handling follows [RFC8259](https://www.rfc-editor.org/rfc/rfc8259).
CSV refusal accounts for [OWASP's formula-injection guidance](https://community.owasp.org/attacks/CSV_Injection).
Full transformation breadth,XLSX/XML/fixed/EDI outputs,joins/arithmetic/general
schemas,application integration,original customer journeys and actual final-source
acceptance remain mandatory and open. No overall parity or product completion.
