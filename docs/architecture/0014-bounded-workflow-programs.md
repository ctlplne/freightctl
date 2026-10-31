# Bounded workflow programs

This decision defines the execution contract. [F040](../qualification/evidence/F040-bounded-routing.json) qualifies the selected assisted same-host component; full J03, baseline parity and release qualification remain open.

The next J03 outcome is a collected batch whose files follow approved routing rules. For example, a north settlement file goes to its north recipient and audit recipient, a south file goes to its south recipient, and an unmatched file is explicitly kept local. Every newly captured sibling must first pass ordinary intake. Each resulting delivery still needs ordinary current authority and exact-file dispatch consent. No model or script chooses a recipient during execution.

## One definition, a fixed effect catalog

Schema 1 keeps its existing canonical bytes and ordered delivery meaning. Schema 2 retains the same `steps` array as a catalog of approved SFTP delivery templates: exact step IDs, registered connection revisions, literal filenames and optional encryption policies. A new `program` selects and orders catalog steps. It cannot create an address, change a connection or interpolate an untrusted filename into a recipient.

The program has typed `deliver`, `if`, `for_each` and `keep_local` nodes. A loop visits an explicit, finite list of catalog step IDs; its variable can select only an item in that list. Conditions can combine bounded `all`, `any` and `not` groups over typed immutable file metadata and collection facts. String matching is case-sensitive and uses a bounded glob grammar where requested. Numeric comparisons use integers, without float conversion. Rule thresholds use canonical decimal strings on the JSON wire, so a browser cannot round a 64-bit threshold through JavaScript’s floating-point number type. Time, filesystem listings, network responses, model text and arbitrary code are not condition inputs.

A program may select each catalog step at most once for one immutable input. A selected path must either produce deliveries or explicitly keep the file local with a recorded reason. Empty accidental output, duplicate effects, mixed delivery/local dispositions, an unavailable fact and an unbound variable are errors. They cannot turn into a silent successful run. Current parsing, definition-size and catalog bounds remain. The program additionally bounds tree depth, node count and total evaluation visits, including nested loops. These are operational safety budgets, not commercial editions.

## Frozen facts and plan

File facts come from the exact durable `files` row. Collection facts come from the captured job, immutable producer manifest and original input claim: source name, producer batch ID, manifest count and original index. A caller cannot supply those facts. An unchanged input keeps its original job/run meaning across later workflow revisions.

Before creating external-effect intents, compile the approved program into one immutable execution plan. The plan contains those exact facts, the selected catalog step IDs, control decisions and the explicit local disposition if applicable. Commit the plan, run, source linkage, selected delivery intents, events and idempotent receipt in the same PostgreSQL transaction. Preview is local metadata work and shows potential versus selected effects clearly.

PostgreSQL independently validates the program/facts/selection and binds ordinal positions to the selected plan, rather than treating catalog positions as executed positions. Non-owner runtime SQL cannot add a skipped recipient, reorder selected effects, forge source facts or claim completion while an exact selected intent is unfinished. Old schema-1 runs and receipts retain their original meaning. Models can propose only the same inspectable draft and cannot enable execution.

The ordinary worker executes the resulting SFTP intents. It never interprets a fresh branch or loop after a retry. Source, workflow, calendar, account, connection, encryption, intake and dispatch checks stay live. Read-only reconciliation of an uncertain delivery remains an observation operation under its original contract. Cancellation cannot recall local or receiver bytes.

A deliberate local result has its own visible terminal state and no fake receiver receipt. A collected batch is validated for routing decisions before useful downstream admission. Bounded queue capacity can defer selected deliveries without changing the frozen choices or repeatedly writing empty polling receipts.

## Privacy and proof

Execution plans and source facts remain actor-private under forced RLS. Ordinary event feeds redact new plan/source-name data. Protected audit evidence keeps the exact facts and decisions for authorized review.

Qualification must use real PostgreSQL, real custody, stock SFTP sources and distinct independent receivers through browser, API and CLI. Exercise each branch, nested finite loops, explicit local results, unknown/malformed facts, injection-shaped filenames, duplicate and oversized expansion, foreign scopes, whole-batch intake, independent per-file/per-step consent, lost responses, restart, revoked authority and ambiguous receipt recovery. Preserve the first actual failure and immutable source/output epochs. All baseline rows and full journeys remain open until their complete requirements are proven. Models and the scanner stay off for this work; F026 aggregate replay remains owner-deferred.
