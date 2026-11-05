# Secure artifact exchange plan

Accepted product direction: 2026-11-05, owner decision S002. Starting commit:
`93cf90e20889eab4103703f445b5c46ba11ac1af`.

**freightctl is a secure artifact exchange platform that lets agents, applications,
people and systems send and receive artifacts under explicit permissions, with
reliable delivery and traceable outcomes.**

This is the implementation plan for that definition. The first compelling customer
workflow, buyer and market wedge remain unselected. Reference exchanges below test
the foundation; they do not establish customer demand, adoption or superiority.
[GOAL.md](../../GOAL.md) remains the complete acceptance contract. Planning does
not establish runtime qualification. Owner decision S003 resumes implementation
and authorizes source/CI batches under its focused-proof and FINISH rules.

## Product model

| Concept | Contract |
| --- | --- |
| Participant | An authenticated agent, application, person or external system, bound to tenant/partner scope and explicit authority. A participant can send, receive or do both. |
| Artifact | A bounded object with exact immutable bytes, revision, length, digest and custody provenance. Documents, datasets, generated outputs and software packages are examples. Descriptions and suggested recipients are untrusted data. |
| Exchange endpoint | An approved receive mailbox, custody view, storage location or protocol connection. Logical addressing resolves under current permissions to a versioned adapter profile, not an arbitrary URL or host path. |
| Exchange policy | The permission to move this artifact between these participants, with checks, approvals, encryption, expiry, retention and receipt requirements. Each onward handoff needs its own authorization. |
| Exchange record | The immutable request bindings, events, attempts, approvals and receipts explaining what was accepted, held, made available, delivered, retrieved or acknowledged, including uncertain outcomes. |

An exchange request binds the acting identity and any permitted delegation, source
artifact revision, receiving participant/endpoint, policy revisions, required
checks, expiry, promised confirmation and idempotency key. The final wire schema,
API paths, CLI commands and provider format must be frozen before implementation;
this document does not advertise new interfaces as implemented.

For example: a person submits a document, an agent retrieves it, a second agent
receives an extracted dataset, and an approved business endpoint receives the
result. The second artifact has its own immutable identity and authorized lineage.
Receipt of the document does not grant permission to forward it or execute its
contents. Correlation links remain scoped and redacted; they do not expose another
participant's files or history.

These permissions govern operations through freightctl. After authorized retrieval,
freightctl cannot erase the recipient's copy or control exchanges performed through
other channels. Record and enforce the boundary the product actually controls.

## Trust Control boundary

Trust Control owns identity and credential lifecycle. freightctl validates an
identity from an explicitly configured provider, maps it to scoped authority and
checks the particular exchange. Credential validity alone grants no destination,
artifact, forwarding or administration permission.

The product plan includes an optional Trust Control provider adapter. Its actual
issuer, credential type, audience/scope rules, delegation, expiry, key rotation,
revocation and outage behavior are an open contract, recorded as X07. Do not
invent a Trust Control API or assume a token format. Sender authentication secrets
and recipient transport secrets have separate references and access boundaries;
neither belongs in prompts, artifacts or ordinary evidence.

The adapter is an optional deployment choice. Core installation and exchanges
continue to work with ordinary customer-managed credentials/providers, without a
Trust Control account or service. Real provider qualification is required before
claiming Trust Control interoperability. A local stand-in tests only freightctl's
side of the contract. Provider failure must not silently switch identities or
broaden authority; freeze fail-closed behavior for new and in-flight work and
prove ordinary-provider exchanges remain independent.

The trstctl suite, general credential/trust control plane, general certificate
authority, organization-wide credential discovery and standalone secrets manager
remain outside freightctl. S002 supersedes only S001's exclusion of the dedicated
integration requirement. Historical S001 remains in the ledger.

## Exchange behavior

Support participant push, authorized recipient retrieval/polling and governed
collection from a configured source. An agent can be the receiver, sender or both
without a model running inside freightctl. A freightctl deployment agent is a
separate bounded edge component; ordinary participant agents need not install it.

"Any participant" describes eligible actors through supported endpoint profiles.
Publish exact protocol, identity, size, receipt and failure limits for each
adapter. A protocol name or provider stub does not establish compatibility.
Cross-tenant/partner access remains denied unless a separately specified exchange
contract explicitly authorizes both sides without impersonation or bypassing RLS.
The first reference exchange uses separate identities in one approved scope and
includes wrong-tenant/partner refusal; it does not claim general cross-tenant
routing.

Custody acceptance promises only its qualified persistence boundary. Required
checks and approvals must pass on the exact revision before publication or
delivery. Notification, availability, byte retrieval, integrity verification,
receiver durable acceptance and business processing are separate evidence. Some
receivers cannot establish the later stages; report those stages as unknown.

Use stable exchange/operation identities, transactional intents, durable leases
and fencing. Identical retries recover the original result; changed meaning under
the same key refuses. After possible remote publication, preserve ambiguity and
reconcile before any unsafe resend. Exactly-once business effects require a real
receiver deduplication/transaction contract. A reply is a new authorized exchange.

Notifications and polling are bounded and permission-checked, including filename
and metadata disclosure. Availability cannot bypass a hold, revocation or expiry
when bytes are subsequently fetched. At the first implementation contract review,
choose the smallest receive-discovery mechanism using existing PostgreSQL
coordination. Do not introduce a second database or message broker by implication.

## Reuse and compatibility

The first versioned structures now live in
[exchange_contract.go](../../internal/store/exchange_contract.go). The profile is
`custody-https-poll-v1`: a registered, exact-revision custody view in one tenant
and partner, discovered by bounded polling. It contains no arbitrary URL, host
path or implicit forwarding grant. The ordinary credential profile is an existing
freightctl account verified by the existing transport and PostgreSQL transaction.
Trust Control's missing contract is not substituted with an invented credential.

An endpoint definition pins recipient and allowed senders by tenant, partner,
actor, authority revision and namespace-root digest. A request pins the immutable
file ID, length, SHA256 and original acceptance policy; endpoint ID, revision and
definition hash; exact expiry and `availability-only-v1` receipt contract. The
authenticated sender and operation key come from the trusted transport, outside
the payload. Optional `reply_to` is correlation only: a reply is a new exchange
with its own endpoint and live authorization. Availability does not promise
retrieval, receiver persistence or business processing.

Canonical decoding refuses unknown fields, duplicate/case-folded field aliases,
nulls, trailing JSON, unqualified profiles and stronger receipt assertions. Its
16KiB envelope, depth8 and token4096 parsing bounds protect control operations.
Configured artifact size, sender count and new-exchange lifetime impose admission
bounds; expiry does not change the canonical meaning of a receipt replay. None of
these structural checks authenticates a participant, opens a file or grants access.
Public surfaces and actual runtime proof remain owed for the services below.

F081/F082 now implement the internal registration and receive-view services;
their native PostgreSQL and public-interface proof remains owed. A view is a
revocable permission for one exact file, not a copy/forwarding permission. Both
participants, the original source path permission, endpoint revision, storage
identity and current intake policy are rechecked before each bounded read. The
server checks the stored sender's authority as a dependency without authenticating
or acting as that sender. A reply uses a new artifact and separately granted
delivery authority. Publication, retrieval authorization, receiver persistence and
business processing retain separate meanings.

Receive discovery pages contain at most 100 entries. A cursor completes one poll
cycle; each new cycle starts without it so concurrent lower UUIDs are not lost.
Held entries expose only a view ID and fixed state. Authority changes refuse the
whole affected page rather than leaking an unauthorized cursor. Byte reads keep
the existing 256 KiB cap and a 10 second authorization deadline. Deployment settings
bound available views per sender, allowed senders and lifetime (whole seconds);
requests retain exact UTC microsecond expiry. Admission counts unexpired views,
including temporarily unavailable views. An unconfigured adapter refuses.
These local checks establish no actual PostgreSQL,HTTPS,stock-client,process-death,
independent-receiver,capacity or complete AX qualification. Public surfaces,
runtime qualification of per-view cancellation, retention/fairness and all
reference profiles remain owed. F091 implements one immutable sender cancellation
or recipient decline, with the exact request hash, current original participant
binding, transactional event/receipt, and a shared/exclusive view lock around every
bounded read. It revokes future access without recalling prior copies. Its actual
PostgreSQL/API/CLI/browser runtime proof remains owed.

| Existing foundation | Planned use |
| --- | --- |
| Tenant/partner accounts, grants and provider references | Bind participants and delegation; keep authentication separate from exchange permission. |
| Immutable file custody, uploads and checks | Represent artifact revisions and exact-byte admission/publication. |
| Namespace, connections and partner administration | Resolve receive views and approved endpoints under current authority. |
| Typed workflows, independent approvals and policy revisions | Review and authorize each processing/delivery effect. |
| Delivery intents, leases, receipts and reconciliation | Execute external handoffs and report honest outcomes. |
| Journal, audit, UI, API, CLI and agent tools | Expose the same exchange and receive operations under shared services. |

Inspect the actual services before selecting changes. The table is a reuse plan,
not a claim that logical inboxes or all exchange operations already exist. Preserve
historical IDs, canonical hashes, receipt meanings and installed migrations. Add
only necessary versioned events, API contracts and append-only migrations; use
the retained-estate upgrade process when authorized. No new participant database,
identity issuer, generic agent runtime or ambient execution privilege is implied.

All participants use the same authorization, policy, audit and idempotency path.
AI tools cannot invent recipients or gain broader rights. Artifact exchange must
work with freightctl inference disabled. The separate private-model quality,
disclosure and adversarial requirements in GOAL13/14 remain open and unchanged.

## Build order and exit evidence

1. **Freeze the contracts.** On application resume, inspect exact current source,
   native results and red gates. Map the existing services to participant,
   artifact, endpoint, policy and record. Freeze request/receive/receipt semantics,
   scopes, admission bounds, errors and compatibility. Pin an ordinary credential
   profile first; resolve X07 before implementing the real Trust Control adapter.
2. **Prove a small bidirectional exchange.** Use two independently authenticated
   deterministic software callers, real PostgreSQL and storage, verified HTTPS
   and a stock client/independent byte observer. Agent A submits an exact artifact;
   B discovers and retrieves only its permitted revision; B sends an independently
   authorized reply. Run with inference disabled. Exercise held bytes, forwarding
   denial, stale/revoked authority, same-key recovery, changed-key meaning,
   interrupted upload, process death and uncertain delivery as applicable.
3. **Bridge existing participant endpoints.** Reuse supported HTTPS/browser,
   SFTP and FTPS paths for person/system-to-agent and agent-to-system exchange.
   Test selected push and collection profiles with stock clients and independent
   receivers. Freeze every claimed adapter pair and replay affected original
   journeys. New status/notifications must recheck scope and byte authority.
4. **Qualify the provider boundary.** With the actual approved Trust Control
   profile, prove identity mapping, restricted delegation, rotation/revocation
   during queued/active work, wrong issuer/audience/scope refusal and provider
   outage behavior. Repeat the ordinary-provider journey with Trust Control
   absent. Keep fixture, real provider and independent operator evidence distinct.
5. **Use customer evidence to choose the wedge.** Observe actual exchange work,
   identify a repeated painful job and compare setup, approval, recovery and
   receipt accuracy on the same job. Record the chosen buyer/workflow and acceptance
   criteria before claiming a wedge. Continue the existing protocol, migration,
   resilience, private-AI, performance and packaging requirements.

The machine-readable [exchange requirements](../qualification/artifact-exchange.json)
contain eight planned requirements and three engineering profiles. R016 tracks
their implementation; X07 records the missing provider contract. They add explicit
product qualification work, not competitor observations. All 83 original parity
rows, twelve full customer journeys, historical defects and evidence stay intact.

For each profile, retain exact candidate/artifact identities, native environment,
real caller/receiver/provider versions, original failures, independent byte checks,
permission refusals, persisted event/receipt assertions, recovery and limits. A
model answer, contract document, mocked peer, skipped test or passing ledger check
cannot qualify the profile. Assisted deployment, independent adoption and enterprise
readiness remain separate. This plan itself grants no deployment, inference load,
scanner run or resource increase. S003 supplies current application-resume and
source/CI push authority.
