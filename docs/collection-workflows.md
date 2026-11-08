# Remote artifact collection

## Read-only DAV source under qualification

The manual `webdav.collect` source reuses the ordinary ready-manifest,custody,
intake,approval,lease,fencing and original-receipt workflow below. Local focused
transport and typed-interface checks pass;actual native PostgreSQL/served-HTTPS,
CLI/browser and independent upstream DAV server qualification remain owed.
It does not add a DAV delivery endpoint or calendar arrival source.

An administrator registers a source through local `connection-register` with a
protected request file. Set `directory` to the exact remote DAV directory and
`dav` to `{ "schema_version": 1, "destination": { ... } }`. The destination
contains `address`,`server_name`,`ca_reference`,`ca_sha256`,`token_reference`
and `token_sha256`. Use a canonical numeric IP:port as the address and the exact
TLS certificate name separately. The CA and bearer token live in operator-owned
files;their approved SHA256 values stay in that private request. SSH,FTPS and
local-source fields must be absent. Registration records an immutable schema4
connection and makes no source contact. Browser/API workflows use its exact
ID,version and definition hash;they cannot introduce a host credential reference.

The reader uses TLS1.3 with only that pinned CA,name and numeric endpoint.
Ambient proxies,system roots,DNS lookups,redirect following,cookies and source
mutation methods are absent. A redirect fails the collection;it cannot select
another recipient for the credential. The source account should independently
permit only the reviewed directory. The transport reopens the protected bearer
reference for each request and checks its approved fingerprint. Current workflow,
connection and lease authority is checked during streaming and before each
private staging write. Closing or cancelling work interrupts active HTTP reads.

Publish ordinary immutable files first and the ready manifest last. The reader
accepts only complete200 identity-encoded responses and verifies the promised
length,SHA256 and exact end of stream. Unknown HTTP lengths remain bounded by
the approved manifest length;extra or missing bytes fail. Metadata retains its
existing32KiB bound;payloads use32KiB application buffers and the existing
approved workflow file/batch limits. Socket idle/header/parser bounds protect
runtime operations;they are independent of GitHub runner capacity.

The review shows read-only HTTPS identity and fingerprints of the CA/token
references. It exposes no token value,token digest or host credential path.
The source is excluded from delivery pickers and scheduled-arrival admission.
Receiving a batch grants no forwarding or execution authority. Add and approve
ordinary onward steps separately when required;business acceptance stays unknown
without a receiver contract. A saved original work receipt does not reopen the
source or repeat effects,even when its old credential file is unavailable.

Explicit Basic credentials use a separate inner DAV schema2. Set
`destination.authentication` to`basic`,provide the public `user`,and give
`password_reference`/`password_sha256` instead of token fields. Mixing the two
credential forms is refused. Usernames cannot contain a colon or control
characters;the password is a protected UTF8 file with no control characters.
Its exact bytes remain pinned. The client sends this credential only through
the same verified TLS1.3 endpoint;server challenges cannot change its mode,
recipient or permission. The review uses the separate
`freightctl-webdav-basic-collection-source-v1` profile and displays the account
name and a fingerprint of the password reference. It exposes no password value,
password digest or local reference path. Incoming freightctl DAV remains the
separate bearer profile.

The prepared native independent-server proof uses the unmodified pinned
rclone1.76.0 binary after its full source/binary security gates. It serves two
synced immutable fixture files on task-owned loopback TLS1.3 with an explicit
protected bcrypt htpasswd file,empty rclone config and read-only filesystem
service. No credential value enters argv. The ordinary product source then
captures and independently reads exact custody with zero onward effects;an
original-key replay must survive removal of its old credential file. This proof
is prepared and compiled,not yet runtime-qualified.

Migrations64–65 add strict DAV connection/protocol/view guards to the existing
registry. Migration65 preserves the earlier bearer SQL body and every previous
migration byte. All78 metadata tables and77 forced-RLS tables remain intact.
The retained local schema35 database is unchanged. Fresh native initialization,
upgrade/restore and actual final-source runtime proof remain owed. Client,
bearer-source and Basic-source profiles run as separate required Actions steps
after successful security/database prerequisites;each failure keeps the job red.

Primary protocol/peer inputs:[HTTP Basic](https://www.rfc-editor.org/rfc/rfc7617),
[rclone WebDAV server](https://rclone.org/commands/rclone_serve_webdav/).

## Collection workflow

For separately approved routing changes to an existing captured batch, see [captured routing authorization](captured-routing-authorization.md). Selected backend contracts now pass in temporary PostgreSQL databases; browser controls, retained upgrade and stock-source/receiver qualification remain pending.

Open **Collections** to prepare an ordinary versioned workflow with a remote input. Select a registered source connection, ready-manifest name, existing virtual target folder and file/byte limits. Add outgoing SFTP steps if needed; zero outgoing steps means local collection only. Preview shows the pinned source identity, local paths and all receiver effects without contacting a peer.

Saving a draft, approving its exact definition, queueing a job, reading the source, queueing downstream work and executing each next transfer step are separate actions. A saved draft survives reload in the saved-workflow picker. The picker shows the latest revision of each collection workflow owned by this account. Queueing requires the exact approved revision under current account authority.

This is an explicitly invoked, ready-manifest batch input. Calendar admission for remote inputs, missing/late arrival policy and the complete scheduled-collection journey remain required work. The existing **Schedules** picker continues to select local published-file workflows.

## Producer completion contract

The source publishes immutable payload files first, then publishes the ready manifest. For example:

```json
{
  "schema_version": 1,
  "batch_id": "9e00d187-cd22-4872-8bda-91b8f6730faa",
  "files": [
    {
      "name": "settlement.csv",
      "size_bytes": 3,
      "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    }
  ]
}
```

Here the exact bytes are `abc`, without a newline. The workflow's completion contract is `immutable-files-sha256-manifest-v1`. The producer must retain those exact files while collection can run. A manifest cannot specify a host, target path, credential, recipient, workflow or permission.

The manifest is strict JSON, at most 32 KiB, containing 1–64 files within the approved bounds. Each name is a unique ASCII basename of at most 128 bytes, starting with a letter or digit and containing only letters, digits, dots, underscores or hyphens. Paths, trailing dots, another ready-manifest file and unknown fields are refused. A digest is a lowercase 64-character SHA-256 fingerprint. Empty payload files are permitted with their actual empty-file digest.

The client checks directory/file metadata without following symlinks, opens files read-only, and verifies the exact promised length, digest and end of file. A changed same-size file fails its digest. An unchanged size over time is never treated as proof of completion. The registered directory, pinned SSH host and client key remain part of the reviewed connection. This development profile retains its existing numeric-loopback connection restriction.

Collection exposes no source write, rename or deletion operation. Use a separately restricted remote account; a registered starting directory alone does not jail that account on its server.

## Durable capture and intake

Queueing commits metadata only. A confirmed worker first records a durable reading lease and captures one immutable manifest. Retries cannot silently switch the job to a different producer batch.

Payloads are copied into private task-owned staging objects, verified, synced and sealed read-only. The exact file record, normal intake binding, collection input claim, event and acceptance retry receipt then commit together. Storage and PostgreSQL do not share one transaction: a crash can leave a sealed object without a confirmed file record. Recovery verifies that same object before reuse; it does not guess from an existing filename. Uncertain objects remain retained for reconciliation.

No input in an unfinished batch can be downloaded or published. After every input has a durable local receipt, the batch capture and any permitted local publication commit with the worker's receipt. Required CSV, signature and scanner checks still apply to the exact immutable files. Captured means locally accepted; it does not mean clean, released, sent or accepted by a business system.

For a policy requiring checks, use **Intake checks** to run them and approve each exact release. Downstream admission waits for every newly collected sibling's ordinary availability check. One released file cannot cause part of a held batch to route. Use **Review queueing downstream work** again after the remaining releases; it records ordinary ordered workflow intents without contacting either peer.

Ordinary file permissions, live connection/key state, workflow authority and each exact-file independent dispatch policy control sending. Source/workflow approval cannot stand in for a named reviewer's consent. **Review working next transfer step** works one next eligible step of the approved ordered workflow. Another worker may have advanced it; the review displays all approved receivers. The server rechecks the live step and its exact-file dispatch approval.

## Identity, replacement and collisions

An input's identity includes the registered connection family, remote directory, source name, byte count and digest. A workflow family claims that identity once across its versions. A new producer batch ID or host-key version alone does not make unchanged input new. Reusing a producer batch ID with different contents is refused.

Local names are `<SHA-256>-<source name>` in the approved virtual folder. They are created without replacement. A collision remains visible instead of overwriting an existing path.

Preparing a new workflow revision does not move or rebind existing claims, targets, files or runs. A later batch may refer to earlier accepted inputs; follow **Inspect original input job** for their original workflow and receipt history. The later job neither republishes nor resends them. An input remains claimed if its original job is cancelled or expires; cancellation is not an instruction to duplicate an uncertain exchange.

Cancellation stops further collection and sending under that job. Already captured local files and receiver copies remain. An unfinished cancelled batch stays unavailable; this initial component does not provide a general orphan-claim reassignment or deletion/reconciliation workflow.

## Leases, cutoffs and retry receipts

Each job freezes a 1–3600 second collection/sending cutoff from durable queue time. A worker checks it with current account, source, target, storage and workflow authority before acceptance and consequential sends. A cutoff is an authorization boundary, not proof that the recipient's business process finished by that time.

Reading leases last 30 seconds, capped by the original cutoff, and renew during live work. A replacement waits for the recorded lease to expire. Its attempt and fence counters increase; the older fence cannot accept bytes after takeover. The original maximum of eight attempts is retained. Stream slots, storage quotas and the approved file/byte bounds also apply. A full downstream queue leaves remaining input claims intact.

After a lost response, retry the same operation with its original key and identical meaning. It returns the recorded receipt. A failed attempt's receipt remains historical even after a later attempt succeeds; choose a new key for a newly reviewed retry after its recorded backoff. A historical receipt grants no current execution authority.

## API and CLI

The existing tenant/partner prefix exposes:

- `GET /workflow-collection-connections` and `GET /workflow-collection-workflows` for actor-private, bounded metadata choices.
- The ordinary `/workflows/validate`, `/workflows/drafts` and exact-version approve/revoke operations for configuration.
- `POST /workflow-collections/preview` and `POST /workflow-collections` for reviewed job admission.
- `GET /workflow-collections` and `GET /workflow-collections/ID` for private jobs, input receipts and current local states.
- `POST /workflow-collections/ID/work|refresh|cancel` for separate reading, downstream admission and cancellation.
- The ordinary `/workflow-runs/RUN_ID` and `/work` interfaces for ordered sending.

CLI equivalents are `workflow-collection-connections`, `workflow-collection-workflows`, `workflow-collection-preview`, `workflow-collection-start`, `workflow-collection-status`, `workflow-collection-list`, `workflow-collection-work`, `workflow-collection-refresh` and `workflow-collection-cancel`. Use protected DSN/token references, the ordinary tenant/partner/storage flags, `--collection-id`, bounded `--request-file` and `--idempotency-key`. Job work takes `{"definition_hash":"REVIEWED_JOB_HASH"}`. Refresh and cancel additionally require `expected_revision`. These are ordinary typed workflow services; no model is involved.

Local-only execution needs workflow_execute/read/write/list and target permissions. Forwarding also needs deliver. Current execution requires partner-root scope. Connection registration remains an administrator operation. Another manager does not gain the original actor's collection history. Ordinary event feeds redact collection packages and receipts while the protected journal retains them.

Migration 30 adds four forced-RLS tables: jobs, immutable producer batches, input claims and minimal shared file holds. A shared hold contains no source, job or actor details; it prevents another administrator from bypassing an unfinished batch when private input rows are hidden. It changes no existing/default permissions or runtime bypass privileges. The original availability function retains all intake/signature/scanner conditions and adds the whole-batch capture gate.

The selected local qualification uses real PostgreSQL, private storage, a stock read-only OpenSSH source, a separate stock receiver, Chromium and independent byte retrieval. Encrypted definition hashes have contract coverage; no new source-to-encrypted-receiver runtime qualification is claimed here. See [scheduled collection](scheduled-collections.md) for due-correlated ready manifests and arrival policy. Broad connector/routing/batch semantics, multi-host production recovery, business acknowledgments and complete customer journeys remain open. Models and the malware scanner remain off. The owner-deferred full replay remains pending.

[Collected handoffs](collected-handoffs.md) add a separate approved successor for completely untouched schema-2 queued work. The original job and input assignment stay immutable. The engine and saved-request CLI journey are locally verified; browser review, stock delivery and broader attempted/ambiguous recovery remain open.
