# Versioned workflows and registered connections

## Local collection adapter under implementation

F293 implements a read-only adapter for private ordinary local directories.
It is not yet admitted as a workflow or registered connection:the original
`local.collect` normalization regression remains red until the durable connection,
SQL,CLI/API/browser review and custody integration are complete. Do not advertise
this primitive as a qualified local/network-storage connector.

Metadata inspection returns a physical root fingerprint from the held OS
directory identity,not from its path spelling. An opener must supply that exact
reviewed fingerprint. Unix uses device/inode identity;Windows uses the full
native128-bit file ID and64-bit volume identity. Every read checks the current
root,path identity and actual private permissions again. This narrow profile
refuses symlink roots/files,unsafe flat names,changed physical files,unbounded
manifests and wrong lengths/digests. It does not write producer files or create a
marker in the producer directory.

An authority callback must pass before opening and around each bounded read.
Copy output must be unpublished private staging:an error can leave partial
staged bytes,and only ordinary custody acceptance may publish verified bytes.
No local read grants forwarding or execution. Connection revocation,leases,
idempotency,events,intake and batch admission still need their existing ordinary
workflow integration. Local macOS filesystem positive/adverse cases pass;
Linux/Windows compilation is not native runtime qualification. Mounted network
storage,crash/restore and performance profiles remain separately owed.

F295 adds the protected local profile constructor. Its reviewed definition
fixes a private configuration-file reference,that file's exact SHA256 and the
physical root fingerprint. The private file contains only schema1,the fixed
`freightctl-local-collection-source-v1` profile,the absolute directory and the
same root fingerprint. Unknown/duplicate/aliased fields,nested values,changed
bytes or root,and absent current authority refuse a reader. The configuration
is read through the existing protected secret buffer and cleared afterward.
This does not yet expose registration or execution through a product interface;
ordinary connection/SQL/workflow/custody and browser/native proof remain owed.

The first workflow executor sends one immutable accepted file through an ordered list of `sftp.deliver` steps. CLI and HTTPS use the same typed definition, validation, permissions, approval and execution services. It uses the [outbound SFTP profile](protocols/outbound-sftp.md), including its loopback-only development network, required extensions, bounded workers and uncertain-receipt rules. This is a foundation for the full workflow engine; schedules, conditions, collection, processing, visual editing and AI proposals remain required work.

## Register the receiver once

A connection version fixes the receiver address, SSH username, directory, pinned public host key, private-key reference and client public fingerprint. Only local `connection-register` accepts public-key and private-key file references. HTTP workflow input can select registered IDs; it cannot introduce a key path, new host trust or an arbitrary destination.

Use a root-mounted owner with `admin` and `connections_manage` and a protected request file:

```json
{
  "expected_version": 0,
  "address": "127.0.0.1:2222",
  "user": "receiver",
  "directory": "/inbox",
  "host_public_file": ".private/receiver-host.pub",
  "key_file": ".private/outbound-client.key",
  "key_public_file": ".private/outbound-client.pub"
}
```

Run `connection-register --request-file .private/connection.json --idempotency-key receiver-registration` with the existing tenant, partner and protected token selectors. Registration validates the protected identity and public fingerprints without contacting the receiver. Its `resource` result contains a connection ID, version, definition hash and public review metadata. It omits private-key references and host-key wire data from HTTP/CLI views. Secret values never enter the database or journal.

To change a receiver or key reference, register a new immutable version using `connection_id` and `expected_version` for the current last version. Version two does not replace version one inside old workflows. Explicitly revoke a selected version with its hash and state revision when it must stop being used. `connection-revoke` and the corresponding HTTPS decision recheck owner authority. Revoking any connection version referenced by a run freezes that entire run through both workflow execution and direct delivery commands, including after the step using that connection completed. Existing successful receipts remain historical observations.

The runtime still uses ordinary protected key files; protected provider custody, overlapping live rotations and audited rebinding require further work. Registering a newer version is not proof of a seamless rotation.

## Define, validate and review

The definition contains only supported typed steps and explicit registered connection versions:

```json
{
  "schema_version": 1,
  "name": "settlement delivery",
  "steps": [
    {
      "id": "send_primary",
      "kind": "sftp.deliver",
      "connection": {"id": "CONNECTION_UUID", "version": 1, "hash": "CONNECTION_HASH"},
      "filename": "settlement.csv"
    }
  ]
}
```

The placeholders above must be replaced with actual registered values. Step IDs are unique lowercase identifiers; filenames are one bounded ASCII component. This initial profile supports 1–16 ordered steps using the same source file. Unsupported task kinds, scripts, expressions, recipient overrides and unknown fields fail. Input is at most 32 KiB, at most sixteen nesting levels and 4,096 parsed values. Duplicate JSON keys and mixed-case field aliases fail before typed decoding. Canonical normalization occurs before hashing or retry comparison.

For validation, submit `{"definition": DEFINITION, "file_id": "OPTIONAL_ACCEPTED_FILE_UUID"}` through `workflow-validate --request-file .private/preview.json` or `POST .../workflows/validate`. The result includes the canonical definition/hash, registered destination review metadata, source identity if requested, required approval, and each planned final-name pattern. It makes no remote connection and writes no domain events or intents. The native exercise succeeds while the selected receiver is stopped. Validation is not execution or approval, and checking accepted metadata does not replace the worker's byte verification.

Create a draft with `{"expected_version": 0, "definition": DEFINITION}` through `workflow-draft` or `POST .../workflows/drafts`, with an idempotency key. Creating the first version allocates a workflow ID. To edit, supply that `workflow_id` and the current last `expected_version`; the result is a new draft version. The prior version and any run using it keep their original meaning. A new draft receives no execution authority.

Read exact versions with `workflow-status --workflow-id ID --version N`. Compare two with `workflow-diff --workflow-id ID --version NEW --against-version OLD` or the HTTPS diff route. The difference includes both complete definitions/hashes and ordered lists of added, removed and changed step IDs. Connection changes are visible references, not automatic replacement of recipients.

`workflow-approve --workflow-id ID --version N --definition-hash HASH --expected-revision REV --idempotency-key APPROVAL_KEY` approves only the reviewed definition and current actor authority. `workflow-revoke` uses the same exact preconditions. A **version** identifies immutable definition contents; a **revision** counts its state changes, such as approval and revocation. Changing an account policy invalidates its frozen approval authority; an old approval cannot silently adopt the new policy. Draft a newly reviewed version rather than modifying an old approval.

## Create and execute a run

Use the approved reference and exact accepted source ID:

```json
{
  "workflow": {"id": "WORKFLOW_UUID", "version": 1, "hash": "WORKFLOW_HASH"},
  "file_id": "ACCEPTED_FILE_UUID"
}
```

Submit this through `workflow-run --request-file .private/run.json --idempotency-key RUN_KEY` or `POST .../workflow-runs`. Run creation freezes the workflow revision/hash, accepted file ID/length/hash/policy/event, storage UUID, actor mount/authority revision and every step's exact connection version. The run, all step-to-delivery bindings, queued delivery intents, events and original command receipt commit in one PostgreSQL transaction. A failure while binding the last step leaves none of that partial run committed. A retry returns the original run resource and creates no extra intent.

Call `workflow-work --run-id ID --idempotency-key DISPATCH_KEY` or `POST .../workflow-runs/ID/work` with an empty body. One call selects at most one eligible step. It first persists a dispatch decision fixing that step's delivery ID. Retrying the **same** key keeps that selection even after the step succeeds or the server restarts. A fresh key selects the next eligible step. This prevents a lost reply from accidentally starting the following delivery.

The dispatcher and direct delivery worker enforce the same runtime bindings. Every earlier step must have a persisted successful integrity receipt. The workflow must remain approved, every referenced connection version active, source access current and the frozen actor authority/storage identity unchanged. Workers repeat these checks at lease, stream and publication boundaries. Unknown task kinds cannot fall through to a shell or another executor.

Run creation and execution need `workflow_execute`, `read` and `deliver`; they do not acquire those permissions from a definition or model response. Draft editing needs `workflow_manage`, and approval/revocation needs `workflow_approve`. This initial ownership model also requires root `/` and keeps all five new domain relations actor-private as well as tenant/partner scoped. Migration 8 does not add grants to existing accounts. New development bootstrap administrators default to eighteen grants; delegated human lifecycle remains open.

## Status and recovery

`workflow-run-status --run-id ID` or the HTTPS GET returns:

- `run`: the persisted run projection and its state revision.
- `steps`: each exact delivery identity, state, attempt count and recorded observation.
- `observed_state` and `observed_reason`: the deterministic state computed from current receipts and configuration.

A new run with no dispatch or attempt is `queued`. A persisted dispatch is `running`; its reason distinguishes preparation from bytes in progress or waiting for another worker. Revocation, a blocked delivery or an uncertain publication needs `attention`. `succeeded` means every required integrity receipt exists. It does not mean the receiving business application processed the file.

If a process dies after a delivery receipt commits but before the run projection updates, the GET can truthfully report an observed success while showing the older stored projection. Retrying the same dispatch key repairs the projection without resending bytes. Such a completed run cannot be relabelled cancelled just because the projection lagged.

An uncertain first delivery blocks the second step. Use the existing read-only `delivery-reconcile` path under current workflow and connection authority. A matching reserved final file can recover an observed receipt; missing bytes retain ambiguity. Then retry the original dispatch key to observe that same step, and use a fresh key only when intentionally advancing. Revoked workflows/connections remain frozen; an independently authorized recovery/rebinding policy is still required before their credentials can be used again.

`workflow-cancel --run-id ID --definition-hash WORKFLOW_HASH --expected-revision RUN_REV --idempotency-key CANCEL_KEY` cancels queued work and its remaining queued/retry intents atomically. It rejects live staging, publishing or ambiguous steps; stopping an active external action and resolving its outcome needs further work. Cancellation never erases a successful remote effect or uncertain receipt.

[Assistance controls](assistance.md) can prepare a proposed draft without granting workflow approval. The endpoint client is disabled by default, and local model loads remain disallowed on this shared machine. No model is called by this executor. Existing typed execution has no inference dependency. This establishes ordinary execution of the current task type; it does not qualify model planning, diagnosis, outage behavior of a future model integration, or either required private model profile.

## HTTPS routes and evidence

All routes use the existing tenant/partner prefix, scoped bearer token and TLS. Mutations require `Idempotency-Key`; decisions use `{"definition_hash":"HASH","expected_revision":N}`.

| Route | Effect |
| --- | --- |
| `GET connections/ID/VERSION` | Authorized public review metadata; no secret references. |
| `POST connections/ID/VERSION/revoke` | Revoke that exact registered version. |
| `POST workflows/validate` | Read-only typed validation and planned effects. |
| `POST workflows/drafts` | Create an immutable draft version. |
| `GET workflows/ID/VERSION` | Read that authorized definition and approval state. |
| `GET workflows/ID/VERSION/diff?against=OLD` | Compare two authorized versions without external contact. |
| `POST workflows/ID/VERSION/approve` | Approve the reviewed hash/state under current authority. |
| `POST workflows/ID/VERSION/revoke` | Revoke that exact approval. |
| `POST workflow-runs/preview` | Read-only exact-input preview with potential and selected effects; see [approved routing programs](workflow-programs.md). |
| `POST workflow-runs` | Atomically create the frozen run and its selected delivery intents. |
| `GET workflow-runs/ID` | Current run projection, steps and derived observations. |
| `POST workflow-runs/ID/work` | Persist one dispatch decision and execute its existing bounded intent. |
| `POST workflow-runs/ID/cancel` | Cancel eligible queued work using exact run preconditions. |

Command resources in idempotent receipts preserve their original snapshot. Fetch status for later progress. Registry versions, workflow definitions, runs, step mappings and receipts require exact immutable events; forced row security is checked live on all twenty-seven domain relations. Deferred SQL checks require all step intents and exact source/connection bindings at commit, rather than trusting only application validation.

`python3 scripts/qualify-workflows.py` uses real PostgreSQL/storage, HTTPS and CLI, multiple connection/workflow versions, a separate stock OpenSSH receiver and independent stock SFTP retrieval. It exercises offline preview, strict input, approval/role/actor/tenant/partner denial, frozen destinations, dispatch replay across restart, dependency refusal, whole-run revocation, conservative ambiguous receipt recovery, a failed final run projection, and queued cancellation. Real database tests also reject false success and changed approved definitions, and show whole-run rollback when a later binding fails. Fuzzing covers both valid and malformed typed input. The foundation runner rejects a source edit during qualification so its manifest cannot silently identify a different candidate.

The profile uses synthetic 2 MiB files and assisted same-machine services. Full customer journeys, visual UI, private AI, schedules/calendars/triggers, conditions/loops/batches/processing, migration import, fair unattended queues, active cancellation/rebinding, broader network/peer/platform support, large files and enterprise/release qualification remain open.

[Held intake](intake.md) is a source gate: a new controlled revision needs a current exact release before workflow run creation and each checked worker boundary. The CSV validator currently runs through the shared intake service; it is not yet a typed per-workflow processing task. Legacy integrity-only sources keep their recorded scope. Signatures, scanning, broader processing tasks and the complete secure-business-file journey remain required.
