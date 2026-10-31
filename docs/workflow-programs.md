# Approved routing programs

[F040 qualification](qualification/evidence/F040-bounded-routing.json) covers the selected assisted same-host component through stock clients and the browser. The complete product, J03 and release qualification remain open. Models and the scanner stay off during this work; F026's final aggregate remains owner-deferred.

Schema 2 adds decisions to the ordinary workflow definition. Keep the existing `steps` array as the catalog of approved delivery templates. Each template fixes a registered connection revision, literal destination filename and optional encryption policy. Add a `program` that selects templates from that catalog. Schema 1 keeps its existing ordered meaning and canonical fingerprints.

For example, a collected north settlement selects `north` and then `audit`; a south settlement selects `south`. An unmatched file records an explicit local outcome. Its bytes remain under ordinary file access and intake policy, and no delivery intent or receiver receipt is created.

```json
{
  "nodes": [
    {
      "kind": "if",
      "when": { "op": "glob", "field": "source.name", "text": "north-*.csv" },
      "then": [
        {
          "kind": "for_each",
          "variable": "recipient",
          "steps": ["north", "audit"],
          "body": [{ "kind": "deliver", "step_variable": "recipient" }]
        }
      ],
      "else": [
        {
          "kind": "if",
          "when": { "op": "glob", "field": "source.name", "text": "south-*.csv" },
          "then": [{ "kind": "deliver", "step": "south" }],
          "else": [{ "kind": "keep_local", "reason": "unmatched_source_file" }]
        }
      ]
    }
  ]
}
```

This is the `program` value, not a complete definition. The complete definition also needs `schema_version: 2`, a name and the ordinary catalog/source configuration. Every referenced step must already exist in that catalog. A loop variable can select only an item in its approved finite list. Neither a filename nor a rule can construct a recipient, connection, credential or executable command.

## Facts and comparisons

The server derives facts from durable records. Callers submit the workflow reference and file ID, not facts or a claimed producer filename.

| Fact | Meaning |
| --- | --- |
| `file.id`, `file.sha256`, `file.policy` | Exact accepted file revision, byte digest and file policy. |
| `file.size_bytes` | Accepted byte count. |
| `source.name`, `source.batch_id` | Original producer filename and batch ID from the captured manifest. |
| `source.file_count`, `source.index` | Original manifest length and zero-based position. |
| `variable` | Current catalog step bound by an enclosing finite loop. |

Source facts require a collection source. They come from the original input claim, captured job and immutable manifest. Renaming a producer file later cannot change a captured file's choice. An unchanged input keeps its original job, workflow revision and run across later collection jobs. A new producer batch ID alone cannot request a resend.

String comparisons support `eq`, `ne`, `prefix`, `suffix` and bounded ASCII `glob` patterns using `*` and `?`. Matching is case-sensitive. Integer comparisons support `eq`, `ne`, `lt`, `le`, `gt` and `ge`. Conditions can combine `all`, `any` and `not`; scoped loop variables are strings containing approved step IDs.

Integer thresholds are canonical decimal strings on the JSON wire. For example, `{"op":"gt","field":"file.size_bytes","number":"1048576"}` means strictly more than one MiB. Go, PostgreSQL and the browser compare exact integers; the browser does not round a 64-bit threshold through a floating-point number.

Current protective bounds are 16 catalog steps, 64 program nodes, 64 predicate terms, four control levels, three predicate levels and 256 evaluation visits including loops. Existing 24 KiB definition and 32 KiB request bounds remain. A selected path may emit each catalog step once. Duplicate effects, a mixture of sending and keeping local, unavailable facts and accidental empty output are refused.

## Review an exact input

Use `workflow-validate` or `POST .../workflows/validate` to review a definition and its potential effect catalog. This does not choose recipients for an unspecified future file.

Use `workflow-run-preview --request-file REQUEST.json` or `POST /v1/tenants/TENANT/partners/PARTNER/workflow-runs/preview` to preview one approved workflow and accepted file:

```json
{
  "workflow": { "id": "WORKFLOW_UUID", "version": 1, "hash": "APPROVED_SHA256" },
  "file_id": "ACCEPTED_FILE_UUID"
}
```

The reply separates `potential_effects` from `selected_effects` and includes the schema-2 `execution_plan` and `execution_plan_hash`. The plan records exact file and original collection facts, selected step order, the decision path and any local reason. The preview reads metadata only: it reserves no queue capacity, writes no runs/events/receipts/intents, opens no payload and contacts no peer. It requires current file access and approved workflow/source authority. A collection's sibling intake checks must already be complete.

The browser's Collections editor provides branch, finite-loop and local-outcome controls over the same definition. Definition review shows the rules and potential recipients. A later version shows whether the routing program changed even when the catalog stayed the same. Each captured input has a separate routing-preview action. Private run inspection loads the original workflow and manifest, independently recomputes the plan and checks its fingerprint before showing the selected recipients.

Preview grants no sending consent. Before admission, the server rechecks current state and authority and compiles the same facts inside the transaction. PostgreSQL independently recomputes the plan and its canonical fingerprint. The run, frozen plan, selected intents, source links, events and original command receipt commit together. Workers execute those intents and never reinterpret fresh rules after a retry.

## Intake, sending and recovery

Every newly captured sibling must pass ordinary intake before useful batch admission. A missing decision for a later sibling blocks the batch without partially admitting an earlier one, even if the send queue is full. The API returns `409 workflow_routing_decision_required` for an undecidable input. Inspect its exact facts and original approved rules; the job retains its original revision. Governed rebinding of an already captured, undecidable input remains open.

Each selected file and step retains its ordinary independent dispatch consent. A later step becomes eligible only after the preceding step's successful integrity receipt. The receiver test also verifies that the later step cannot be approved prematurely. Retrying the original work key observes the same dispatch; a new key is needed to intentionally advance. Neither a file name nor a model output can approve a send.

A local outcome is terminal `kept_local` with zero steps and no invented receiver receipt. A schema-2 direct workflow with an empty recipient catalog can record this outcome with `workflow_execute` and `read`, without `admin` or `deliver`; normal file access still applies. Sending definitions retain `deliver`, live connection/key/source/calendar checks and exact-file consent. Collection work additionally retains its source and namespace permissions.

Plans and source facts remain actor-private under forced row-level security. Ordinary event feeds redact plan/source-name data; protected audit evidence retains the exact facts and choices. Application restart and browser reload preserve the frozen plan. Business acceptance remains unknown unless a separate receiver contract proves it. No new encrypted-peer, production-platform, multi-host or full-journey claim is made by the selected plaintext routing replay.

Run the relevant component profile with `python3 scripts/qualify-routing.py --postgres-container-id EXACT_TASK_CONTAINER_ID`. It checks the recorded task container's resource limits, uses a disposable database and loopback peers, and preserves unique operation outputs and source fingerprints. It exercises the real browser with response loss after actual commits, selected accessibility checks, independent consent and stock SFTP retrieval. Its scope is recorded separately from the owner-deferred aggregate replay.
