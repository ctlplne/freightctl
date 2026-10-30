# Review recorded onboarding exchanges

An outbound SFTP requirement can now be compared with an existing connectivity probe and workflow delivery. The review reads their durable records. It makes no receiver contact and cannot create a run, retry a delivery, approve onboarding or activate production. It compares the saved direction, protocol and receipt level; contact obligations, free-text notes and receipt contracts still need human assessment.

This is implemented but runtime qualification remains pending. The new PostgreSQL cases compile but have not executed. A native browser journey, independent receiver exercise through this review, authority-change races and full current-source gates remain required. F026's separate full replay remains deferred at the owner's request.

## Operator sequence

1. Save the partner requirements. Run the explicit connectivity test against the selected registered connection; inspect its recorded outcome.
2. Use the ordinary approved workflow to exchange a safe test file with the intended receiver. Inspect the run and its strongest receipt. This review never sends the file for you.
3. In the saved onboarding draft, open **Review file exchange evidence**. Select the outbound SFTP requirement. Copy the probe UUID from connectivity history, the run UUID from its workflow-run receipt, and the exact step ID from the approved workflow definition. Choose **Compare recorded exchange**.
4. Inspect the source, connection/workflow versions and hashes, delivery ID, stored receipt hash, transferred-object digest/length and snapshot hash. A recipient-encrypted delivery has a different transferred-object digest from its plaintext source; the review checks the stored link between both.
5. Assess the contact obligations, notes and receipt contract. Explicit onboarding approval, activation and queued-work credential lifecycle are still required and are not implemented by this review. A matching recorded receipt does not activate the partner.

The API uses `POST /v1/tenants/{tenant}/partners/{partner}/onboarding-exchange-review`. POST carries a bounded selection; it changes no domain state and needs no idempotency key. TLS and ordinary bearer/browser-session authorization still apply. Browser requests retain the normal CSRF checks.

The same selection is accepted by `freightctl partner-onboarding-exchange-review --dsn-file .private/pg-runtime.dsn --token-file .private/operator.token --tenant TENANT_UUID --partner PARTNER_UUID --request-file .private/exchange-review.json`.

```json
{
  "plan": {
    "id": "00000001-1111-4111-8111-111111111111",
    "version": 2,
    "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  },
  "requirement_id": "00000002-1111-4111-8111-111111111111",
  "probe_id": "00000003-1111-4111-8111-111111111111",
  "run_id": "00000004-1111-4111-8111-111111111111",
  "step_id": "send",
  "expected_authority_revision": 7
}
```

These are synthetic identifiers. Use exact references from the saved draft, probe, run and current account. The body cannot supply an endpoint, private key, receipt, success flag, approval or activation. Missing, duplicate and unknown fields are refused by the ordinary typed boundary.

## What is checked

The existing root-scoped `admin`/`accounts_manage` authority is required, together with `connections_manage`, `read`, and one of `workflow_manage`, `workflow_approve` or `workflow_execute`. Existing grants do not change. Probes, workflow configurations, runs and deliveries stay actor-private under the existing tenant/partner row-security rules. Plans retain their existing scoped management visibility.

One scoped transaction reads and checks the selected records. The probe must refer to the exact latest saved plan, requirement, connection and authority. The run must use the same current namespace and authority, its source must still be accessible and equal the accepted file, and its exact workflow must still be approved with active connections and available selected encryption recipients. The selected step must use the exact probed connection. IDs from unrelated successful exchanges cannot substitute for these links.

A successful probe and completed workflow/delivery are required before a receipt can match. The review reconstructs the immutable delivery definition and checks its digest, workflow/run/step/connection links, source, storage, namespace, authority, destination, filename and encryption policy. An encrypted delivery must also bind the exact stored ciphertext to its source, policy and delivery definition. Remote receipt digest/length and host identity must match the intended transferred object. Raw private connection references, receiver paths, payload bytes and peer text are not returned.

A remote integrity receipt can satisfy a recorded transport or integrity requirement. A business requirement remains `business_receipt_missing`: remote file existence, hash, length and file fsync do not establish that the receiver processed the business records. Reconciliation can observe integrity without acknowledging an earlier file fsync. Directory durability across power loss remains unestablished.

The snapshot carries exact revisions and hashes, and the browser independently reconstructs its Go-compatible hash. Its observation time is separate from the snapshot hash. Repeated reads can observe newer state; the snapshot is not a reservation or a durable approval. Any later approval/execution must recheck exact current state, authority, protected storage/credentials and policy. There is no claim that historical probe evidence is a fresh receiver test.

The query has a ten-second context deadline, existing database statement bounds, indexed object lookups and at most the existing sixteen workflow steps. Request decoding retains the 32 KiB/depth/token/duplicate-key limits; the browser validates bounded metadata and exact selected identities. It never reads file contents or loads a model or scanner.
