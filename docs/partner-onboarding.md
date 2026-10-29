# Record partner contacts and exchange requirements

Open **Onboarding** in the partner workspace to record the people responsible for an exchange and the evidence the exchange must produce. This saves an immutable draft: each edit creates a new numbered version, and earlier versions stay available. It does not configure a connection, grant a contact account access, test a protocol, approve a workflow or activate production.

Full onboarding still requires accounts and credentials, folder permissions, protocol tests, an independent test exchange, exact approval, production activation and key rotation without losing queued work. Those steps are not completed by saving a draft. Existing account and transfer controls remain separate; a draft does not prevent an already authorized account from using them.

## Prepare and review in the browser

Sign into the relevant partner as a current root `/` administrator with both `admin` and `accounts_manage`. Tenant directory authority alone cannot read another partner's contacts. File readers and audit readers cannot read these plans.

1. Choose **New onboarding draft** and name the exchange.
2. Add the responsible contacts. A responsibility such as “Operations” describes a person's job; it grants no application permission. Enter an exact email address without a display-name wrapper. Phone is optional.
3. Add exchange requirements and select a responsible contact from this draft. Choose whether freightctl sends or receives, the required protocol, and the required delivery evidence. These choices describe requirements, including protocols not yet implemented or qualified.
4. Record the receiver agreement and notes where useful. A business acknowledgment requires an actual receiver contract; writing its name does not establish that contract or verify a receipt. Do not put credentials or private keys in these fields.
5. Choose **Review onboarding draft**. Check the complete contacts and requirements, plan ID, previous version, current account access revision and definition SHA-256. The fingerprint identifies the exact reviewed definition. Then choose **Save reviewed draft**.

The review freezes one command and one operation key. If the response is lost, retry from that review. The server returns the original receipt after checking current authority; it does not create another version. If somebody edits the draft or changes your authority, a new write is refused. Cancel, reopen the current draft and review again. Canceling an uncertain response does not undo a write that already committed.

Open a saved draft to edit its current version. **Download saved draft JSON** exports the saved definition and source identifiers, including contact details. Keep it in a protected location. The download is informational; it is not an activation file or a credential.

## Shared API and CLI

All operations use the authenticated tenant/partner scope and the same typed store service:

| Operation | REST path | CLI command |
| --- | --- | --- |
| List current drafts | `GET /v1/tenants/{tenant}/partners/{partner}/onboarding-plans?limit=50&after=UUID` | `partner-onboarding-list --onboarding-limit 50 --onboarding-after UUID` |
| Read latest or historical version | `GET /v1/tenants/{tenant}/partners/{partner}/onboarding-plans/{plan}?version=0` | `partner-onboarding-status --onboarding-id UUID --onboarding-version 0` |
| Save a reviewed version | `POST /v1/tenants/{tenant}/partners/{partner}/onboarding-plans` | `partner-onboarding-save --request-file REF --idempotency-key KEY` |

Version `0` means latest. List responses include `authority_revision`; use it as `expected_authority_revision` for a new command. The current-view response also includes this revision. A new plan uses `expected_version: 0`; an edit uses the exact version being replaced. The next version is allocated by PostgreSQL under the partner account-management lock.

Every CLI operation also accepts `--tenant`, `--partner`, `--dsn-file` and `--token-file`. Use the ordinary non-owner runtime DSN, never the deployment-admin DSN. Set `umask 077` before creating request/result files. An installed executable can be used as follows; development can substitute `sh scripts/go.sh run ./cmd/freightctl`:

```sh
freightctl partner-onboarding-list --tenant TENANT_UUID --partner PARTNER_UUID \
  --dsn-file .private/pg-runtime.dsn --token-file .private/operator.token

freightctl partner-onboarding-save --tenant TENANT_UUID --partner PARTNER_UUID \
  --dsn-file .private/pg-runtime.dsn --token-file .private/operator.token \
  --request-file .private/onboarding.json --idempotency-key UNIQUE_REVIEW_KEY

freightctl partner-onboarding-status --tenant TENANT_UUID --partner PARTNER_UUID \
  --dsn-file .private/pg-runtime.dsn --token-file .private/operator.token \
  --onboarding-id PLAN_UUID --onboarding-version 1
```

The command shape below uses placeholders; replace IDs with distinct lowercase UUIDs and revisions with current observed values:

```json
{
  "plan_id": "PLAN_UUID",
  "expected_version": 0,
  "expected_authority_revision": 1,
  "definition": {
    "schema_version": 1,
    "name": "Settlement exchange",
    "contacts": [
      {
        "id": "CONTACT_UUID",
        "name": "Partner operations",
        "role": "Exchange operations",
        "email": "operations@freightctl.invalid",
        "phone": ""
      }
    ],
    "requirements": [
      {
        "id": "REQUIREMENT_UUID",
        "name": "Daily settlement delivery",
        "contact_id": "CONTACT_UUID",
        "direction": "send",
        "protocol": "sftp",
        "required_receipt": "business",
        "receipt_contract": "Receiver acknowledgment agreement still to be confirmed",
        "notes": "Untrusted requirements; no execution authority"
      }
    ]
  }
}
```

POST requires `Idempotency-Key`; browser cookie requests also require the normal same-origin CSRF proof. Duplicate JSON keys, unknown fields, invented activation/approval fields and oversized inputs are refused. Invalid commands return the stable API error `invalid_onboarding_command`. Stale reviews return a conflict; they cannot be turned into a new action by retrying an old key with changed content.

## Bounds and privacy

A document holds 1–64 contacts and 1–64 requirements, with at most 24 KiB of canonical definition JSON. These are per-document processing bounds. Use another draft for additional exchanges; there is no commercial cap on partners or plans. Lists contain at most 100 current summaries per page.

Names are at most 128 UTF-8 bytes, contact responsibilities 64, emails 254, phones 64, receiver agreement text 512 and requirement notes 2,048. Text must be NFC Unicode. Labels and contact fields reject control characters and surrounding whitespace. Agreement/notes preserve line breaks, tabs and surrounding whitespace; other controls are refused. Each requirement must name a contact in the same document. A referenced contact must be reassigned before removal.

The canonical definition fingerprint uses Go's fixed struct-field order and JSON escaping. The browser independently computes the same fingerprint, including HTML characters and Unicode line separators, before accepting a saved response. It checks the reviewed plan, author, version and definition against the returned receipt.

Migration 19 adds two immutable forced-RLS relations. Ordinary service reads recheck current root account-management authority. Plan versions are shared only with authorized managers inside that partner; retry receipts are private to the original actor. The serving role has only SELECT/INSERT on these new tables. A draft version, its exact source event, completion event and retry receipt commit together or all roll back.

The protected journal retains the original contact/requirements payload. Ordinary event feeds and signed audit snapshots replace these two event payload types with a redaction marker and SHA-256 of the original payload. That marker lets an auditor correlate a retained source without receiving its contact text. It does not reconstruct the source. Database administrators remain inside the documented trust boundary; retention, erasure and independent protected archival remain required work.

Saved outbound SFTP requirements can use [recorded connectivity tests](onboarding-connectivity.md) against an exact registered connection revision. A read-only connectivity result still needs separate file exchange evidence, approval and activation.

The native partner exercise covers draft review, exact lost-response recovery, concurrent edit refusal, authority revocation/restoration, historical reads, audit redaction, draft export and server restart, followed by the existing native/stock-curl file exchange. It uses synthetic data on one host with assisted prerequisites. It does not qualify full onboarding, independent adoption, business acknowledgments, complete accessibility or production activation. No model is loaded.
