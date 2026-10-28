# Initial trust boundaries and attacks

This is a living design record, not a completed security assessment.

| Boundary | What can go wrong | Required control and proof |
| --- | --- | --- |
| Client to protocol/API | Wrong identity, replay, oversized body, slow request | TLS/SSH verification, short scoped credentials, idempotency, size/time/concurrency admission; stock-client rejection tests |
| Identity to tenant/partner | Token chooses somebody else's scope | Authenticate identity first; service authorization plus forced SQL row policies; direct non-owner SQL and API isolation tests |
| Service to PostgreSQL | Missing journal, leaked pooled scope, altered events | Local transaction scope, tenant-aware keys, atomic journal/index/idempotency, least grants; rollback/concurrency/permission tests |
| Service to storage | Partial bytes, path escape, links, replacement, disk full | Private root, generated identities, descriptor-relative confinement, sync before acceptance, exact digest; real filesystem and crash tests |
| Processing to publication | Scanner offline called clean, archive bomb, changed bytes | Immutable revisions, pinned check identity, bounded separate workers, quarantine and current approvals; independent scanner/parser tests |
| Delivery to peer | Changed host identity, forged receipt, double payment | Approved endpoint/trust, durable intent, fencing, receiver receipt contract; independent receiver and crash-after-send tests |
| Browser to action | CSRF, XSS, stolen invitations, inaccessible recovery | Origin/session controls, safe rendering, expiry/recall, WCAG journeys; real browser tests |
| Untrusted data to AI/tool | Prompt injection, invented recipient, private disclosure | Redact authorized context, structured proposal validation, revision-bound approvals, no ambient execution rights; adversarial cases |
| Worker/agent to host/network | Arbitrary shell, SSRF, runaway processing | Explicit capabilities, no imported script execution, isolated pools, approved network targets and budgets; denial tests |
| Operations to retained data | Lost key, inconsistent restore, unsafe upgrade | Key references and custody, consistent backup manifest, clean restore and reconciliation; AI-disabled/offline recovery |
| Build to distribution | Leaked secrets, vulnerable dependencies, fake qualification | Pinned dependencies, scans with feed/input manifests, signed reproducible builds, honest red gates; owner authority before publication |

Host root, storage administrators and PostgreSQL superusers can defeat local controls. Protection against them needs independent retention, key custody and tamper-evident exports; no claim is made yet. A single local disk does not survive disk loss. Payload content and ordinary filenames must stay out of default logs. Public test data is synthetic; credentials and raw evidence stay in ignored `.private/` and `evidence/raw/`.
