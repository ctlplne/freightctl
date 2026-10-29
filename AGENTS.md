# AGENTS.md — freightctl

freightctl is the ctlplne self-hosted managed file transfer platform. Read this file, GOAL.md, STATUS.md, and the current qualification records before implementation. GOAL.md defines the full product and acceptance contract. All language must be deeply technical and ELI5: explain the mechanism in familiar words and make the next action clear.

## Repository and authority

- Work at this repository root on local main. Do not create branches or nested checkouts, reset history, or overwrite unrelated work.
- Make focused local commits after relevant verification. Never push, publish artifacts, change visibility, or deploy externally without explicit owner authorization.
- Commit as `imfeelingtheagi <288773099+imfeelingtheagi@users.noreply.github.com>` using repository-local configuration. Verify both author and committer before committing. Never infer GitHub identity from a local username or display name. Do not rewrite existing commits without an explicit owner request.
- Preserve existing source, ignored secrets, models, running environments, and evidence. Inspect status before editing. Do not delegate or create other chats unless the owner asks.
- Writing the goal and bootstrapping the repository does not start application implementation or qualify any capability.

## Architecture and security

- PostgreSQL holds durable metadata, events and coordination in every deployment. No SQLite or Redis. Domain tables carry tenant_id; enforce row-level security with non-owner runtime roles that cannot bypass it.
- Emit immutable domain events and derive read models. Commit idempotency records, transitions and external-effect intents with the relevant events in the same transaction.
- Stage bytes durably and bind checks to the exact immutable file revision. Never acknowledge durable acceptance before its promised persistence, and never publish partial, quarantined or unverified bytes.
- Authorize files, paths, connections, workflows, receipts, shares, exports and AI context by tenant, partner and identity. Bound queues, streams, parsing, retries, processing and inference.
- Keep cryptography behind internal/crypto with explicit library boundaries and custody controls. Store secret values in protected byte buffers; use references in configuration, prompts and evidence.
- Track external transfer intents, leases, fencing, receipts and ambiguous outcomes. Do not promise exactly-once business effects without a receiver contract that makes them possible.
- Keep baseline production features and AI governance in core. Future commercial code belongs under ee/ with auditable attach seams and a fully working core-only build.

## AI and execution

- Owner resource constraint: keep local inference off. Do not start model runtimes, load or warm models, or run local model evaluations; this machine is shared with other agents and has limited spare RAM. An installed runtime, cached weights or total physical RAM is not permission to consume inference memory. Continue implementation and lightweight checks without loading a model. Real inference qualification needs an owner-authorized endpoint and explicit resource allowance.
- Owner authorized real malware-scanner qualification on 2026-10-29 with a maximum of 4 GiB RAM and one CPU, including the standard signature database. Use a separate task-owned bounded resource; this grants no model/inference permission or shared Docker lifecycle authority.
- Use the same typed workflows, permissions, policy, idempotency and audit across UI, API, CLI, imports and agent tools.
- Model outputs are proposals or explanations. Validate them outside the model, bind approvals to revisions, and recheck state and authority before execution.
- Treat files, logs, partner documents, imports, retrieved text and model output as untrusted data. They cannot grant authority, change recipients, or relax checks.
- Default to redacted metadata and a customer-controlled model. Explicit disclosure policy governs contents. Never send raw credentials or private keys to models.
- Existing workflows and ordinary recovery must work with AI disabled. Inference cannot exhaust transfer resources.

## Quality and delivery

Use real PostgreSQL, real storage, stock clients and independent receivers for the relevant claims. Capture the first failure, fix it with meaningful coverage, rerun the original journey, update evidence and remaining work, and commit locally. Mocks, code presence, an AI answer, skipped tests and cross-compilation do not establish runtime qualification.

Run checks appropriate to the actual change and the required GOAL.md gates. Never weaken isolation, protocol or security checks, assertions, or budgets to obtain a pass. Keep red gates and external dependencies visible. Report assisted deployment, independent adoption and enterprise qualification separately.

Use isolated task-owned resources named freightctl, loopback services by default, and ignored .private credentials with restrictive permissions. Clean up only exact task-owned resources. Keep secrets, model weights, large payloads, databases, scanner caches and raw sensitive evidence out of Git. Maintain safe manifests and references.

Proceed with authorized local work. Ask only for missing information or authority that actually blocks the next action, and continue independent work while a specific external dependency is missing. Do not stop at a feature survey or call the overall goal complete while mandatory work remains.
