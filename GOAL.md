# freightctl product build and qualification goal

- Owner: Shankar
- Product: freightctl, a ctlplne studio product
- Workspace: /Users/shankar/Desktop/ctlplne-freightctl
- Created: 2026-10-28
- GitHub: https://github.com/ctlplne/freightctl
- Origin: https://github.com/ctlplne/freightctl.git
- Branch: main
- Visibility: The existing `ctlplne/freightctl` repository was made public on 2026-11-02 after the owner's action-time confirmation. Source publication and CI pushes were authorized for this task; release artifacts, packages, images and external deployments remain separately gated.
- Status: Product execution contract. Repository bootstrap does not establish product readiness.

## 0 Repository ownership and execution authority

This directory is the repository root. Keep GOAL.md here; do not create another nested freightctl checkout. The owner has authorized a private GitHub repository named ctlplne/freightctl, local Git initialization, and an origin pointing to the URL above. Check existing local and remote state before setup. Reuse an existing matching repository; never replace an unrelated origin, reset history, or overwrite existing work. Record the actual setup result in STATUS.md. Remote creation does not authorize a push.

For implementation turns, read AGENTS.md, this goal, STATUS.md, and the current qualification and remaining-work records. Inspect Git status and active resources before editing. Continue the current implementation from observed state. Preserve unrelated work, ignored credentials, databases, model files, and retained evidence. A stale status entry is a lead to reconcile, not permission to start over.

All autonomous implementation commits directly to local main. Do not create development, task, or agent branches. Never push, publish a release, upload an image or package, change repository visibility, or deploy to an external environment without the owner's explicit authorization for that action. Local commits must work without GitHub. Use the configured owner identity for bootstrap commits; do not alter global Git configuration. Do not create separate chats or delegate work unless the owner asks.

This goal authorizes sustained local implementation, isolated setup, testing, diagnosis, reversible repairs, documentation, and local commits when the owner starts or resumes the build. Writing this goal and bootstrapping the repository is a separate task from implementing the application. Do not claim the application exists because these documents exist.

## 1 Mission and standard of quality

Build freightctl into a leading self-hosted managed file transfer platform. Managed file transfer means exchanging files with partners, customers, employees, and internal systems while controlling access, processing, delivery, failures, and evidence. A working SFTP server is one component of this product.

The target is functional parity with the relevant paid self-managed incumbents, plus demonstrated improvements in migration effort, partner onboarding, operator workload, trustworthy automation, security, portability, and total operating cost. Build complete production workflows and qualify them. A demo, a feature list, generated code, or a passing unit suite cannot establish parity or superiority.

The defining AI experience is: give freightctl the existing setup and a partner's requirements; receive an understandable migration plan, tested transfer workflows, and evidence-backed operational help. AI must improve the whole journey from requirements through recovery. It must remain usable with a customer-controlled model and disconnected infrastructure.

Build in stages to manage dependencies. Every stage contributes to this full destination. Early protocols and journeys establish foundations; they do not silently become the complete product. Missing baseline capabilities remain required until implemented and qualified or the owner explicitly changes scope.

All explanations, interface copy, documentation, and reports must be deeply technical and ELI5. Explain what actually happens in familiar language, define unfamiliar terms, distinguish observed facts from inference, and make the next action clear.

## 2 Free core and the ctlplne self hosted ethos

Use the studio's source-available BUSL-1.1 model: the approved Additional Use Grant permits the intended free production use, and each release converts to MPL-2.0 four years after publication. Use the studio's MPL-2.0 model for appropriate clients and integration libraries. Record and obtain the owner's approved freightctl grant and exact licensing text before distribution. Pending legal text does not block local engineering. Describe BUSL accurately as source-available.

All baseline functionality in this goal belongs in the free core. This includes protocols, automation, partner management, browser transfers, sharing, identity-provider integration, granular permissions, tenant isolation, approvals, auditing and export, encryption, scanning and policy integration, gateways, agents, clustering, recovery, migration, disconnected operation, and AI orchestration and evaluation tools.

Do not impose commercial caps on users, administrators, tenants, partners, connections, protocols, workflow steps, executions, transfers, file sizes, storage, throughput, replicas, model requests, or deployment environments. Administrators configure quotas and bounded capacity to protect their infrastructure. Those controls must have an operational purpose and must not conceal an edition limit.

Core must install, start, restart, upgrade, transfer files, authenticate locally, recover, export data, and use a configured private model without a ctlplne account, trial key, hosted control plane, remote entitlement service, telemetry upload, or vendor availability. Deliver a complete disconnected installation bundle. External partner systems, customer-chosen identity providers, cloud storage, scanning engines, and model hardware can have their own requirements; document them precisely without representing third-party services as free.

Commercial revenue can come from support, long-term maintenance, migration assistance, managed operation, and additional Enterprise services. Future proprietary code belongs only under ee/ and must not be imported by core except through narrowly defined build-tagged attach seams with core-only twins. Core-only builds must execute the entire baseline. An optional Enterprise license can fail without disabling core or blocking access to customer files and evidence. Do not build a billing or licensing portal ahead of the transfer product.

Build original functionality using public specifications, permitted interfaces, and appropriately licensed dependencies. Do not copy proprietary vendor code, private signatures or detection feeds, licensed workflow content, or customer data. Track dependency, model, dataset, and feed redistribution rights.

## 3 Incumbent baseline and parity accounting

Establish a versioned baseline from the current official documentation and available installations of:

| Benchmark | Required comparison |
| --- | --- |
| Fortra GoAnywhere MFT | Paid self-managed transfer, workflow, collaboration, secure forms and mail, gateway, agents, threat-protection integration, clustering, and acceleration capabilities relevant to file exchange. |
| Progress MOVEit | Transfer, Automation, Ad Hoc, Gateway, supported high-availability patterns, reporting, APIs, and current AI functionality. |
| JSCAPE by Redwood | MFT Server, Gateway, monitoring, protocol interoperability, automation, and operational resilience. |
| Cerberus FTP Server | Enterprise and Enterprise Plus customer workflows, administration, partner access, automation, auditing, and deployment expectations. |
| SFTPGo | Both open-source and Enterprise capabilities, deployment effort, storage support, automation, and operator experience. A capable free alternative is a competitive baseline. |
| IBM Sterling and Axway | Enterprise reference workflows for partner onboarding, routing, delivery visibility, scale, and governance. Record the exact product and edition for each reference. |

The first four products define the primary incumbent comparison. Capture their relevant documented paid capabilities in a finite, versioned matrix; do not substitute free editions. Additional IBM, Axway, and emerging requirements must have explicit rows and acceptance criteria before becoming committed scope. Refresh sources before comparative claims. Baseline changes remain visible rather than quietly expanding or shrinking the finish line.

Before substantial implementation, create docs/qualification/parity.json. Each row needs a stable ID, customer job, competitor product and edition, version if known, official URL, observation date, exact behavior, freightctl surfaces, implementation ownership, dependencies, native clients or peer systems, acceptance journey, and evidence. Separate sending from receiving, a gateway from a server, and protocol support from proven interoperability. Split encryption, receipts, duplicate handling, restart, authorization, and failure paths into testable behaviors.

Use explicit states: planned, implementing, implemented but unverified, verified locally, externally qualified, blocked, or owner-approved exclusion. A blocked row names the missing hardware, licensed installation, credentials, network, platform, certification, or product implementation. It remains open. A mock cannot establish vendor interoperability. Documentation establishes documented competitor capability; hands-on tests establish observed behavior. Record those separately.

Maintain docs/qualification/journeys.json, defects.json, ai-evaluations.json, and remaining.json with reproducible evidence. A row cannot become verified because a handler exists, the UI displays a setting, an AI claims success, or a test was skipped. Completion requires the original customer outcome through real interfaces.

## 4 Product boundaries and studio integration

freightctl owns secure file exchange: connections, partner mailboxes, workflows, file processing, delivery verification, sharing, migration, and operations. It must run independently of every other ctlplne product.

Owner-approved scope change, 2026-11-04: the **trstctl feature suite is excluded from freightctl**. Do not bundle or rebuild that suite, add a general credential/trust management control plane, or require a trstctl installation, account, API or service. The former dedicated trstctl credential-lifecycle integration requirement is removed from this build and its acceptance gates. General-purpose certificate-authority infrastructure, organization-wide credential discovery and a standalone secrets-management product are outside freightctl's scope. This decision is recorded as S001 in [the remaining-work ledger](docs/qualification/remaining.json).

freightctl still owns the security needed for its own file exchanges: scoped account and credential enrollment, protected secret storage and references, SSH host verification, TLS certificate validation, OpenPGP operations, and safe rotation/revocation for partners, connections, gateways, agents and queued transfers. Use customer-managed keys, certificates, KMS/HSM backends and ordinary secret providers where configured. These transfer controls remain required under sections 11 and 12; they do not authorize building a general identity, PKI or secrets-management product.

Integrate with probectl and standard observability systems for telemetry, and with ordinary paging services for escalation. Use cratectl for release distribution where useful. These integrations must not make another studio product a prerequisite.

Include the data validation, mapping, routing, and business acknowledgments needed for transfer workflows. Keep general ERP functionality, a universal application builder, an arbitrary autonomous agent platform, and a complete office collaboration suite outside this goal. A boundary must not erase a documented baseline transfer capability. Record unclear cases and resolve them against the actual customer job.

## 5 Required customer journeys

Walk these journeys from a clean installation using public documentation, the browser, CLI, API, and stock clients where appropriate:

1. Install without vendor connectivity, create the first tenant and administrator, configure a storage root, onboard a partner, and complete the first independently verified exchange.
2. Receive a payroll or settlement file, authenticate its sender, verify its signature, scan it, validate its structure, encrypt it for the recipient, deliver it, capture the strongest available receipt, and retain an understandable audit record.
3. Collect scheduled files from remote systems, detect missing or late arrivals, process batches, route by approved rules, and confirm the downstream outcome that the workflow actually promises.
4. Let an invited human upload a large file through the browser, resume after interruption, share it under expiry and access rules, record retrieval, and revoke further access.
5. Onboard a partner through requirements, accounts, credentials, folder permissions, protocol tests, a test exchange, approval, and production activation. Rotate the relevant keys without losing queued work.
6. Diagnose permission errors, an expired certificate, changed host identity, a full disk, unavailable scanner, malformed input, remote outage, and an ambiguous delivery. Recover without silently losing data or causing duplicate business actions.
7. Import an existing transfer estate, explain its behavior, translate supported workflows, identify unsupported behavior, compare outputs, cut over in controlled waves, and roll back safely.
8. Describe a workflow in plain language, review its generated plan, resolve missing information, test it, approve it, and observe its execution. Repeat with the model unavailable to prove existing automation continues.
9. Investigate a failed business exchange using AI, inspect the cited source evidence, approve or preauthorize a bounded recovery action, and verify what happened independently.
10. Prove tenant and partner isolation through every protocol, storage backend, search, audit, AI context, share, gateway, agent, and recovery operation.
11. Operate multiple workers and gateways, kill processes during transfers, restore backups into a clean environment, upgrade with queued work, and verify all acknowledged data and required receipts.
12. Export files, configuration, workflows, partner mappings, receipts, and audit records in documented formats, then recover or move them using ordinary tools.

For each journey record the candidate commit and artifact digests, environment, exact steps, time and assistance, success evidence, failures, recovery, and limits. Run repeated schedules and renewals; one successful execution does not prove unattended operation. Keep everyday operator adoption separate from an assisted demonstration.

## 6 Protocol compatibility and delivery semantics

Provide inbound and outbound roles wherever the baseline requires them. Publish a protocol and client matrix with supported versions, commands, extensions, algorithms, limits, and unsupported cases.

- SFTP over SSH, with ordinary OpenSSH and common enterprise clients. Cover paths, directory listing, upload and download, overwrite, append, rename, permissions, interrupted transfers, and extensions. Treat the legacy SCP wire protocol separately from modern scp clients that use SFTP.
- Explicit and implicit FTPS, with correct passive and active data-channel handling, certificate validation, session behavior, gateway and firewall operation, and resume. Plain FTP is an explicitly enabled compatibility option with restrictive policy and visible warnings.
- HTTPS browser and API transfers with streaming, resumable upload sessions, ranges where supported, integrity validation, and safe handling of interrupted or repeated requests. Support WebDAV operations required by the matrix.
- AS2 sending and receiving, signed and encrypted messages, synchronous and asynchronous message disposition notifications, certificate rollover, digest validation, duplicate message IDs, retries, and failure receipts. A receipt must be correlated to the exact original message and its integrity check.
- AS1 and AS3, AS4, OFTP2, and PeSIT behavior required by captured baseline rows. Specify the profile, role, signing, security, receipt, restart, and peer requirements before implementation. Do not advertise these names based on an HTTP listener or a single happy-path sample.
- Mail-based exchange, message-queue integration, and accelerated large-file transfer where required. Define their security and acknowledgment boundaries precisely.

For proprietary protocols or acceleration products, distinguish functional outcome parity from compatibility with the incumbent's wire format. Implement permitted public standards or original alternatives and measure equivalent outcomes. Record lawful interoperability prerequisites as blockers; do not invent a proprietary compatibility claim or silently drop the relevant requirement.

No protocol success message may promise more than the persisted state supports. Separate received bytes, validated file, published file, dispatched bytes, remote transport acceptance, integrity-confirmed receipt, and downstream business acceptance. TCP completion or an SFTP close acknowledgment does not prove that a payroll processor imported a file. Document which evidence each peer can provide.

## 7 Connections storage and edge deployment

Support local filesystems, customer-mounted network storage, S3-compatible storage, AWS S3, Azure Blob, Google Cloud Storage, remote SFTP and FTPS, WebDAV, and the Microsoft file services and database connections required by the matrix. Explicitly qualify SMB, SharePoint, OneDrive, email, and message-queue connectors. Record cloud identity, API versions, pagination, throttling, retry, encryption, and checksum differences. A local emulator tests a contract; it does not qualify a live vendor service.

Provide virtual folders with consistent permissions across protocols. Paths are tenant- and partner-scoped capabilities, not arbitrary host filesystem strings. Handle symlinks, hard links, mount boundaries, Unicode normalization, case differences, reserved names, object prefixes, and rename semantics deliberately. Explain differences between an object store and a filesystem rather than pretending their guarantees match.

Provide a separate edge gateway for a perimeter network, commonly called a DMZ. It forwards only configured protocol traffic to permitted internal services, supports internal-initiated connectivity where required, and keeps plaintext payload persistence and primary credentials out of the perimeter by default. Define TLS termination, trust, buffering, connection limits, and failure behavior. It must not become a general-purpose proxy.

Provide bounded, least-privileged agents for private networks and remote hosts, with enrolled identities, scoped jobs, signed updates, revocation, connection recovery, and visible health. No arbitrary remote shell is granted by installing an agent. Qualify gateway and agent identity rotation during live workloads.

## 8 Workflow engine and scheduled operation

Use one versioned workflow representation for visual editing, declarative files, CLI, API, imports, and AI proposals. Each execution binds an immutable workflow revision, approved destinations, credential references, policy versions, processing versions, and source file identities. Changing a workflow cannot alter the meaning of an already approved run without a new authorization decision.

Support schedules with time zones, daylight-saving changes, business calendars, holidays, missed-run rules, deadlines, concurrency limits, and bounded catch-up. Cover event triggers, folder monitors, API invocation, manual runs, dependencies, conditional branches, loops, batches, variables, reusable components, and approved external processing. Prevent trigger loops and repeated processing of incomplete or unchanged input.

Tasks must cover collection, copy, movement, safe rename, synchronization, routing, checksums, compression and extraction, encryption and signatures, schema validation, deterministic transformation, database exchange, notifications, approvals, retention, and receipts. Add matrix-required tasks with their complete failure semantics. Watchers must define when a file is complete; an unchanged size for a short interval alone is not a universal proof.

Provide drafts, validation, diffs, test runs, promotion, approvals, rollback to a prior definition, and Git-based configuration workflows. Show the files and external effects a test will touch. A dry run cannot contact a production recipient or execute a destructive action while claiming to be a preview.

Execute processing extensions in isolated workers with resource, filesystem, identity, and network limits. Avoid shell string construction. Operator-approved legacy scripts require explicit capabilities and visible risk; never execute an imported script just to discover what it does. AI-generated code receives no special execution rights.

## 9 Human file exchange and partner administration

Provide a separate, accessible browser experience for partners and recipients. Cover drag-and-drop and batch upload, folders, progress, pause or resume where supported, downloads, identity verification, file requests, secure packages, expiry, download limits, recall, branded portals, accessible error messages, and a clear delivery history. Invitation, account recovery, account expiry, self-service registration, and administrator approvals must work end to end.

Build secure forms and mail-oriented transfer workflows required by the baseline, including browser-based forms, upload constraints, attachments represented as controlled transfer packages, and appropriate mail-client integration. Explain the distinction between sending an invitation, retrieving a file, and reading its contents. Recalling a share prevents future authorized retrieval; it cannot erase a recipient's downloaded copy.

Partner administrators can manage only delegated accounts, credentials, folders, and approved workflows. Support templates, groups, account import, lifecycle policies, contact ownership, onboarding checklists, connectivity tests, and environment separation. Partner A must not learn partner B's file names, users, directory existence, or transfer history.

## 10 Durable state and reliable external effects

Default to a supported Go release, PostgreSQL for durable metadata and coordination, filesystem or object storage for bytes, and a typed web interface using the studio's React and TypeScript conventions. Select supported dependency versions at implementation time and record them. Use PostgreSQL in every deployment; do not introduce SQLite, Redis, or a second coordination database. Additional infrastructure requires an architectural decision with a demonstrated need.

Record immutable domain events in a durable PostgreSQL journal as the source of truth for control state. Build read models and audit projections from those events. Commit events, idempotency records, workflow transitions, and external-effect intents in the same transaction. SQL row changes representing domain mutations cannot bypass the journal. File streams and protocol sessions have their own explicit durable checkpoints; do not write an event per packet.

All domain tables carry tenant_id. PostgreSQL row-level security enforces tenant boundaries using non-owner runtime roles without superuser or BYPASSRLS privileges. Tenant-aware uniqueness and foreign keys prevent cross-tenant references. Administrative maintenance uses separate, audited capabilities. Enforce storage and session isolation in addition to SQL isolation.

Stage incoming bytes durably before acknowledging the corresponding durable acceptance. Validate and scan the exact immutable bytes before publication or dispatch. Filesystem or object storage and SQL do not share an atomic transaction: use a documented staged-commit and reconciliation design that handles crashes at every boundary. Retain enough identity, length, digest, storage version, and journal information to recover without guessing. Never publish partial, unverified, or quarantined bytes.

Every mutating API accepts and honors an idempotency key; protocol operations use explicit session, upload, message, or delivery identities. Replays with identical meaning return the original result; reusing a key with different meaning is rejected. Workers use durable leases and fencing so a worker that has lost ownership cannot complete a conflicting effect.

External actions originate from durable intents. A transfer worker can stream a large file directly while executing such an intent; an outbox record must reference bytes rather than contain the payload. Track progress and remote acknowledgment. Test the crash between remote success and local recording. Claim exactly-once business effects only when the receiving system provides the necessary deduplication or transaction contract. Otherwise expose an ambiguous outcome and use reconciliation or operator review before unsafe retry.

Use separate bounded pools and queues for protocol sessions, scans, transforms, delivery, synchronization, API operations, and model requests. Apply per-tenant and per-partner fairness, admission control, disk and staging quotas, circuit breakers, timeouts, cancellation, rate limits, and bounded retry with jitter. A slow recipient, huge archive, failing model, or busy partner must not exhaust unrelated transfers.

## 11 Security and file custody

Treat the internet-facing transfer service, browser, API, gateway, processing workers, agents, AI boundary, and control plane as distinct trust boundaries. Maintain a threat model and dependency-closure checks for each. Keep configuration administration and payload processing separated by explicit interfaces and identities.

Support OIDC, SAML, LDAP or Active Directory, required RADIUS integration, local accounts, multi-factor authentication, service accounts, short-lived tokens, API keys, and protocol-appropriate public-key or certificate authentication. Apply granular roles, separation of duties, partner delegation, approval policies, account expiry, session revocation, and emergency access procedures. Browser SSO must not silently grant protocol access with broader permissions.

Authorize every file operation, storage reference, workflow step, export, receipt, search, and model context. Recheck live authorization before consequential actions and after changes to identity or configuration. Encrypt transport, enforce host and certificate verification, and fail closed on unexpected remote identity changes. Never automatically trust a new SSH fingerprint because a transfer is urgent.

Scan and validate before files become available under workflows requiring those controls. An unavailable scanner is unknown or blocked, never clean. Bind scan results to the exact bytes, engine and signature versions, configuration, and time. Make quarantine, release, re-scan, and exception approval auditable. Provide an operational local scanning option and interfaces for customer-selected ICAP, antivirus, and data-loss prevention services.

Bound archive recursion, decompressed size, expansion ratio, file count, parser complexity, processing time, memory, and temporary storage. Defend against path traversal, archive escape, XML external entities and signature wrapping, malformed MIME, spreadsheet formula injection in generated exports, decompression bombs, malicious filenames, server-side request forgery, DNS rebinding, and credential leakage. Unsafe redirects cannot turn an approved destination into another host or internal service.

Support retention, deletion, legal holds, file ownership, data residency rules, per-tenant keys where required, and documented backup retention. Deletion must account for replicas, versions, caches, temporary bytes, and retained evidence. Do not promise physical secure erasure on storage where the platform cannot enforce it; document the actual deletion or cryptographic erasure boundary.

Keep secret values, payload contents, tokens, sensitive file names, and model prompts out of ordinary logs by default. Use references and selective redaction in evidence. Deliver vulnerability reporting, patching and upgrade procedures, SBOMs, signed release artifacts, and a documented security response process. A security setting or supported algorithm is not a certification.

## 12 Transfer cryptography keys and identity lifecycle

This section covers credentials and cryptographic operations used by freightctl's own transfers and runtime identities. It does not reintroduce the trstctl suite or the general credential/trust management control plane excluded in section 4. For example, freightctl must validate a partner's certificate and safely use its replacement during queued work; operating a general certificate-issuance service is outside this goal.

Put direct cryptographic operations behind internal/crypto with backend-agnostic interfaces and tested algorithm policy. Protocol libraries that internally use cryptography need a documented dependency boundary; do not copy code or invent cryptographic primitives to enforce an import rule. Keep raw private keys out of the control plane and UI, use a separate narrow key-operation service where custody requires it, and isolate file decryption and transformation in scoped workers.

Support OpenPGP encryption, decryption, signatures and verification, SSH host and user keys, TLS identities, partner certificate pinning where needed, and customer-managed KMS or HSM backends. Bind recipient identity, encryption key and destination in the approved workflow. Show key ownership, fingerprint, expiry, trust, rotation status, overlap windows, and revocation effects.

Keep secret material in bounded byte buffers with best-effort locking, dump exclusion, explicit zeroing, restricted process access, and clear platform limits. Prevent payload or private-key access through diagnostics and model tooling. Store encrypted secret envelopes with auditable access and support external secret references.

Test rotation and revocation during queued jobs, active sessions, asynchronous receipts, retries, and restored backups. Define whether a pending job can use an old key and require a new decision when its security meaning changes. Support modern SSH and TLS algorithm agility, including applicable standardized post-quantum negotiation when libraries and peers support it. FIPS claims must identify the validated module, artifact, mode, operating environment, and applicable certificate; interoperability and certification are separate qualification records.

## 13 AI product requirements

AI is a first-class operating interface over the same governed product used by humans and ordinary automation. Its outputs must become inspectable product objects: workflow drafts, migration mappings, diagnostic findings, transformation proposals, and bounded action plans. A conversational answer alone does not complete an operational task.

### Requirements to tested workflows

Accept plain-language requirements and approved partner documentation. Produce the normal typed workflow representation with source and destination identities, file rules, schedule and time zone, credentials by reference, encryption and verification policy, scan and validation steps, failure handling, retention, receipt requirements, and required approvals.

Identify missing or contradictory requirements. Never invent a recipient, fingerprint, credential, business calendar, acknowledgment guarantee, or security exception. Show an understandable plan and a precise configuration diff. Compile and validate the proposal, run contract checks and isolated test exchanges, and attach their results before activation. A failed test remains visible; the model cannot narrate it into a pass.

For example, a payroll workflow must distinguish collecting a file by 07:00 from confirming payroll processing by 07:00. The proposed schedule, delivery evidence, timeout, and escalation must match the promised outcome.

### Existing estate to qualified migration

Accept supported configuration exports, scripts, manifests, and approved documentation. Use deterministic parsers for known formats, with AI helping explain behavior, find dependencies, map unknown constructs, and draft translations. Inventory schedules, paths, endpoints, credentials by reference, permissions, scripts, transformations, receipts, and downstream effects.

Produce an explicit mapping for every source behavior: translated, needs input, unsupported, or blocked. Never claim a faithful conversion from a plausible-looking workflow. Compare file selection, byte outputs, schedules, access, transformations, error handling, receipts, and observable effects against reference runs. Keep the original configuration intact and record evidence for each migration decision.

### Evidence backed diagnosis and recovery

Answer operational questions using tenant-authorized workflow definitions, execution events, connection state, receipts, policy outcomes, and redacted logs. Cite actual run and event references that an authorized operator can inspect. Show confirmed cause, possible causes, missing evidence, and the next useful check separately. Do not expose private model reasoning; provide a concise explanation grounded in recorded evidence.

Trace the full exchange rather than stopping at the last network request. Explain whether a file was absent, rejected, quarantined, delayed, dispatched, acknowledged, or awaiting a business response. An inferred root cause must be labeled as inference.

Generate bounded recovery plans with exact resource identities, preconditions, effects, and duplicate-delivery handling. Administrators may preauthorize routine actions within explicit policy. Require the configured approval for changes to recipients, host trust, keys, permissions, scanning, retention, destructive operations, or ambiguous deliveries. Recheck state and authority immediately before execution; a stale approved plan must fail safely or return for review.

### File structure and transformation assistance

Detect schema changes using actual parsers and contracts. AI can propose a mapping, explain differences, generate test fixtures, and draft a deterministic transformation. Support CSV, fixed-width text, JSON, XML, spreadsheets, and captured EDI requirements with bounded parsing and visible schema rules.

Preserve monetary precision, identifiers with leading zeros, encodings, date and time meaning, nulls, duplicate records, ordering requirements, and record counts. A similarly named column is not proof of equivalent business meaning. Operators must review ambiguous mappings. The approved transformation becomes versioned, repeatable code or declarative rules; routine processing must not require fresh model judgment for each file or record.

### Reporting and operational assistance

Create reports, partner onboarding checklists, workflow explanations, handover documentation, and suggested operational improvements from authorized product records. Compute counts, durations, rates, and totals with deterministic queries and show their time range and provenance. The model may explain the result; it cannot invent numeric evidence. Use scoped query tools or validated report definitions rather than unrestricted model-authored database access.

Identify unusual volume, lateness, failure patterns, and destination changes with transparent rules or evaluated statistical models. Label suggestions and confidence. An anomaly can trigger investigation or an approved hold; AI cannot silently reroute confidential data or relax security to meet a deadline.

### Other agents as authorized clients

Expose documented APIs and a Model Context Protocol interface, a standard way for AI clients to call tools. Tools include inspecting a partner, validating a workflow, preparing a transfer, checking receipts, gathering diagnostic evidence, proposing a change, and requesting an allowed recovery. Use the same tenant, identity, permission, policy, idempotency, and audit checks as every other interface.

Bind requests to explicit resources and immutable revisions. Advertise tool effects accurately, separate preparation from execution, support cancellation and deadlines, and bound tool loops, runtime, token use, and concurrency. Do not grant an agent a database shell, unrestricted filesystem, arbitrary network access, or a universal administrator token.

### Private models and continuous operation

Support a customer-controlled local inference endpoint and a documented fully disconnected model setup. Provide at least two qualified model and hardware profiles, with licenses, model and tokenizer digests, context limits, resource requirements, and observed task quality. Model choice must not change authorization semantics. Support optional external model endpoints only through explicit administrator configuration and data policy.

Use metadata and redacted evidence by default. File contents, partner documents, filenames, personal data, and secret values have independent access and disclosure rules. Obtain the configured authorization before content is sent to any model, including a local one. Never send raw credentials or private keys. Bound context, redact before transmission, and control retention for prompts, retrieved material, embeddings, caches, and responses. Retrieval indexes must preserve tenant and resource permissions after revocation or deletion.

Treat uploaded files, partner documents, imported scripts, log messages, retrieved text, and model output as untrusted data. Instructions embedded in that material must not change the agent's permissions, selected tenant, approved recipients, or tool policy. Validate structured outputs and tool arguments outside the model. Model configuration, tools, credentials, and policy are administered through separate trusted interfaces.

Existing workflows, protocol sessions, approved transformations, policy, audit, and recovery procedures must continue when inference is slow, unavailable, or disabled. Isolate AI resource usage from transfer capacity. Provide an ordinary UI, CLI, and API path for every required outcome. Include the AI integration and governance in core without mandatory hosted tokens or per-transfer AI fees; document customer compute and optional provider costs.

## 14 AI evaluation and measurable acceptance

Create a small, useful evaluation harness alongside the first AI journey. Grow it with real defects and representative workflows rather than spending the build on a generic benchmark framework. Fix case definitions and expected outcomes before tuning a candidate. Keep development examples separate from held-out cases.

Qualification must include at least 100 representative workflow and migration cases, at least 50 diagnostic incidents, and at least 100 adversarial or authorization cases across the two qualified private model profiles. Include incomplete requirements, conflicting instructions, unsupported protocols, wrong tenants, revoked access, malicious documents, secrets, ambiguous receipts, and changes after approval. Record exact model, prompt and tool versions, hardware, decoding settings, repeated-run behavior, and input datasets with redistribution rights.

Targets are acceptance requirements, not current claims:

- At least 90% of fully specified, supported workflow cases produce a draft that passes semantic and execution assertions within the published bounded attempt budget. Measure the unassisted rate and human correction effort separately.
- Mandatory reference workflows and migration fixtures must pass their deterministic acceptance tests before being offered as supported. Missing inputs must be surfaced; unsupported cases must not be counted as successful conversions. Publish overall source-estate coverage and unsupported rates so easy cases cannot disguise poor coverage.
- At least 90% of incidents with sufficient evidence identify the expected primary cause, with event references that support it. Score cases needing more evidence for a correct request or abstention rather than a confident guess. Critical claims and computed figures in accepted answers must resolve to authorized source records.
- Every adversarial test must preserve the intended authorization and data-disclosure boundary. Any observed forbidden execution, cross-tenant disclosure, exfiltration, or forged success is a release blocker. Passing the suite is evidence for those tests, not a proof against every possible attack.
- Model outages and overload must not corrupt drafts or interrupt ongoing transfers. Existing workflows and standard recovery must pass with AI disabled.

Measure task success, invalid plans rejected, operator edits, time to a validated workflow, time to verified recovery, unsupported-case detection, false diagnoses, tokens, latency, CPU or GPU memory, and inference cost. Compare the same jobs with ordinary freightctl interfaces and documented incumbent workflows. Do not publish a time-saving or accuracy percentage without the case set, method, baseline, and limits.

## 15 Migration cutover and exit

Provide supported importers for the primary incumbents and ordinary shell, PowerShell, scheduled-task, and cron-driven transfer setups represented in the matrix. Start with permitted exports and public interfaces. Treat proprietary encrypted fields, unavailable schemas, platform-specific scripts, and vendor-only APIs as explicit migration dependencies rather than guessing their meaning. Import secret references or use an isolated customer-controlled re-enrollment process.

Produce a complete estate inventory, dependency graph, coverage report, proposed configuration, test plan, and cutover plan. Every original schedule and workflow needs a destination or a visible unresolved row. Preserve stable file identities, partner naming, access boundaries, retention obligations, and required receipt history where technically and legally supported.

Run a shadow or comparison mode without performing duplicate production effects. Explain exactly which endpoints, test data, and notifications it uses. Where dual execution would cause two payments or two imports, compare against isolated recipients, recorded inputs, or explicit receiver deduplication contracts. Test schedule boundaries, file-selection rules, transformations, errors, and restart behavior.

Support phased partner migration, pause and drain, resumable queues where compatible, freeze windows, credential and host-key transition, explicit rollback checkpoints, and reconciliation of ambiguous in-flight transfers. Prove external behavior through independent clients and receivers. The AI migration assistant prepares and explains the same evidence; it does not bypass these checks.

Provide documented, versioned exports for files, manifests, connections, partner identities, permission mappings, workflow definitions, calendars, policies, keys or key references as permitted, receipts, execution history, and audit records. Include checksums and a restore or portability exercise. No commercial license or model availability may be required to leave freightctl.

## 16 Operator experience and automation surfaces

Provide a coherent administration UI, partner portal, CLI, REST API with OpenAPI, declarative configuration, and supported automation integrations. Required features must be discoverable and operable through documented surfaces. Use stable machine-readable errors, actionable human explanations, consistent operation IDs, pagination, search, bulk actions, cancellation, and progress reporting.

Make configuration understandable: show partner, environment, protocol, destination, credential reference, trust identity, file rules, required checks, schedule time zone, expected receipt, and retention in one reviewable plan. Distinguish a draft, tested configuration, approved revision, active schedule, queued run, and completed business exchange.

Cold-start onboarding must lead to a real exchange with a stock client and an independent receiver. Supply safe sample data and an optional demo separately. Product-driven setup, credential enrollment, diagnosis, recovery, audit export, upgrade and restore must not require reading source code or undocumented SQL. Follow the ctlplne visual language where suitable while designing for the actual transfer operator and partner.

Meet WCAG 2.2 AA for critical browser journeys, keyboard navigation, progress and error announcements, readable status distinctions, large lists, and interrupted uploads. Qualify current supported browsers. Preserve ordinary administration when AI is disabled.

## 17 Availability backup and disaster recovery

Support a documented single-node deployment, clustered transfer and workflow workers, redundant gateways, and a qualified multi-host production profile. Define the dependencies and failure model for PostgreSQL, staging storage, object storage, keys, agents, clocks, and network partitions. A local container cluster does not prove multi-host availability.

Use ownership leases and fencing for schedules, jobs, locks, upload publication, and delivery. Test worker death, delayed workers, duplicate messages, network partitions, database failover, storage outage, full disk, clock skew, gateway loss, and simultaneous recovery. Explain whether sessions resume, restart, or need client reconnection. Do not call interrupted bytes lost if a supported resume path exists, and do not call a restart seamless.

Back up metadata, journal, workflows, configuration, keys or key references, payload versions, receipts, and required evidence consistently. Restore into a clean environment with vendor connectivity blocked, verify file digests and permissions, reconcile in-flight work, and prove that schedules resume without duplicate external effects. Test upgrades and supported rollback paths with active and queued workloads.

For the qualified HA profile, target no loss of durably acknowledged data under its documented single-node failure model. For the reference disaster-recovery estate, target a recovery point within five minutes and recovery within thirty minutes. Define estate size, topology, backup frequency, key availability, and exclusions before measuring. A single disk cannot satisfy redundant-storage claims, and a process restart cannot qualify site recovery.

## 18 Observability audit and operational evidence

Give each business exchange, workflow execution, file revision, protocol session, delivery attempt, processing step, receipt, approval, and AI proposal stable correlated identities. Show a timeline from expected arrival to the strongest verified recipient outcome. Record pending, blocked, failed, retrying, ambiguous, quarantined, canceled, expired, and completed states truthfully.

Provide metrics, structured logs, distributed tracing, OpenTelemetry integration, health and readiness endpoints, dashboards, searchable transfer history, scheduled reports, and alerts for failures, missing files, deadlines, capacity, expiring identities, quarantine, and loss of dependencies. Distinguish internal health from the ability to complete a real transfer.

Audit actor, tenant, authority, operation, old and new configuration references, workflow and policy versions, file digest, destination, approvals, external receipts, and outcome. AI actions additionally record model and tool versions, disclosed data categories, relevant source references, proposed actions, and actual tool results with configured redaction and retention.

Make audit evidence tamper-evident and independently exportable, with integrity verification and protected retention. Explain the protection boundary; append-only application code alone cannot defeat a database superuser. Required audit persistence failure must have explicit fail-closed or durably buffered behavior. Do not silently discard evidence to keep a success indicator green.

## 19 Performance and operating cost targets

Define reproducible workloads and reference hardware before optimization. Targets below are initial engineering acceptance targets; they are not measured product claims. Publish the actual candidate, storage, encryption, scanning, model hardware, network, file sizes, concurrency, warmup, duration, and native results. Changes to a target need an explicit documented engineering decision; failure cannot be hidden by relabeling the workload.

- Cold start: a competent operator using published instructions completes the first verified SFTP or HTTPS exchange within thirty minutes on supported local infrastructure, with every required external prerequisite and administrator intervention recorded.
- Reference transfer node: on an 8-vCPU, 16-GiB Linux host with adequate NVMe storage and networking, sustain at least 1 Gbit/s aggregate encrypted transfer of large files without AI or scanning in the data path, and publish end-to-end results with each required processing policy enabled.
- Stream memory: bulk file handling remains bounded independently of file size. Target no more than 64 MiB of incremental application buffering per active bulk stream, excluding explicitly bounded processing engines, kernel buffers and shared caches. Measure those other costs separately.
- Scale: qualify at least 1,000 concurrently authenticated sessions, 1,000 partners, 10,000 configured workflows, and one million file or execution records in the reference estate. Report active transfer concurrency, queueing, and admission behavior separately from idle sessions.
- Responsiveness: target p95 below 250 ms for ordinary metadata APIs under the reference workload, excluding remote authentication, transfer bytes, heavy exports, and inference. Measure their latency separately rather than hiding it in averages.
- File size: prove resumable transfers at 100 GiB and a streaming correctness test at 1 TiB on adequate storage. Smaller local tests remain useful but do not qualify those sizes. Document connector and peer limits instead of advertising a universal untested maximum.
- Endurance: complete a 72-hour representative mixed-workload run with scheduled arrivals, transfers, failures, scans, rotations, and bounded AI activity. Track memory, temporary bytes, queue growth, connection leaks, receipt reconciliation, and orphan cleanup.
- AI efficiency: publish validated-workflow latency, diagnosis latency, tokens and resource usage on both private model profiles, including cold starts and outages. Compare operator time and total operating cost; a zero license fee does not make hardware, storage, scanning, inference, or administration free.

Benchmark acceleration under realistic bandwidth, latency, packet loss, CPU limits, and competing traffic. Respect congestion and fairness. A faster localhost copy does not prove better wide-area delivery or compatibility with an incumbent's accelerator.

## 20 Engineering security and interoperability gates

Write meaningful regression tests before or alongside implementation. Use real PostgreSQL with enforced runtime permissions and real filesystem or object-storage behavior for durability, isolation, idempotency, journal, and outbox tests. Simulated peers and cloud emulators are useful contract tests; report their scope accurately.

Publish conformance suites and qualify stock clients and independent receivers. Include OpenSSH, curl, lftp, appropriate browser clients, GnuPG or other independent cryptographic tooling, and standards-based AS2 and other protocol peers as relevant. Pin versions and collect native outputs. Vendor comparison requires authorized installations and explicit edition and version records.

Use property tests and fuzzing for protocol parsing, MIME and XML, archive extraction, path resolution, workflow expressions, importers, transformations, receipt correlation, and model tool arguments. Test cross-tenant and cross-partner access through every surface. Include replay, unauthorized resume, symlink races, content replacement after scanning, forged receipts, signature wrapping, destination changes, revoked approvals, and crashes at each publication and external-effect boundary.

Wire appropriate build, formatting, lint, static analysis, unit, race, integration, protocol conformance, frontend type and build checks, UI journeys, architecture checks, migration tests, AI evaluations, packaging, and security scans into local commands and CI. Add suites when their implementation exists; an absent or placeholder command cannot report success. Test core-only and any Enterprise-attached builds.

Use govulncheck for shipped Go configurations, dependency auditing for shipped JavaScript, Gitleaks or an equivalent for changes and history, Trivy or an equivalent on actual images and release artifacts, and applicable source and runtime security analysis. Record scanner versions, feed freshness, input coverage, completion, native results, reachability assessment, and limitations. A missing scanner does not stop independent testing. Do not weaken rules, assertions, protocol validation, tenant isolation, or performance budgets to turn a failure into a pass.

Treat failures introduced by a change as blockers to committing it. Record baseline failures and continue focused work, while keeping required gates visibly open. GitHub CI supplements local verification and remains unverified until it runs. Cross-compilation is build evidence, not a native runtime test. External certification, licensed vendor comparisons, real cloud accounts, legacy platforms, and multi-host qualification remain concrete open requirements until exercised.

## 21 Installation packaging and lifecycle

Provide signed, reproducible release builds, SBOMs, container images, an evaluation deployment with PostgreSQL, production deployment guidance, Helm charts, gateway and agent packages, and a complete air-gapped bundle. Keep model installation optional for ordinary transfers; include documented local-model packaging and licensed weight acquisition for private AI operation. No installer may silently fetch dependencies after a disconnected installation has been declared complete.

Qualify Linux amd64 and arm64 for the server, workers and gateway, Windows amd64 for the server and required agents, and supported Linux and Windows endpoint integrations. macOS is a supported development and client environment where practical. Record native operating-system tests. Legacy platform and proprietary endpoint requirements in the matrix need actual permitted interoperability testing or remain blocked; an intermediary connector must not be described as a native port.

Deliver secure first-run enrollment, supported identity configuration, backups, restore, upgrades, rollback boundaries, uninstall, export, log collection with redaction, capacity planning, and operational runbooks. Document the ports, dependencies, privileges, persistent directories, key custody, storage guarantees, network flows, and offline behavior. Use accessible defaults and actionable diagnostics without weakening security.

Use the real interfaces in documentation examples and test them. An assisted demo must be clearly separate from a clean installation. Retain existing customer data during upgrades and uninstall unless the operator explicitly requests a documented destructive action.

## 22 Execution stages

### Stage 0 Establish the working contract

Verify the repository and preserve its state. Create architecture decisions, threat model, the versioned parity matrix, journey inventory, qualification ledgers, source records, and a prioritized remaining-work record. Pin the initial competitor baseline and define native-client environments. Establish a local development path and the smallest useful testing spine. Do not spend the stage generating a large speculative framework.

### Stage 1 Prove complete secure exchanges

Build PostgreSQL isolation and durable events, staged file custody, authentication and permissions, bounded processing and delivery, the operator surfaces, and real SFTP and HTTPS journeys. Prove independent delivery verification, failure handling, retry ambiguity, audit export, and restart recovery. Add the first AI-generated workflow and evidence-backed diagnosis against these real operations, including a model-disabled run.

### Stage 2 Complete adoption and migration

Deliver partner onboarding, browser exchange, sharing, forms, scheduled workflows, stock-client compatibility, supported migration importers, comparison mode and cutover, and the remaining connection and storage requirements. Make the AI migration assistant and workflow planner operate through the actual engine. Replay original journeys after each repair.

### Stage 3 Complete protocol processing and governance breadth

Complete the committed protocol roles and peer qualification, secure mail, transformations, signatures and receipts, validation and quarantine, customer-selected scanning integrations, approvals, identity lifecycle, and enterprise administrative workflows. Close every primary parity row with exact acceptance evidence. A protocol badge or vendor example is insufficient.

### Stage 4 Qualify private AI and production operations

Finish the two local model profiles, held-out AI evaluations, agent tools, injection and disclosure tests, outage behavior, gateway and remote agent operation, multi-host availability, restore, upgrade, native platforms, performance, endurance, and disconnected installation. Continue independent work when a hardware or account dependency blocks a specific row.

### Stage 5 Demonstrate parity and competitive advantage

Run clean operator journeys and permitted incumbent comparisons on identified candidates. Publish migration fidelity, operator time, diagnosis accuracy, delivery evidence, resource and operating costs, resilience, and security findings with methodology and limits. Resolve defects and remaining mandatory gaps. Report assisted design-partner readiness, independent operator adoption, and broader enterprise qualification separately.

These stages establish dependency order, not permission to stop early or postpone architectural requirements that the current implementation depends on. The full goal remains active until its completion rules are met.

## 23 Autonomous work loop and records

Begin each implementation turn by reading current instructions and records, checking main, recording the starting commit, and observing the next incomplete customer journey. Prefer direct product use and real client behavior before source diagnosis. Capture a reproducible failure, diagnose it, make a focused repair, add regression coverage, run relevant gates, replay the journey, update records, and commit locally. A list of fixable defects is not completion.

Use task-owned, isolated configuration, test data, databases, containers, ports and resources named freightctl where possible. Keep credentials in an ignored .private directory with restrictive permissions and secret references in reports. Bind local services to loopback by default. Never use customer credentials, modify unrelated workloads, change the host clock to simulate schedules, or perform global cleanup. Remove only resources created for this task by exact identity.

Keep STATUS.md short and accurate. Maintain machine-readable ledgers with candidate identity, steps and outputs, original findings, regression evidence, outstanding work, and the next useful action. Keep large native logs, models, payloads, scanner databases and temporary work out of Git; retain safe manifests and evidence references. Inspect evidence for secrets and customer data before committing or sharing it.

Do not repeatedly ask permission for authorized local engineering decisions. Ask only for missing authority or information that actually blocks the next action. While a specific external dependency is missing, continue independent mandatory work. Preserve unresolved blockers and communicate actual limits. Do not invent progress, skip acceptance work silently, regenerate existing foundations, or mark the overall goal complete because a time or token budget is ending.

## 24 Where freightctl must earn an advantage

Measure improvements on identical customer jobs and comparable environments:

- Complete production controls and AI governance in a free self-hosted core, with published infrastructure and operating costs.
- Faithful migration supported by inventories, explicit coverage, differential behavior tests, controlled cutover, and usable export.
- Faster partner onboarding and workflow creation with validated plans, clear missing-input handling, and fewer undocumented manual steps.
- Faster, more accurate incident investigation with inspectable evidence and safe recovery under administrator-defined policy.
- Better delivery visibility: the product explains exactly which file reached which stage, the available receipt, and what remains unknown.
- Private AI and ordinary automation that continue to be useful with no vendor connectivity, and transfer continuity when the model stops.
- Strong isolation, disciplined custody, resilient operation, and a simpler operator experience backed by current tests.

Free licensing alone does not establish a win. Incumbents already offer substantial automation and some AI assistance; SFTPGo and ordinary protocol tools already solve important work for free. Compare actual completeness, migration effort, support requirements, privacy, reliability, and total cost. Claim superiority only for the measured jobs and conditions.

## 25 Completion and readiness

The complete product goal is achieved only when all mandatory baseline rows and customer journeys are implemented and qualified, private AI requirements pass, ordinary operation works with AI disabled, native clients and peers confirm interoperability, migration and exit are demonstrated, required security and architecture gates pass, and production resilience, recovery, performance, packaging and documentation have current evidence.

An owner-approved scope change is explicit and recorded. An unavailable vendor installation, certification, cloud account, native machine or multi-host environment creates an open qualification blocker; it does not become an implicit exclusion or a successful test. Local implementation stages may complete while the overall product remains unqualified.

Report three readiness verdicts separately: assisted design-partner deployment, ordinary operator adoption, and broader enterprise or release qualification. Bind each to the tested commit and artifact digests, deployment profile, completed journeys, open defects, external prerequisites, and unverified claims. A polished demonstration does not qualify the entire product.

Final evidence must include the parity matrix, journey and defect records, AI evaluation results, native test and scanner outputs, migration and export exercises, backup and restore results, performance and endurance measurements, operational documentation, remaining work, and the local commit range for owner review. Required red gates, unresolved defects and external blockers remain visible. Never claim that a repository, document, feature count, or license tier makes freightctl the best; demonstrate the customer outcomes that justify choosing it.

## 26 Official benchmark and specification sources

Sources reviewed for the initial goal on 2026-10-28. Use these as starting points, follow current official documentation to the exact behavior and edition, and refresh before asserting parity. They establish documented benchmarks rather than hands-on comparative qualification.

- [GoAnywhere detailed capabilities](https://www.goanywhere.com/products/goanywhere-mft/detailed-features)
- [GoAnywhere licensed modules](https://www.goanywhere.com/products/goanywhere-mft/licensed-modules)
- [GoAnywhere workflow model](https://www.goanywhere.com/products/goanywhere-mft/workflows)
- [GoAnywhere accelerated transfer](https://www.goanywhere.com/solutions/fast-file-transfer)
- [GoAnywhere AI workflow and operations direction](https://www.goanywhere.com/resources/guides/next-era-of-mft-how-ai-is-transforming-managed-file-transfer)
- [MOVEit Transfer 2026 administration](https://docs.progress.com/bundle/moveit-transfer-web-admin-help/page/MOVEit-Transfer-Documentation-2026.html)
- [MOVEit Automation 2026 documentation](https://docs.progress.com/category/moveit-automation-2026)
- [MOVEit Automation 2026 capability sheet](https://www.progress.com/docs/default-source/data-sheets/ds-moveit-automation-datasheet.pdf)
- [MOVEit Transfer 2026 changes and beta AI reports](https://docs.progress.com/bundle/moveit-transfer-release-notes-2026/page/Whats-New-in-MOVEit-Transfer-2026.html)
- [MOVEit Automation failover overview](https://docs.progress.com/bundle/moveit-automation-web-admin-help-2026/page/Overview.html)
- [MOVEit Gateway deployment service description](https://www.progress.com/docs/default-source/data-sheets/moveit-gateway-implementation-services.pdf?sfvrsn=ad1801e0_2)
- [JSCAPE managed file transfer](https://www.jscape.com/products/managed-file-transfer-software)
- [Cerberus editions and commercial capabilities](https://www.cerberusftp.com/pricing/)
- [Cerberus feature catalog](https://www.cerberusftp.com/features/)
- [SFTPGo open-source and Enterprise boundaries](https://docs.sftpgo.com/enterprise/)
- [IBM Sterling enterprise transfer reference](https://www.ibm.com/products/secure-file-transfer?lnk=L0G)
- [IBM Sterling File Gateway partner reference](https://www.ibm.com/products/file-gateway)
- [AS2 protocol and receipt semantics in RFC 4130](https://www.rfc-editor.org/info/rfc4130/)

AS1, AS3, AS4, OFTP2, PeSIT, SSH, TLS, OpenPGP, resumable HTTP and connector-specific specifications must be added with exact versions when their baseline rows are established. Axway reference rows require current official product sources before use. Do not represent an unsourced protocol profile or reference comparison as already qualified.
