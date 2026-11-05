# GitHub Actions qualification plan

Updated 2026-11-05. [GOAL.md](../../GOAL.md) defines the complete product contract.
[STATUS.md](../../STATUS.md), [remaining.json](remaining.json) and the exact
[evidence records](evidence/) hold candidate identities and current results.
All 83 whole baseline rows and 12 full customer journeys remain open. Passing a
component proves only its recorded inputs, environment and assertions.

Dated observations are preserved unchanged in the histories through
[2026-11-04](github-actions-history-through-2026-11-04.md) and
[2026-11-05](github-actions-history-through-2026-11-05.md). This document defines
how to execute and assess work; it does not replace original evidence.

## Execution boundary and authority

Keep the shared ARM Mac for editing, bounded parser/Page/process contracts,
compilation and evidence review. Use Go `GOMAXPROCS=1`, `GOMEMLIMIT=192MiB` and
`-p 1`; use Node's 192MiB heap and one test worker. Heavy runtime work belongs
on disposable GitHub computers: real PostgreSQL, Chrome, stock receivers,
native x86 execution, image builds/scans and reproducible application builds.
Cross-compilation proves a build, while the matching native environment must
prove runtime behavior. Name every simulated peer or cloud endpoint as a stand-in.

Use real storage and non-owner PostgreSQL runtime roles for persistence/RLS;
actual CLI/API/browser journeys for operator behavior; stock clients and
independent cryptographic tools for their specific interoperability boundaries.
A loopback fixture cannot prove a live vendor service, physical remote storage,
independent operator adoption or multi-host availability.

Work stays on local main. Every author and committer must be
`imfeelingtheagi <288773099+imfeelingtheagi@users.noreply.github.com>` and must be
verified before each commit and across every outgoing range. Owner source/CI
push authorization is recorded in GOAL.md. Release, image/package/artifact
publication and external deployment require their separate authority. Keep CI
credentials read-only and checkout credentials unpersisted. CI never authors
commits, changes visibility or rewrites owner history.

## Gate inventory

| Gate | Actual environment and workflow | Required proof |
| --- | --- | --- |
| Source, frontend and supply chain | Linux x86; [core-checks.yml](../../.github/workflows/core-checks.yml) | Formatting/static checks, frontend contracts/type/build/embedded closure, npm audit, Gitleaks history/change scans and source govulncheck through its actual enforcing converter. A parser pass cannot approve a vulnerability finding. |
| Native application and migrations | Separate Linux ARM/x86 with bounded real PostgreSQL; [native-linux.yml](../../.github/workflows/native-linux.yml) | All implemented unit/race/integration and cold migration cases; runtime/RLS authority, exact bytes, leases/replay and independent peers. Require actual mandatory children; retain original failures and distinguish the application section from the later image gate. |
| Metadata restore | Separate fresh PostgreSQL estate on each native Linux architecture; same workflow | Seed through ordinary commands, restore the exact source schema and prove every required row/grant/role/RLS/sequence plus cleanup. [F050](evidence/F050-native-metadata-restore.json) defines this narrower scope. Retained schema35 is unchanged; metadata restore does not qualify payload/key/clean-host recovery or RPO/RTO. |
| Parser/authority fuzz | Native Linux x86; same workflow | All implemented bounded targets, original corpus/time limits and exact failures. Add targets with real parsers; unimplemented or unexecuted targets remain open. |
| Same-image security | Native ARM/x86 after application tests, even when application fails; same workflow | [F075](evidence/F075-peer-image-security.json): scan the exact immutable source-labelled image ID with pinned Trivy, current bound feed, full OS/library inventory and enforcing report. Keep image failures red independently of application results. |
| Source vulnerability configurations | Linux ARM, Windows amd64 and Mac ARM; [native-vulnerabilities.yml](../../.github/workflows/native-vulnerabilities.yml); Linux x86 in core | Actual host/target/toolchain identity, one original scan and its actual pinned converter/refusal controls. [F070](evidence/F070-govulncheck-enforcement.json). These checks do not establish Windows runtime or image security. |
| Windows/Mac runtime units | Actual Windows amd64 and Mac ARM; [native-platforms.yml](../../.github/workflows/native-platforms.yml) | Original native unit/vet/race scope, separate OS concurrency, exact supported interfaces. Windows ACL/directory durability/private-socket D103 remains open until actual repaired native journeys pass. |
| Stock SFTP and operator flows | Linux x86, real services, OpenSSH and sandboxed Chrome; [stock-peers.yml](../../.github/workflows/stock-peers.yml) | Exact source/custody/receiver bytes, workflow routing, collection/arrival/schedule behavior, original HTTP/CLI/DOM outputs and cleanup. Each new profile must satisfy its own complete producer/reporter contract. |
| Core binary reproduction and component inventory | Separate native Linux ARM/x86; [reproducible-builds.yml](../../.github/workflows/reproducible-builds.yml) | [F077](evidence/F077-native-reproducible-core.json): different committed source copies and empty caches, pinned native Go, verified module inputs before/after, readonly/offline builds, physical build-ID reads and exact final executable/Go/help/source/output equality. Bind exact embedded UI bytes and production lock/peer closure; validate the actual inventory using pinned offline stock CycloneDX schemas. Whole deployment SBOM, independent-host reproduction, licensing, signatures and offline installation remain separate mandatory work. |
| First enrollment | Fresh PostgreSQL/storage, sandboxed Chrome and stock curl; [first-run.yml](../../.github/workflows/first-run.yml) | [F069](evidence/F069-native-first-run-gate.json)'s original complete exchange, replay and cleanup. Assisted enrollment cannot establish independent adoption, disconnected installation or whole J01. |
| Stock FTPS receiving/recovery | Native Linux ARM/x86, curl/lftp and named TLS stand-in; [ftps.yml](../../.github/workflows/ftps.yml) | Original bytes, control/data TLS, governance, upload-ticket crash/replay and exact cleanup. Active receiving requires its actual cases. [F062](evidence/F062-ftps-cli-governance.json), [F065](evidence/F065-ftps-public-crash-recovery.json). |
| Receiving browser | Actual HTTPS/storage/PostgreSQL and sandboxed Chrome; [ftps-browser.yml](../../.github/workflows/ftps-browser.yml) | [F067](evidence/F067-ftps-browser-tickets.json): ticket controls, exact owned-process kills, receipt recovery, HTTP/DOM/byte closure and WCAG audits. Keep intermittent D145/D151/D152 causes unproven until reproduced and explained. |
| FTPS consent and collection operator | Linux x86; [ftps-dispatch.yml](../../.github/workflows/ftps-dispatch.yml), [ftps-workflows.yml](../../.github/workflows/ftps-workflows.yml) | Original three fresh plaintext/encrypted estates, six consent phases/18audits, CLI/API metadata replay/cancel/revocation, two metadata Chrome phases/six audits and two byte-operator phases/12audits. Require four original-key recoveries per operator mode, one source acquisition, unchanged producer revisions and independent HTTPS readbacks. [F076](evidence/F076-ftps-collection.json). Previews must prove zero source contact. Native freightctl source is a named stand-in; independent typed FTPS collection remains required. |
| Independent outbound FTPS | Native ARM/x86 stock vsftpd/OpenSSL/PAM; [ftps-client.yml](../../.github/workflows/ftps-client.yml) | [F068](evidence/F068-ftps-client-transport.json): original transport/readback/isolation and independent0400source metadata cases. Preserve x86 filter failures and unavailable native ARM filtering. Active FTP stays disabled. Partial stock metadata passes do not qualify full typed collection. |
| Full foundation aggregate | [full-foundation.yml](../../.github/workflows/full-foundation.yml), manual only | F026 is owner-deferred. Do not automatically run it or recreate the same aggregate under another name. |

## Resource, privacy and receipt rules

Use standard [GitHub-hosted runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
and record actual OS/architecture/tool/peer identity. Pin actions and tool inputs;
verify lockfiles, checksums and exact committed local replacements. A missing
peer cannot silently become an unpinned implementation, weaker TLS, disabled
Chrome sandbox or skipped security gate.

Preserve existing job/package/case deadlines, single-worker settings, live lease
waits, bounded streams and task-owned resource names. Native application jobs
retain50 minutes and600-second package limits. Schema-only templates may avoid
repeating migrations, but each case still needs isolated real databases/storage,
exact migration checksums and runtime/RLS checks. Fixture speed is not product
throughput or capacity evidence.

F075 retains hard1 GiB RAM/no swap, soft768 MiB, one CPU,128 processes and the exact
bounded2 GiB ext4 cache/TMPDIR disk with verified mount/loop ownership and cleanup.
Feed-onlyGOGC25 is an experiment, not an OOM remedy. The original database-file
cap remains1 GiB; the1792 MiB file-only proposal is unapplied and awaits the owner.
No permission to enlarge RAM/disk/time or omit coverage follows from that proposal.
Keep actual file-budget and exact stopped-container OOM failures separate.

Download the complete feed in its own bounded container. Scan an immutable
saved image offline, with read-only input/feed/root, no Docker socket,
capabilities or new privileges. Require fresh feed/report times, unchanged inputs,
OS and installed OpenPGP inventory, all severities and unfixed/suppressed findings.
HIGH/CRITICAL/UNKNOWN, suppression, stale/EOL/foreign or incomplete evidence fails;
lower findings remain visible for assessment. [F075](evidence/F075-peer-image-security.json)
and the [Trivy input](https://trivy.dev/docs/latest/target/container_image/)
/[feed](https://trivy.dev/docs/latest/configuration/db/) contracts remain authoritative.

F077 keeps its20-minute job, one-worker/192 MiB soft Go limit and original
source/file/output/working-byte/time bounds. Its Python schema validator uses
an isolated disposable GitHub venv, exact wheel hashes/versions, wheel-only
installation and offline in-memory schema references. Stock positive/negative
controls and the actual emitted inventory must pass. It publishes only safe
hashes/fixed fields. Raw executables, BOMs, reports and credentials stay private
and ephemeral; no upload-artifact or release occurs. A Go module h1 directory
hash must never be relabeled as an archive/file SHA256 checksum.

Local inference stays off. GitHub also has no model-weight download, inference
endpoint or evaluation authority until the owner names an endpoint, disclosure
policy and explicit compute allowance. Malware qualification has its separate
4 GiB/one CPU authorization; it grants no inference or shared-container lifecycle
authority. Retained schema35,stopped local resources and F026 remain unchanged.

Authorize receipts by their actual receiver contract. Exact readback is distinct
from receiver fsync and business acceptance. Unknown or ambiguous delivery must
remain visible and block automatic resend where required. Model output, a tool
answer or a passing metadata preview cannot grant execution or recipient authority.

## Scheduling and evidence lifecycle

1. Follow each exact source commit, run, attempt and job ID. Preserve the running
   original and keep the newest pending successor. Hold another relevant source
   push while required current native/public/reproduction jobs remain unstarted.
   An unstarted successor with an already-confirmed error may be superseded only
   after retaining the original failure and proving the exact same bad source.
   Recheck every job/runner/step immediately before cancellation. If any job has
   started, refuse cancellation and preserve the live run. An earlier eligible
   snapshot is not current authority. Cancellation never counts as a pass.
2. Fast source checks may supersede older source checks. Runtime workflows finish
   their running candidate; Windows/Mac have separate OS groups. Review every
   trigger consumer when adding imports/scripts/migrations. Ordered path filters
   may omit irrelevant test/scanner-only changes; an omitted run proves nothing
   about that commit's runtime. Direct-main testing is not a pre-push merge gate;
   branch protection needs an approved branch/review contract change.
3. Capture the first actual failure before editing. Add meaningful coverage,
   repair the mechanism and replay the original journey. Preserve every security,
   isolation, protocol, assertion and resource requirement. A later unexplained
   green does not establish an intermittent failure's cause. Fixed fresh
   repetitions stop at first failure; they are not retries until green.
4. Read failures, log404s and API lag do not authorize execution restart or
   cancellation. Re-poll the same handle or exact read-only API. Separate completed
   application steps from full job status and require original command closure.
5. Reopen original outputs, receiver bytes and manifests. Require exact source/
   output closure,tenant/partner/actor authority, immutable revisions, saved keys,
   attempts/fences and cleanup. Zero reported skips cannot prove child cases that
   a failed parent never executed.
6. Keep raw logs, payloads, secrets, models, databases and scanner caches out of
   Git. Retain safe manifests/references/hashes before disposable resources
   disappear. Public diagnostics permit bounded fixed enums/counts/hashes only;
   cookie,CSRF,path,response and exception prose cannot become a diagnostic.

## Next proofs and external dependencies

| Work | Next executable proof | Boundary that stays open |
| --- | --- | --- |
| Collection and mixed/encrypted routing | [F076](evidence/F076-ftps-collection.json):native D173distinct-registration-key replay and actual D175session-subreason diagnosis/repair across original public matrices | Independent source vendors,whole operator/recovery journeys and business acceptance need their own actual evidence. |
| Image security | [F075](evidence/F075-peer-image-security.json):owner file-cap decision plus supported full-feed/scan path inside unchanged hard budgets | No clean image can be inferred from successful download,earlier GC,byte equality or source scanning. |
| Packaging | [F077](evidence/F077-native-reproducible-core.json):native physical build-ID repair,full two-build comparison and actual stock-schema validation | Independent-host reproduction,complete deployment/build-tool/standard-library SBOM,license review,signing and disconnected bundle/install/export/rollback remain mandatory. |
| Payload/key/clean-host recovery and upgrades | Isolated real storage/keys/active-work failure injection and restore into fresh environments,with measured outcomes | Metadata-only same-cluster restore cannot establish RPO/RTO,business delivery or retained-upgrade authority. |
| Processing and protocol breadth | Implement and run actual archive/MIME/XML/receipt/importer/transform/DLP/connector/native-peer gates | No placeholder command,limited parser,stand-in vendor or owner-deferred aggregate can satisfy broader parity. |
| Windows production custody and endpoints | Repair native ACL/durability/transport and replay D103original unit/service journeys | Linux passes and cross-builds cannot qualify Windows. |
| Private AI | Owner-authorized endpoint,disclosure policy,compute allowance,held-out/adversarial validators and AI-disabled replay | No local inference or unauthorized remote calls;X05 remains open. |
| Live cloud,proprietary peers and comparisons | Authorized accounts,identified versions/editions,permitted exports and isolated reference jobs | Emulators/public stand-ins establish only their declared contracts;missing accounts/licenses stay explicit. |
| Gateway/agent/HA,performance and endurance | Actual permitted failure domains and specified storage/network/reference-node resources | Same-host loopback CI cannot prove multi-host availability,required throughput or endurance. |
| Independent adoption and release | Ordinary operator evidence and exact owner-approved license/distribution authority | Assisted work and CI greens do not establish adoption or enterprise readiness. |

For each new capability, add its cheapest meaningful contract checks to core,
real persistence/protocol cases to the corresponding native gate and complete
public journeys to a bounded workflow. Share execution/report profile constants
while independently checking original outputs. Update consumers,evidence and
remaining work together. All mandatory GOAL.md requirements must be proven
before marking the overall goal complete;scope changes require explicit owner approval.
