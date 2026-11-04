# GitHub Actions qualification plan

Updated 2026-11-04. This is the durable execution plan for the existing public
`ctlplne/freightctl` repository. [GOAL.md](../../GOAL.md) defines acceptance;
[STATUS.md](../../STATUS.md), [remaining.json](remaining.json) and the exact
[evidence records](evidence/) hold current results. All 83 whole baseline rows and
12 full customer journeys remain open. A green component is evidence for its
recorded input and environment only.

The earlier plan and its chronological observations are preserved unchanged in
[the history through 2026-11-04](github-actions-history-through-2026-11-04.md).
Use the operating rules below for new work; use immutable evidence and actual
GitHub run/job/attempt handles for qualification decisions.

## Execution boundary

Keep the owner's shared ARM Mac for editing, bounded parser/contract tests,
compilation and evidence review. Use `GOMAXPROCS=1`, `GOMEMLIMIT=192MiB`, Go `-p 1`,
Node heap of 192 MiB and one test worker locally. Do not load models, start inference or
run local model evaluations. PostgreSQL, Chrome, independent receivers, native
x86 execution and image builds/scans belong on disposable GitHub runners.
Cross-compilation is build evidence; it cannot qualify another architecture.

Use actual PostgreSQL and storage for persistence/RLS claims, actual public
CLI/API/browser journeys for operator claims, stock clients for observed client
compatibility and independent receivers/cryptographic tools for their specific
contracts. Name a simulated receiver or cloud emulator as a stand-in. It cannot
qualify a live vendor service, physical remote filesystem, independent operator
or multi-host deployment.

Source/CI pushes are owner-authorized. Work remains on local main, with verified
author and committer `imfeelingtheagi <288773099+imfeelingtheagi@users.noreply.github.com>`.
CI never authors commits. Releases, image/package/artifact publication and
external deployments need their separate authority. No workflow uploads raw
reports, image archives, credentials, payloads, keys or private evidence.

## Gate inventory

| Gate | Workflow and actual environment | Contract and current limit |
| --- | --- | --- |
| Source, frontend and supply chain | [core-checks.yml](../../.github/workflows/core-checks.yml), Linux x86 | Formatting/static checks, frontend contracts/type/build/embedded closure, npm auditing, Gitleaks history/change scans, source govulncheck and actual converter refusal contracts. Parser/report success alone cannot pass a vulnerability finding. |
| Native application, migrations and isolation | [native-linux.yml](../../.github/workflows/native-linux.yml), actual Linux ARM and x86, separate PostgreSQL fixtures capped at 512 MiB and one CPU | All implemented unit/race/integration tests, cold migrations, RLS/runtime authority and independent peer cases. At 5ef3f3b and8905385 both application suites pass841 records with zero failures/skips, including independent AEAD. Both jobs fail afterward at the new image-feed prerequisite D159; full jobs remain red. F074/F075 retain exact separate results. |
| Metadata restore | Same native Linux workflow, separately seeded real PostgreSQL per architecture | Fresh source40,64tables/63forced-RLS/45synthetic rows passes both at28cdfcb. Currentf08ARMrestore also succeeds at job level; x86 remains queued,without a count inferred from status alone. Retained schema 35 is separately approved and unchanged. Metadata-only restore does not qualify payload/key/clean-host recovery or RPO/RTO. |
| Parser/authority fuzz | Same native Linux workflow, Linux x86 | Ten bounded implemented targets; add targets with real parsers. Missing targets and unexecuted cases remain open. Keep original budgets and surface any corpus failure. |
| Exact independent peer image | Same native Linux job, after runtime even on failure if peer build succeeded | [F075](evidence/F075-peer-image-security.json): scan the same immutable source-labelled image ID, without uploading it. Pinned Trivy, current hash-bound feed, OS/library inventory, native identity and enforcing safe summary are required. Original feed preparation fails before scanning (D159). Source28x86 now proves stopped-containerOOM; ARM remains unclassified. Feed-only earlier-GC trial is prepared with unchanged limits and no scan pass. The earlier4d771b2 run was cancelled unstarted and is not a pass. |
| Native source vulnerability configurations | [native-vulnerabilities.yml](../../.github/workflows/native-vulnerabilities.yml), actual Linux ARM, Windows amd64 and Mac ARM; Linux x86 stays in core | Verify host/target/Go version, scan once and enforce the original report through the actual pinned converter. These source passes do not establish Windows runtime support or image security. [F070](evidence/F070-govulncheck-enforcement.json) retains results and the visible module advisory. |
| Windows/Mac runtime units | [native-platforms.yml](../../.github/workflows/native-platforms.yml), native Windows amd64 and Mac ARM | Separate OS concurrency groups prevent a queued Mac from serializing Windows. Windows custody/ACL/directory-sync/private-socket failures remain D103; a cancelled or filtered run is not a pass. |
| Stock SFTP, collection and browser journeys | [stock-peers.yml](../../.github/workflows/stock-peers.yml), Linux x86, real services, stock OpenSSH and sandboxed Chrome | Existing routing, corrected revisions, collection, arrival and schedule profiles reopen exact original outputs/bytes and prove cleanup. Preserve F066's first failure and repaired original journeys. F076 prepares FTPS source40 collection through the same machinery; its actual native/public/operator/crash/dedupe qualification remains pending. |
| First enrollment | [first-run.yml](../../.github/workflows/first-run.yml), fresh PostgreSQL/storage, sandboxed Chrome and stock curl | [F069](evidence/F069-native-first-run-gate.json) qualifies its original 13-command exchange, not independent adoption, disconnected installation or whole J01. |
| Stock FTPS receiving and recovery | [ftps.yml](../../.github/workflows/ftps.yml), actual native ARM/x86, curl/lftp plus TLS stand-in | Original bytes, control/data TLS, governance, upload-ticket crash/replay and exact cleanup remain required. Active receiving cases cannot be inferred from passive tests. See F062/F065. |
| FTPS receiving browser | [ftps-browser.yml](../../.github/workflows/ftps-browser.yml), Linux x86, actual HTTPS/storage/PostgreSQL and sandboxed Chrome | [F067](evidence/F067-ftps-browser-tickets.json): real ticket controls, exact owned-process kills, receipt recovery, HTTP/DOM/byte closure and WCAG audits. D145 remains intermittent with cause unproven despite later greens. |
| FTPS consent | [ftps-dispatch.yml](../../.github/workflows/ftps-dispatch.yml) and [ftps-workflows.yml](../../.github/workflows/ftps-workflows.yml), Linux x86 | Actual public commands/browser with contact-only spies. At 0c681c7 all three fresh plaintext and encrypted workflow profiles pass, each with six browser phases/replays and 18 audits, zero sending contacts/attempts/fences. This proves metadata consent; sender bytes remain a separate native gate. F076 adds a required16-command/mode CLI/API collection metadata profile with original-key queue/cancel/revocation recovery and stopped zero-contact spies. A local follow-up requires two actual Chrome collection metadata phases and six additional WCAG audits per fresh profile. It compares original HTTP bodies/CLI snapshots/rendered identity and stopped zero-contact spies; the original six consent phases/18audits remain enforced. Neither profile qualifies source byte collection. Both28CLI/API profiles pass three fresh estates each. f08metadata Chrome locates response.json failures in both matrices; one earlier plaintext estate passes,which does not satisfy the required three. Verified-curl wire capture repair is prepared locally,retaining exact original headers/requests/responses and all prior metadata checks. A new required operator flag adds ordinary UI draft/approve/queue/work,four lost-response original-key recoveries/mode,one actual native source acquisition,exact unchanged producer revisions and independent HTTPS byte readbacks. It adds two phases/12WCAGaudits per fresh estate,while preserving all original phases,three estates and30minute/source/resource budgets. Native freightctl is a named source fixture,not an independent vendor;actual operator qualification is pending.9e5native process-death pairs pass both architectures, while knownD164/D165fixtures remain red. Retain exact originals before replay. D151/D152 causes remain unproven. |
| Independent outbound FTPS receiver | [ftps-client.yml](../../.github/workflows/ftps-client.yml), native ARM/x86 stock vsftpd/OpenSSL/PAM | [F068](evidence/F068-ftps-client-transport.json): original ARM profiles pass their scope; x86 remains red at stock socket-filter conflicts. Keep active FTP disabled rather than bypass the failing isolation contract. A local follow-up requires independent0400source publication/observation and native bounded metadata boundary reads under the same stock profile; legacy results cannot satisfy its new producer/reporter flag. Atf08bothARMsystem/no-ktls profiles pass both modes/four bounded metadata cases each,with six unchanged source files and all original transport checks. Bothx86stock profiles remain red; nativeARMfilter remains unavailable. This does not qualify full typed collection. |
| Full foundation aggregate | [full-foundation.yml](../../.github/workflows/full-foundation.yml), manual only | F026 is owner-deferred. Never run it automatically or disguise the same aggregate under another name. |

## Resource and trust rules

Use standard [GitHub-hosted runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners),
with one fresh runner per job and task-owned loopback fixtures. Do not attach
production databases, shared Docker state, long-lived self-hosted runners or
production credentials. Keep private fixture files owner-only and explicitly
verify the mounted child directory itself; a protected parent is not the same
contract after a child is bind-mounted (D158).

Use `pull_request` with read-only `contents`, no repository secrets, no privileged
follow-up workflow and checkout without persisted credentials. Pin actions,
tool versions, lockfiles and image digests. Record actual host architecture,
runner/tool versions and immutable peer identity. Do not silently fall back to
an unpinned peer, weaker TLS, disabled Chrome sandbox or skipped scanner.

Existing native application jobs retain their 50-minute job and 600-second package
limits, single-worker Go/Node settings, live lease waits and per-case deadlines.
The schema-only workflow template avoids repeating migrations, while every case
still has separate real databases/storage, exact migration checksum verification
and runtime/RLS checks. Cold store upgrades remain independent. Template
optimization proves fixture behavior, not product throughput or capacity.

The F075 image scanner uses one CPU and 1 GiB RAM, no swap, 128 processes and a bounded
fallback temporary memory filesystem. The prepared D159 repair uses a separate2GiB ext4 disk volume for cache and `TMPDIR`, verified by exact mount/loop backing before use and unmount, including timeout. Bothde93 native mount/identity/cleanup paths execute before feed137. Source28x86 exact stopped state provesOOM; ARM has no classified command/state. A feed-onlyGOGC25 trial retains soft768MiB and all hard/time/disk/isolation limits. Earlier GC may reduce transient memory; the allocation cause and remedy remain unproven ([Go GC guide](https://go.dev/doc/gc-guide#Memory_limit)). Actual feed/scan replay remains required. Download its feed in a separate bounded container; scan an
immutable image archive offline with no Docker socket, read-only root/input/feed
and no capabilities/new privileges. Require fresh feed/report times, unchanged
input hashes and OS plus installed OpenPGP inventory. Count all severities and
unfixed findings. HIGH/CRITICAL/UNKNOWN, suppressed, stale, EOL, foreign or
incomplete evidence fail. Lower findings remain visible and need assessment.
This does not establish vulnerability reachability or a clean released image.
See [Trivy image inputs](https://trivy.dev/docs/latest/target/container_image/)
and [feed controls](https://trivy.dev/docs/latest/configuration/db/).

Local inference stays off. GitHub also has no permission to fetch weights or
call an inference endpoint until a named endpoint, disclosure policy and explicit
resource allowance are authorized. Real malware qualification retains its
separate 4 GiB and one CPU maximum; it grants no inference or shared-container authority.
The stopped local scanner and retained schema 35 estate stay unchanged.

## Scheduling and evidence lifecycle

1. Finish a running qualification candidate. Follow its exact source commit,
   workflow run, attempt and job IDs. Keep only the newest pending candidate;
   hold another source push while a required, unknown candidate is still pending.
   An unstarted successor containing an already-confirmed error may be superseded
   after the original failure is retained. Never call cancellation a pass.
2. Fast source checks may supersede older source checks. Other workflows use
   finish-running/newest-pending groups; Windows and Mac have separate OS groups.
   Ordered path filters may omit irrelevant work, including selected `_test.go`
   changes and the four image-scanner-only scripts from stock journeys. The scanner remains in native Linux and core gates. An omitted run establishes no result for the
   new commit. Review every trigger consumer when adding scripts/migrations.
3. Preserve the first actual failure and immutable original logs before editing.
   Add a meaningful regression, fix the mechanism, replay the original journey
   and record remaining work. An unexplained later green does not establish a
   cause for an intermittent red. Fixed fresh repetitions stop at first failure;
   they are extra coverage, not retries until green.
4. Read failures, temporary log404s and API lag do not justify another execution.
   Retry the same read, use an exact read-only API fallback when needed and keep
   aggregate status separate from completed steps/original logs. Do not cancel
   or restart a running job merely because observation failed.
5. Reopen original command responses, independent receiver bytes and exact
   manifests. Check source/output closure, idempotency identity, tenant/partner
   authority, attempts/fences and exact cleanup. Explicitly distinguish zero
   skips from mandatory child cases that never ran after a parent failure.
6. Keep raw reports, payloads, private keys and full logs in ignored protected
   paths. Public summaries admit bounded fixed fields/counts/hashes and reviewed
   diagnostic enums, never raw exception strings or private command arguments.
   Privacy/refusal/exit contracts are part of the gate. Retain an immutable safe
   reference and SHA256 locally before the disposable runner disappears.

The direct-main repository contract means CI tests a pushed commit after arrival;
it is not a pre-push merge barrier. Required branch checks would need an approved
branch/review contract change. Never amend owner history or use CI to rewrite
provenance.

## Next promotion and work that remains external

| Work | Next executable proof | Boundary |
| --- | --- | --- |
| Independent encrypted FTPS | Retain D158's repaired original native application/AEAD passes; diagnose D159 and require the actual same-image scan | GnuPG and metadata-consent passes do not substitute for independent AEAD or whole protocol qualification. |
| FTPS collection | [F076](evidence/F076-ftps-collection.json): bounded transport, read-only adapter, exact source/SQL/custody/intake bindings, manual and scheduled public journeys | Both9e5native suites pass14of17FTPSleaves,including original-key copy,CSVrelease,batch identity/revocation and real process-death sealed recovery. KnownD164/D165fixture repairs await currentf08native replay. Require the original-wire metadata repair and full operator capture matrix; mixed/encrypted routing,independent typed collection and whole journeys remain open. Preserve current hashes, RLS, command/resource budgets and original stock x86 failure. |
| Payload/key/clean-host recovery and upgrades with active work | Add isolated real storage/key/queued-work fixtures and failure injection, restore into a fresh environment, measure outcomes | Existing same-cluster metadata restore does not establish RPO/RTO, business delivery or retained schema upgrade authority. |
| Processing/security breadth | Add archive/MIME/XML/receipt/importer/transform/DLP/connector gates when those implementations exist | No placeholder command can be green. Keep the owner-deferred F026 aggregate manual. |
| Packaging and disconnected operation | Build reproducibly, inventory full dependency closure/SBOM, test offline installation/export/rollback on each actual native target | Build-only artifacts can stay ephemeral in CI. Signing, release/artifact/image publication and deployments remain separately gated. |
| Windows production custody and endpoint integrations | Repair native ACL/durability/endpoint behavior and replay original D103 failures | Linux passes and cross-compilation cannot substitute. |
| Live cloud/proprietary peers and incumbent comparison | Use owner-authorized accounts, versions, editions, independent peers and permitted exports | Emulators and public stand-ins establish contracts only. Missing accounts/licenses remain explicit external dependencies. |
| Gateway/agent/multi-host availability, performance and endurance | Actual permitted failure domains and specified storage/network/reference-node resources | Same-host CI loopback cannot prove network partitions, multi-host production availability or the required reference throughput/endurance. |
| Private AI and held-out evaluations | Named owner-authorized endpoint, disclosure policy, explicit compute limit, independent validators and AI-disabled replay | No local model load or unapproved remote inference. X05 remains open. |
| Independent adoption and release licensing | Ordinary operator evidence and exact owner-approved grant/distribution authority | Assisted implementation, CI greens and source visibility establish neither adoption nor enterprise readiness. |

For each new capability, add its cheapest meaningful contract checks to core,
real persistence/protocol tests to the matching native gate and actual public
journeys to a bounded separate workflow when needed. Share typed profile
constants between execution and reporting, while independently verifying
original outputs. Change the plan, consumers, refusal coverage, evidence and
remaining work together. All mandatory GOAL.md gates must pass before the
overall goal can be marked complete.
