# freightctl status

Updated 2026-11-05 for the owner-approved product definition and plan. Application
execution remains **paused at the owner's request**;GOAL.md remains
incomplete. All **83 whole baseline rows
and 12 full customer journeys remain open**. Assisted deployment, independent
adoption and enterprise readiness remain separately unqualified. Work stays on
local main; both author and committer are exactly
`imfeelingtheagi <288773099+imfeelingtheagi@users.noreply.github.com>`.
Owner source/CI push authority does not authorize artifacts, releases or deployment.

The accepted definition is a **secure artifact exchange platform that lets agents,
applications, people and systems send and receive artifacts under explicit
permissions, with reliable delivery and traceable outcomes**. Managed file transfer
remains its transport/custody/recovery foundation. The first customer workflow,
buyer and market wedge remain unselected.

The [artifact exchange plan](docs/product/artifact-exchange-plan.md) and
[new requirement register](docs/qualification/artifact-exchange.json) add eight
planned requirements and three engineering profiles under R016. All 83 existing
parity rows, twelve full journeys, prior defects/evidence and readiness verdicts
are preserved. Planning establishes no new runtime qualification.

Owner decision S002 clarifies S001: the trstctl suite/general credential-trust
control plane stays excluded, while an optional real Trust Control identity and
credential provider integration is planned. X07 tracks its unpinned actual contract
and qualification access. Core operation remains independent; every exchange and
onward handoff needs its own authority. This planning-only update does not resume
the application build, start services, change resources or authorize a push.

The prior application handoff is **85695f6**, following **99e57b1** (approved Trivy file-only allowance) and
**ecb3427** ([F079](docs/qualification/evidence/F079-handle-bound-directory-sync.json)
handle-bound directory flushing). This handoff accompanies the requested commit/
source push/pause. Native checks for those changes remain pending. On resume,
inspect current origin/main and its exact jobs before continuing;preserve originals.

Historical 2026-11-04 read-only CI snapshot: all eleven workflows for submitted
**85695f6** were queued when checked; no completed result for F079 or the approved
F075 patch was then observed. CI was not refreshed for this planning-only update;
inspect current exact jobs on application resume.
Prior submitted **ba011f5** now has both native application gates complete:
x86 native127007225597 and ARM127007225840 each884 pass/0 fail/0 skip. Both jobs
remain red at the separate image gate: x86 records OOM under hard1GiB; ARM records
the1,691,381,760-byte database exceeding the old1GiB file cap. Metadata/fuzz and
both reproduction jobs pass. Both public
profiles finish and verify first explicit metadata Chrome,then fail
cli-explicit-collection-source before operator Chrome;underlying source-helper
startup cause remains unexposed. Exact evidence is retained inF076. Windows stays
red;Mac passes. These results do not qualify later source or the full goal.

Exact prior **6ddcb30** passes core41951088073 and both native
reproduction41951088070 jobs. Native-platform41951088055 records the Windows
filesystem probe, but its original unit step still fails; Mac passes. Stock41951088059
passes four profiles; arrivals-schedules126994935686 records one unexpected command
exit, with zero unexpected HTTP statuses, failed browser reports or cleanup failures.
Its exact command/cause is unexposed and remains red. All required prior jobs
started or finished before this push;original failures and scoped passes are retained.

Original97native41944580495 retains880 pass/3 fail/0 skip on each architecture at
D176's invalid fixture step IDs. Exact ba x86 now passes the original mixed case;
ARM/full public completion remains required. Original97public fetch-site and
reproduction build-id command failures stay retained;unexposed causes are not invented.

The retained database remains at approved schema35:64,339 rows,64 tables and
63 forced-RLS tables ([F056](docs/qualification/evidence/F056-retained-handoff-upgrade-applied.json)).
Exact PostgreSQL/scanner resources remain stopped at512 MiB/one CPU and4 GiB/one CPU.
Fresh CI schema40 restores do not authorize a retained upgrade. Local inference
stays off; no actual local PG,Chrome,source/receiver,scanner,image or model ran.
Only bounded parser/protocol/process/file contracts,source inspection and compile/vet
ran here. F026 remains manual and owner-deferred.

[F076](docs/qualification/evidence/F076-ftps-collection.json) retains earlier f08/d6
880/0/0 native component results and17 FTPS leaves, including frozen SQL/schedule,
CSV/batch/revocation and sealed CLI recovery. Later mixed/operator journeys remain
unqualified. D176's shared exact step builder now passes the real Normalize parser;
old hyphen IDs still return ErrInput. Original ba x86 mixed receivers/consent/
decryption passes within884application records;exact ARM/full public replay is required.

D175's prepared observer lets Chrome send original HTTPS requests and binds final
network headers to the original bounded response. It preserves cookie/session,
CLI authority,CSRF,expiry,fetch-site,body,key,byte,source-contact,cleanup and audit
assertions. Response loss drops only the first completed response; original-key
recovery remains mandatory. Eight native-protocol stand-in methods,144 frontend
contracts and102 Python contracts pass locally. First explicit metadata/verification
now passes in both ba public profiles. Full matrices and byte operator remain open. Native freightctl
is a named source stand-in. Independent typed collection and earlier intermittent
D145/D151/D152/D167 causes remain open.

[F075](docs/qualification/evidence/F075-peer-image-security.json) stays red. Both97
image gates observe regular1,691,381,760-byte databases above the original1 GiB
file cap,153-byte metadata and exact scratch unmount. Earlier ARM/x86 exact OOMs
remain separately proven;GOGC25 is not a remedy. The owner approved only the
1792 MiB database-file cap. Its exact reviewed patch is applied and21stand-in
methods pass; it cannot remedy OOM and real image scanning remains unqualified.
Hard1 GiB/no swap,soft768 MiB,one CPU,2 GiB scratch and all security/time guards
remain unchanged. No image scan is qualified.

[F077](docs/qualification/evidence/F077-native-reproducible-core.json) qualifies
only exact6dd's same-runner native core reproduction/component gate:two source
copies/empty caches,18 commands,physical empty build IDs,verified modules and final
source/binary/output/tool closures. Both native jobs bind14 Go modules,exact UI
assets/four runtime packages and214 ARM/215 x86 standard/compiler/vendor package
inputs. Actual pinned offline CycloneDX1.6 stock validation passes. No validator
ran locally and no artifact was uploaded. Independent-host same-target repeats,
complete implicit/generated/build-tool/deployment inventory,upstream license
review,owner grant,signing and disconnected installation remain mandatory.

[F078](docs/qualification/evidence/F078-windows-filesystem-observation.json) records
elevated NTFS API facts:explicit protected owner/SYSTEM descriptors match;read-write
directory handles flush successfully while read-only handles/reopen upgrades fail5.
Go modes remain0666/0777. This does not qualify access isolation,reparse/race safety,
power-loss durability or Windows server/agents;D103 stays open. F079 adds pinned
descriptor/full128bit identity checks before a writable directory flush in custody.
Two local own-file and seven custody contracts pass;Windows tests compile/vet only.
Actual Windows rename/reparse races,private ACL/root/key creation and full runtime
qualification remain required. [F068](docs/qualification/evidence/F068-ftps-client-transport.json)
retains ARM stock metadata passes and x86 filter failures;native ARM filtering is
unavailable and active FTP remains disabled. [F074](docs/qualification/evidence/F074-ftps-recipient-encryption.json)
retains independent encryption evidence;readback differs from receiver fsync/business
acceptance. Full protocol,processing,recovery,capacity,packaging,adoption and X05's
authorized inference endpoint remain open. The [durable CI plan](docs/qualification/github-actions-plan.md)
and exact qualification/remaining-work ledgers govern the next action.
