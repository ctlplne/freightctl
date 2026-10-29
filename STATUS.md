# freightctl status

- Updated: 2026-10-29; Stage 1. The full product goal is active.
- Workspace: `/Users/shankar/Desktop/ctlplne-freightctl`, local `main`.
- Both Git author and committer: `imfeelingtheagi <288773099+imfeelingtheagi@users.noreply.github.com>`.
- Local inference stays off. No model runtime, load, warmup or evaluation is authorized. X05 needs an owner-authorized endpoint and explicit resource allowance.
- The real malware engine and standard signature database stay unloaded. X06 needs the owner’s resource/endpoint choice; time and preselected options grant no permission.
- No new push, publication or external deployment is authorized or performed.

## Current work

F020 adds explicit tenant directory authority bound to a current root administrator credential. Protected deployment maintenance grants, revokes or inspects that authority; first-run can explicitly opt in. Existing accounts and new partner administrators inherit no tenant authority. Ordinary browser/API/CLI enrollment reviews exact credential/grant revisions, saves a generated credential before proof-only creation, and commits source/target enrollment events with one original receipt. See [partner enrollment](docs/partner-enrollment.md) and [F020 evidence](docs/qualification/evidence/F020-tenant-partner-enrollment.json).

All **32 final core gates pass on 196 unchanged executable source entries**, including **137 PostgreSQL integration tests with no skips** and 12 frontend contracts. Native Chromium/stock curl pass response-loss receipt recovery, stale/cached/rotated authority refusals, new-partner transfer/restart and cross-partner isolation. Fresh review/directory/transfer screenshots were inspected; confirmed recovery clears the earlier error banner. Migration 18 adds three forced-RLS relations (39 total) and an isolated non-login/non-owner/non-BYPASSRLS partner projection writer. The runtime retains SELECT-only credentials/authority and no direct partner INSERT. Migrations 1–17 and the 21 ordinary permissions/existing grants are unchanged.

The first aggregate failed on the same sources under **D052**: the encrypted-publication helper reached a 65-second deadline, with later database-unavailable/statement-timeout failures. Its native output, original sources, probes and a deliberately interrupted replay remain retained. After the owner manually restarted Docker Desktop, this chat verified/restored only its exact retained PostgreSQL container/volume with unchanged 512 MiB/one-CPU limits. All 16 original failed cases then passed unchanged before the full aggregate. This does not establish the original cause; D052 stays open with D043/D049. No assertion, deadline, durability, isolation or resource target was relaxed, and this chat performed no Desktop restart or cleanup.

Current source/full-history secret scans have zero findings; full JavaScript audit has zero advisories; Go has no imported affected package or reachable vulnerable symbol, retaining the module-only legacy OpenPGP advisory. Native secret-scan peaks were 83.5/74.7 MiB and the audit peak was 102.4 MiB. These measurements and 192 MiB soft heaps are not hard RSS limits. Final metadata and the new local commit receive separate private scans/verification. No push, model or real malware engine/database is involved.

## Previous completed evidence

F019 at `f5f9767` is the last completed aggregate: **31 gates**, **188 unchanged source entries**, one-time first tenant/partner/admin setup, exact historical receipt replay and browser workspace ID import. The first-run and original failures remain retained.

F018 at `e3ba084` retains the previous completed aggregate: **30 implemented-core gates**, **181 unchanged source entries**. It proves actual worker death, original lease expiry, conditional browser/API/CLI recovery, stable lost-response receipt replay and separately approved exact CSV retrieval. F017 at `7e606de` proves assisted signed-browser review, signature refusal/revocation and independent downloaded-byte verification. F016 at `da10d06` covers ordinary scoped account lifecycle. These records and all earlier failures remain in [qualification evidence](docs/qualification/evidence/).

The implemented core also includes durable PostgreSQL events/receipts, immutable custody, tenant/partner/actor permissions, virtual paths, stock SFTP/HTTPS, upload checkpoints, delivery intents, typed approved workflows, held CSV checks, public signature verification, recipient encryption, scanner controls and an embedded browser workspace. Model output is only a validated proposal; implemented ordinary workflows run with AI disabled. Genuine inference/malware detection and application private signing/decryption custody remain unqualified or incomplete.

D043’s earlier custody fuzz deadline and D049’s timing cause remain open. F015’s explicit bounded native crypto peer works; the historical default Docker peer startup at Created/PID zero remains unresolved. Serial gates and 192 MiB soft process heaps are not global CPU/RSS caps. The native crypto watchdog samples its child family at 128 MiB; unsampled peaks and observer/OS costs are separate. Fresh native source/history secret scans have zero findings. The full JavaScript audit has zero advisories; Go retains the existing module-only legacy OpenPGP advisory outside imported packages, with no reachable vulnerable symbol. GitHub workflow execution remains unverified.

## Repository and readiness

Owner-requested recreation is complete; implementation, protected credentials, models, PostgreSQL data and evidence are preserved. New history starts at `e1eab1a`. Recorded repository ID: `1437631520`; origin: `https://github.com/ctlplne/freightctl.git`; last recorded remote head: `b48fe6b`. The 2026-10-29 GitHub observation reported private visibility, main and login imfeelingtheagi. Local work has advanced without a new push. All inspected reachable author/committer identities are the required owner identity.

- Assisted design-partner deployment: **Not qualified**.
- Ordinary operator adoption: **Not qualified**.
- Enterprise/release qualification: **Not qualified**.

All **83 complete baseline rows** and **12 complete journeys** remain open. [Remaining work](docs/qualification/remaining.json) and [journeys](docs/qualification/journeys.json) preserve the full scope.

## Next work

Continue general tenant/partner requirements, contacts, checklists, invitations/providers/delegation and production activation; broader browser exchange and sharing/batches/forms; signed/scanner recovery, governed re-scan/rebind, private crypto custody, retention/cleanup and journal reconstruction. Continue schedules/calendars, connectors, migration/cutover/exit, protocol/peer breadth, gateways/agents, fair admission, native platforms, multi-host restore/upgrade, performance/endurance and disconnected packaging/security. Diagnose D043/D049 without relaxing their gates. Keep X05/X06 and independent adoption/enterprise prerequisites explicit.
