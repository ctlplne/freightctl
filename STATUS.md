# freightctl status

- Updated: 2026-10-29; Stage 1. The full product goal is active.
- Workspace: `/Users/shankar/Desktop/ctlplne-freightctl`, local `main`.
- Both Git author and committer: `imfeelingtheagi <288773099+imfeelingtheagi@users.noreply.github.com>`.
- Local inference stays off. No model runtime, load, warmup or evaluation is authorized. X05 needs an owner-authorized endpoint and explicit resource allowance.
- The real malware engine and standard signature database stay unloaded. X06 needs the owner’s resource/endpoint choice; time and preselected options grant no permission.
- No new push, publication or external deployment is authorized or performed.

## Current work

F019 adds protected `setup-plan` and one-time `setup`: generated tenant/partner/admin IDs, explicit names and grants, credential fingerprint, durable storage identity, atomic enrollment/event/receipt and exact historical retry. The normal runtime receives no bootstrap write authority. Browser sign-in can import bounded workspace IDs; imported origins, credentials, grants and commands cannot change authority. See [first-run instructions](docs/first-run.md).

Focused real PostgreSQL tests pass atomic rollback, concurrent plans, runtime refusal, actor-private receipt visibility, exact retry, legacy-install preservation and ordinary account creation after setup. An assisted empty-database native browser/stock-curl/restart exchange passes. This is initial tenant/partner scope enrollment, not complete partner lifecycle or independent adoption. The final candidate passes **31 implemented-core gates** on **188 unchanged source entries**, including eleven frontend contracts, real PostgreSQL/race/migrations, all eight bounded fuzz gates, first-run enrollment, stock protocols, delivery/workflows, no-inference assistance, held checks, scanner outage, browser exchange/recovery and independent crypto. See [F019 evidence](docs/qualification/evidence/F019-first-run-enrollment.json).

Migration 17 adds the immutable installation receipt as the 36th forced-RLS domain relation. Migrations 1–16, existing grants, the 21 default permissions, 70-second check lease, three-attempt limit, two worker slots, fencing and separate release remain unchanged. The runtime stays non-owner/non-BYPASSRLS with SELECT-only credential and installation-receipt access.

D049 retains the first aggregate’s scanner-verdict/profile-expiry and staging-cancellation timing failures on unchanged source. The PostgreSQL gate took 616.603 seconds versus 273.018 previously. A durable-sync wait was observed; timing cause remains unassigned. Both the prior committed schema and unchanged candidate pass the affected original tests in later serial replays. The first baseline probe lacked a required fixture password and provides no product evidence. No assertion, deadline, durability, isolation or resource target was relaxed.

## Previous completed evidence

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
