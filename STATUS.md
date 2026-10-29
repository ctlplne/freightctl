# freightctl status

- Updated: 2026-10-29; Stage 1. The full product goal is active.
- Workspace: `/Users/shankar/Desktop/ctlplne-freightctl`, local `main`.
- Both Git author and committer: `imfeelingtheagi <288773099+imfeelingtheagi@users.noreply.github.com>`.
- Local inference stays off: no model runtime, load, warmup or evaluation. Cached weights and host RAM do not grant resource permission. X05 needs an owner-authorized endpoint and explicit allowance.
- The real malware engine and standard signature database stay unloaded. X06 needs the owner's resource/endpoint choice. Neither elapsed time nor a preselected option is approval.
- No new push, publication or external deployment is authorized or performed.

## Current implementation and evidence

The core has durable PostgreSQL events and exact command receipts, immutable byte custody, tenant/partner/actor permissions, virtual paths, stock SFTP/HTTPS, durable upload checkpoints, outbound delivery intents, approved typed workflows, held CSV checks, public signature verification, recipient encryption, scanner integration controls and an embedded browser workspace. Model output remains a validated proposal; ordinary implemented workflows run with AI disabled. Actual inference, malware detection and private signing/decryption custody are still unqualified or incomplete.

F018 is the current worker-recovery record: [evidence](docs/qualification/evidence/F018-browser-worker-recovery.json). A real check worker is killed after its reservation commits. Browser/API recovery refuses replacement before the original 70-second lease expires. After expiry, an explicit review binds the replacement to the exact check revision, old worker/lease, source digest and policy digest. The backend compares these selectors under the claim lock and rechecks current access and bindings. A lost committed response retries the same command and recovers attempt two; CLI replay returns that same receipt. Separate release and native/stock-curl retrieval verify the original 900,000-row CSV bytes. Chromium is closed while waiting for the lease. This new recovery fixture is CSV-only; signed/scanner recovery and governed re-scan/rebind remain open.

F017 retains signed-browser/recovery evidence. Chromium pauses/reloads, survives fixture-server restart, resumes the exact source, attaches an independent armored signature, checks, reviews and releases. The check and release review show full primary/signing fingerprints, registered key version/hash, signature digest/format and verification timestamps. Source, policy and report digests bind that review to the exact revision; the backend rechecks live authority and cryptographic proof.

Lost committed check/release responses now retry with the same command identity and recover the original receipt. Release review stays frozen until confirmed or explicitly canceled; definitive refusals require refresh/new review. Native injection proves one check attempt. Wrong signers, changed contents, malformed/oversized signatures and live signer revocation refuse the relevant operations. Independent GnuPG verifies both Chromium's and stock curl's received bytes against the product's served signature. This is assisted same-host evidence, not downstream business acceptance.

All **30 implemented-core gates** pass on **181 unchanged final source entries**: ten frontend proof contracts/typecheck/artifact integrity, module/vet/unit/race, real PostgreSQL integration/migrations, eight bounded fuzz gates, stock clients, upload/restart, delivery/workflows, synthetic no-inference assistance, held intake, scanner outage, both exchange browser profiles, worker-death browser recovery and independent signed/encrypted receivers. Native GnuPG is explicitly selected and has a sampled 128 MiB child-family watchdog; the observer/OS and unsampled peaks are separate. Serial gates and per-process heap settings are not a global CPU/RSS cap.

Migrations 1–16, the 70-second lease, three-attempt budget, two worker slots, fencing and separate release are unchanged by F018. Recovery reuses the ordinary check engine through browser/API/CLI. All 35 domain relations require forced RLS under a non-owner runtime. New bootstrap defaults have 21 grants; existing grants are preserved. The runtime retains SELECT-only credential access; F016's isolated non-owner projection trigger validates ordinary account commands and atomically invalidates admitted browser sessions on security changes.

F001–F017 and their original failures remain in `docs/qualification/evidence/`. F015 restored fresh independent crypto regressions with an explicit native peer after Docker/GnuPG probes stalled Created/PID zero; that Docker issue remains unresolved on this host. F016 is bound to `da10d06` by all 174 source Git blobs; F017 is bound to `7e606de` by all 176. F018 retains D047's first real worker-death failure: its lease expired but the browser lacked a recovery action. The original sources and corrected native journeys are retained. D043's earlier custody fuzz deadline remains open with unassigned timing cause despite the unchanged current gate passing. Fresh native source/history secret scans have zero findings. The full JavaScript audit has zero advisories; Go reachability retains only the existing legacy OpenPGP module advisory outside imported packages. GitHub workflow execution remains unverified.

## Repository and readiness

Owner-requested recreation is complete; implementation, protected credentials, models, PostgreSQL data and evidence are preserved. New history starts at `e1eab1a`. The recorded repository ID is `1437631520`, origin is `https://github.com/ctlplne/freightctl.git`, and the last recorded remote head is `b48fe6b`. The 2026-10-29 GitHub observation reported private visibility, main and login imfeelingtheagi. Local main has advanced without a new push. All inspected reachable author/committer identities are the required owner identity.

- Assisted design-partner deployment: **Not qualified**.
- Ordinary operator adoption: **Not qualified**.
- Enterprise/release qualification: **Not qualified**.

All **83 complete baseline rows** and **12 product journeys** remain open. [Remaining work](docs/qualification/remaining.json) and [journeys](docs/qualification/journeys.json) retain the full scope; a green implemented-core regression does not close those requirements.

## Next work

Finish ordinary first-admin/partner onboarding, invitations/providers/delegation and broader browser exchange. Extend conditional recovery to native signed/scanner cases; add governed re-scan/rebind, private crypto custody, protected retention/cleanup and journal reconstruction. Qualify genuine scanning after X06 and actual inference after X05 without loading either by inference from installed software. Continue schedules/calendars, connectors, migration/cutover/exit, protocol/peer breadth, gateway/agents, fair admission, native platforms, multi-host failure/restore, performance/endurance and disconnected packaging/security. Diagnose D043 without relaxing its original gate. Keep independent adoption, enterprise claims and all external prerequisites explicit.
