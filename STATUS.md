# freightctl status

Updated 2026-11-05. Application implementation is **active** under owner decision
S003, recorded verbatim in [the owner-decision ledger](docs/qualification/remaining.json).
The complete GOAL.md baseline and AX01–AX08 remain required. All 83 whole parity
rows and twelve full customer journeys remain open. Assisted deployment,
independent adoption and enterprise readiness remain separately unqualified.

Starting local main: dc74d8e33487dae53f18ebaa030a372e97770e9d; clean on resume.
Origin/main: 85695f62a0b40bdccca92e16aa6ffbb17543c0a1. Its eleven runs are
terminal. Exact run/job handles are retained; nonsecurity log investigation and
repair are deferred to mandatory FINISH. No original run was canceled.

Security triage: source/core/native vulnerability gates pass at 85695f6.
Both native peer-image scans now reach enforcing-summary and refuse invalid
evidence (exit2); the precise check is unknown. Both observe DB1691381760 within
the approved1792MiB file allowance and exact scratch unmount. Existing F075 OOMs
remain separate blockers. A static verifier-location diagnostic is prepared;
it changes no check, finding policy, coverage or budget. No image is qualified.
Original security evidence: .private/freightctl-s003-resume-security/manifest.json
SHA256 7dffb350c24e2512034d498d4a287ef75129aef85cb552124bcbe9345160f6ba.

Source/CI batches are authorized after previous required runs are terminal.
The repository-local pre-push guard is enabled: pinned Gitleaks, exact owner
author/committer and existing-origin/main fast-forward checks. It never authorizes
release/package/image/artifact publication, visibility changes or deployment.

F080 implements bounded canonical endpoint/exchange contracts. Four focused
methods, store vet and import architecture pass; the observed uppercase JSON alias
regression is repaired. This grants no runtime or exchange qualification. Next:
implement durable registered endpoints, polling/retrieval and separately authorized
reply using existing PostgreSQL/custody services. Keep per-item focused proof; native/served outcomes
stay owed until actual CI. Trust Control X07 blocks only its real provider profile.
Retained schema35 and resources are unchanged. Local inference and heavy runtime
qualification stay off; F026 remains manual/owner-deferred.
