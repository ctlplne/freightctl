# Qualification records

`parity.json` pins initial finite baseline `2026-10-28.1`. `sources.json` records official documentation observed on 2026-10-28. A document describes advertised behavior; it does not prove a vendor installation does it, or freightctl can interoperate. Rows explicitly keep licensed installation prerequisites open. Missing exact editions and protocol profiles are R001. GOAL.md stays authoritative if this initial inventory misses a requirement.

`journeys.json` tracks the 12 complete outcomes. A narrower foundation experiment can have its own evidence manifest without marking a complete journey passed. `defects.json` retains the first failure and subsequent repair evidence. `remaining.json` keeps all work groups and external dependencies visible. `ai-evaluations.json` records acceptance thresholds without fabricated model results.

Evidence must identify a tested Git commit (or starting commit plus exact dirty source hashes), built artifact digests, environment, command, native result, assistance, duration and limitations. Keep large logs and payloads out of Git. Commit safe manifests with references and hashes, after checking for credentials and sensitive data. A verified row needs nonempty evidence; an excluded row needs explicit owner authorization. These records never turn a skipped test into success.

Run `python3 scripts/check-records.py` to check record references and evidence requirements. This validates bookkeeping only. It does not qualify product behavior.
