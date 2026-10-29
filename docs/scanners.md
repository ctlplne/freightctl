# Local scanner integration

This integration keeps a required scan between signature verification and CSV parsing. It streams the exact accepted revision to a configured local `clamd` Unix socket. A clean response can let the check pass; a separate ordinary release decision still controls publication. A missing, expired, changed or malformed scanner produces a failed check and leaves the bytes held.

The adapter and publication guards have local control tests. **Real malware detection is unqualified.** No ClamAV daemon or standard signature database was loaded for F013. Synthetic protocol peers test parsing and refusal; they establish no detection coverage. The real CLI/HTTPS journey deliberately uses an absent socket to prove outage behavior. Local inference also remains off.

## Enroll a reference

Use `scanner-register --request-file REQUEST --idempotency-key KEY` with the ordinary tenant, partner, database and protected token selectors. Enrollment requires `admin`, `scanner_manage` and the root mount. It validates protected local configuration without starting or contacting the engine. Existing credentials receive no automatic grant upgrade. New development administrators receive twenty grants.

The request has `expected_version: 0` for a new scanner, plus this `definition`:

| Field | Meaning |
| --- | --- |
| `schema_version` | `1` |
| `kind` | `clamd-instream-v1` |
| `socket_reference` | Absolute private Unix socket path, at most 100 bytes. No TCP or DNS endpoint. |
| `configuration_reference` | Absolute protected regular file, at most 32 KiB. |
| `configuration_sha256` | SHA-256 of those exact configuration bytes. |
| `expected_version` | Exact VERSION reply: engine, database serial and build date. Select it from an authorized engine, never from the synthetic test values. |
| `valid_until` | Future expiry within 72 hours of both database time and signature build time. The profile requires `TZ=UTC` because clamd's date has no time zone. Enrollment canonicalizes expiry to UTC microseconds before hashing. |
| `max_bytes` | 1 byte–1 GiB, additionally constrained by intake and custody quotas. |
| `timeout_seconds` | 1–60 seconds. The enclosing check deadline can expire sooner. |
| `max_result_age_seconds` | 60–3600 seconds. Proof also expires with the profile. |

`scanner-status --scanner-id ID --version VERSION` returns sanitized metadata. HTTP uses `GET /v1/tenants/{tenant}/partners/{partner}/scanners/{scanner}/{version}`. Neither response contains socket/configuration paths. HTTP cannot enroll host paths. To revoke, use `scanner-revoke --scanner-id ID --version VERSION --definition-hash HASH --expected-revision REVISION --idempotency-key KEY`, or POST the ordinary revision/hash decision to the resource's `/revoke` route. Revocation is permanent for that version.

Add `"scanner": {"id": "ID", "version": 1, "hash": "DEFINITION_HASH"}` to a new intake policy. Use actual enrollment output. Policies without this field retain their original canonical meaning and scope. Installing a scanner does not retrospectively certify old files. A new database/configuration/version requires explicit new enrollment and policy selection; governed re-scan/rebind is still required work.

## Protected engine configuration

The deployment operator owns the engine and signature updates. freightctl never launches a process or loads a database. Keep socket parent, database and temporary directories private (`0700`), the configuration `0600`, and the socket `0600`. Enroll only the exact reviewed configuration. Unknown directives, duplicate keys, includes, TCP listening and executable hooks are refused by this profile.

The accepted configuration subset requires `Foreground`, `ScanArchive`, `AlertExceedsMax`, `AlertEncrypted`, `OfficialDatabaseOnly`, `Bytecode` and `EnableVersionCommand` to be `yes`. It requires `ConcurrentDatabaseReload`, `EnableReloadCommand`, `EnableShutdownCommand` and `EnableStatsCommand` to be `no`, `SelfCheck 0`, and `BytecodeSecurity TrustSigned`. Socket reference and mode must match the definition. Other optional accepted scan switches are explicit configuration choices; the hash records them, without establishing their detection coverage.

| Engine bound | Accepted range |
| --- | --- |
| `MaxThreads` / `MaxQueue` | 1–2 / 2–8; queue at least twice threads. |
| `StreamMaxLength`, `MaxFileSize` | At least selected `max_bytes`, at most 1 GiB. |
| `MaxScanSize` | At least selected `max_bytes`, at most 2 GiB expanded bytes. |
| `MaxRecursion` / `MaxFiles` | 1–8 / 1–1024. |
| `MaxScanTime` | 1000 milliseconds through the configured adapter timeout. |
| `ReadTimeout`, `CommandReadTimeout` | 1 second through the adapter timeout. |
| `SendBufTimeout` | 1 millisecond through the adapter timeout in milliseconds. |

These checks pin a local configuration file. They cannot prove that a hostile or misconfigured daemon loaded it, authenticate a full signature corpus, enforce the daemon's RSS, or establish safe expansion ratios and temporary-disk limits for every archive format. The socket process and operator remain a trust boundary. Engine version admission accepts patched 1.4 (at least 1.4.6) and 1.5 (at least 1.5.4); this is parsing policy, not a runtime-qualification claim for either branch or a future patch.

ClamAV documents a 3–4 GiB memory recommendation for the standard database. On this shared machine the database stays unloaded until an explicit resource allowance or an appropriate existing endpoint is provided. An ICAP service needs its own adapter and qualification; it cannot be inserted into this Unix protocol interface. See [ClamAV requirements](https://docs.clamav.net/), [protocol](https://docs.clamav.net/manual/Usage/ClamdProtocol.html) and [pinned upstream configuration](https://github.com/Cisco-Talos/clamav/blob/clamav-1.5.4/etc/clamd.conf.sample).

## Exact bytes and publication

One `IDSESSION` sends VERSION, INSTREAM, VERSION, END. The two exact version replies bind engine and signature version around the stream. Chunks are at most 32 KiB; the adapter verifies accepted length, EOF and SHA-256 before finishing the stream. A clean result must be the exact correlated `stream: OK` reply. Missing IDs, extra replies, errors, early success, control characters, oversized records, version drift and trailing bytes fail closed. Detection names enter evidence only as hashes. Limit/encrypted heuristic detections are `blocked`; other detections are `detected`. Both reject before CSV parsing. These classifications currently have protocol-fixture evidence only.

Two PostgreSQL scan admission slots operate across application processes, separately from delivery/encryption slots. The existing check worker owns its normal 70-second lease, three-attempt limit and authority fence. Scope and ownership are rechecked during bounded reads. No unbounded in-process scan queue is added. Kernel filesystem operations that never return still need host/storage recovery; cancellation cannot interrupt such an operation.

The report binds source digest/length, exact profile hash, engine/database/configuration, response hash and timestamps. Proof expires at the earlier of profile expiry and scan start plus its configured maximum age. Release rechecks current authority, actual bytes, approved report, profile and configuration hash. It uses the recorded fresh scan snapshot without contacting the daemon again. Later socket outage alone does not invalidate an already valid snapshot; expiry or profile revocation does. SQL checks the selected proof before publication, and each ordinary bounded read checks current availability. Revocation cannot retrieve bytes already sent.

## Verification and remaining work

`python3 scripts/qualify-scanner-controls.py --pgp-fixture-reference .private/EXISTING_FIXTURE` runs serial checks with one Go execution thread, using a fresh two-row synthetic public-key fixture. It runs all-package unit/race, real PostgreSQL consumers, scanner/CSV fuzzing, stock-client regressions and the real outage journey. It continues independent gates after failures and preserves a failed overall status. A stale fixture cannot turn green: its unchanged one-hour signature policy still rejects it. The current broader consumer run is red because fixture refresh timed out with Docker reporting Created/PID zero. It does not rerun unchanged independent crypto-container journeys; F011/F012 retain their exact original evidence. `scripts/qualify-foundation.py` includes scanner parsing and outage gates in the full suite.

F013 records exact source and output hashes, first failures and scope. Operational standard-database detection, genuine engine behavior under malformed/archive/timeout cases, official feed freshness/rights, OS sandbox/RSS/temp-disk controls, independent detection corpus, ICAP/DLP, re-scan/rebind, delegated review and native deployment platforms remain open. Full J02 and the S-SCAN baseline row remain unqualified.
