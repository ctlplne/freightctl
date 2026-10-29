# Selected real scanner runtime

F023 exercises ClamAV 1.5.4 with genuine official signatures through the ordinary held-file path. A scan is a dated inspection of specific bytes. It does not publish them: an authorized operator separately releases the exact report, policy and file revision. General malware coverage, production deployment and the full business-file journey remain open.

The owner authorized at most **4 GiB RAM and one CPU** for scanner qualification. The application, scanner and stock curl ran together inside that hard kernel limit. Local inference remains off. The runtime is stopped after each journey; signature databases, custody and evidence remain on exact task-owned volumes.

## Observed profile

| Boundary | Actual setting or observation |
| --- | --- |
| Image | Official `clamav/clamav:1.5.4_base`, digest `sha256:1afb149cf8b3c501a143874516a5f7cd3ce0ca3c2fd9201de97039ce6371a6fc` |
| Execution | Actual Linux/amd64 process under emulation on arm64 macOS. This is not native Linux or native macOS qualification. |
| Signatures | Official daily 28168, main 63 and bytecode 339; FreshClam database load tests enabled and passed; read-only during the journey. |
| Identity | Nonroot `100:101`, all capabilities dropped, no new privileges, read-only container root, 128 PID limit. |
| Memory | `memory.max=4294967296`; memory and swap limits equal, so no extra swap allowance. Peak for this run: **1,128,042,496 bytes**. Zero OOM/kill events. This observation is not a size estimate for other feeds or workloads. |
| CPU | `cpu.max=100000 100000`: one CPU worth of time per period, shared by scanner, application and client. |
| Temporary space | 128 MiB tmpfs, `nosuid,nodev,noexec`, private scanner directory. No temporary scan files remained at the final observation. Broader temporary-space behavior remains required. |
| Transport | Protected `0600` Unix socket under a `0700` directory. No scanner TCP listener or published container port. |
| Database/API | The exact retained task PostgreSQL network namespace supplies loopback PostgreSQL and loopback TLS API. PostgreSQL and host observers are separate existing resources. Only the ordinary runtime database credential enters the scanner container. |
| Engine bounds | One scan thread, queue two; 8 MiB stream/file limits, 16 MiB expanded scan limit, recursion four, 100 files; three-second engine scan limit and ten-second adapter deadline. Existing two PostgreSQL scan slots and check lease/fencing remain unchanged. |

The strict configuration still requires archive scanning, limit/encryption alerts, official databases and signed bytecode. Reload, shutdown and statistics commands are disabled; concurrent reload and self-check are disabled for this immutable snapshot. Updating signatures requires an explicit new qualified profile and policy selection. The built-in image healthcheck targets its default socket and reports unhealthy with this custom socket; it is not used as readiness evidence. The harness waits at most 30 seconds for the configured socket and obtains the actual VERSION reply. Production packaging needs a healthcheck for the configured socket.

## Repeating the retained journey

Use `python3 scripts/qualify-scanner-real.py --runtime-reference .private/EXACT_RUNTIME/state.json` only after preparing an authorized task-owned runtime. The protected state identifies the exact container ID, image, volume and application/configuration digests. It grants no authority by itself. The harness checks actual Docker ownership, nonroot restrictions, read-only signature mount, exact PostgreSQL container identity and kernel caps before proceeding.

The preparation captured in F023 uses the pinned image, retained official database volume and a separate task volume. A non-networked preparation container copies the Linux application and protected configuration, sets executable/configuration modes and then ownership. The runtime uses the image's actual ClamAV user. `volume-nocopy` preserves database ownership; Docker's empty-volume image population had reset earlier ownership attempts. A separately captured, signed-package Alpine curl installation lives in the task volume and runs under the same final cgroup. No application package dependency changed. The protected preparation scripts, package versions, first failures, database hashes and exact commands are referenced by the evidence record.

Build the application from the selected source using the pinned Go toolchain with `GOOS=linux GOARCH=amd64 CGO_ENABLED=0`. A successful build establishes only that it compiled; the retained journey establishes actual execution. Generate new TLS output paths for each journey and pass secret values through protected references or stdin. Preserve the runtime credential's restrictive file mode. Never mount the PostgreSQL administrative credential in the scanner container.

The harness drives these outcomes through real CLI, TLS API, disk and PostgreSQL:

1. Enroll the observed engine/configuration and recover the same enrollment receipt. Refuse profile reads from foreign partner/tenant scopes.
2. Accept a CSV durably into hold, scan it, keep it unavailable until separate exact release, and compare stock-curl retrieved bytes with the original bytes.
3. Detect the harmless EICAR marker directly, inside ZIP and inside nested ZIP. Reject before CSV parsing; journal only bounded metadata and detection-name hashes.
4. Observe a clean scan followed by invalid CSV rejection. Block archives exceeding file count, recursion or expanded-byte limits, and an encrypted archive.
5. Pause only the exact daemon, retain access to an already fresh released snapshot, and fail a new scan after the unchanged ten-second deadline. Unknown remains held. Resume the daemon.
6. Change the pinned configuration after release and refuse further reads. Restore the exact protected bytes, verify retrieval while the original proof is current, then revoke the profile and refuse further bytes.
7. Retain kernel resource observations, engine logs and source hashes; stop only the exact task runtime on success or failure. The retained PostgreSQL service and volumes remain intact.

The [EICAR standard test file](https://www.eicar.org/download-anti-malware-testfile/) checks antivirus response without using real malware. These selected cases do not establish general detection sensitivity, false-positive rates or independent corpus coverage. The protocol follows the [official clamd command contract](https://docs.clamav.net/manual/Usage/ClamdProtocol.html); an encrypted, authenticated scanner TCP transport is not provided by this profile.

## D058 and remaining work

The first real journey returned HTTP 200 bytes after the scanner configuration changed following release. SQL checked durable proof, expiry and profile state, but SQL cannot inspect a local file. F023 adds the missing host check to the common availability guard. Every new read and every bounded read on an open revision reader now validates the exact release profile and protected configuration before sending bytes. Content drift, loose permissions and a missing configuration all return no bytes. Real PostgreSQL regressions first failed on all three cases, then passed unchanged after repair. A later scanner socket outage alone still does not erase an already current proof.

This profile trusts the local socket process/operator and Docker host. File hashing does not remotely attest which configuration or full corpus a hostile process loaded. Independent corpus, broader archive/parser/timeout and expansion-ratio coverage, fair resource admission, feed update/redistribution lifecycle, governed re-scan/rebind, ICAP/DLP, delegated review, hardened production isolation and native deployment platforms remain required. Full J02, S-SCAN, assisted deployment, independent adoption and enterprise release remain unqualified.
