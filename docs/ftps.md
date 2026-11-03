# FTPS receiving development profile

`serve-ftps` receives uploads and serves authenticated downloads through the same PostgreSQL, namespace, permissions, immutable revisions and intake policy used by the other transfer interfaces. Explicit mode starts with a plaintext greeting and requires `AUTH TLS` before login. `--ftps-implicit` negotiates TLS before the greeting. Both control and data connections require TLS1.3.

This is an implementation under qualification. Native ARM application/database/storage journeys pass with the Python TLS client stand-in. The macOS system curl8.7.1/LibreSSL3.3.6 pairing does not resume its TLS1.3 control session for data and is refused. The dedicated native Linux ARM/x86 stock-curl jobs pass atbef49ed in F059. The original full native replay at563751e passes on both architectures:223 engine pass records with one unchanged privileged-port20 skip, followed by569 PostgreSQL integration pass records with zero failures/skips each (F060). These component results do not close a full parity row. Windows D103, production networking and the complete FTPS parity rows remain open.

## Start a loopback server

Follow [development setup](development.md) to initialize PostgreSQL and create a scoped account/token. Use an enrolled production certificate when that environment exists. An explicit local test certificate can be generated with:

```sh
sh scripts/go.sh run ./cmd/freightctl dev-cert --cert .private/ftps.crt --key .private/ftps.key
sh scripts/go.sh run ./cmd/freightctl serve-ftps \
  --listen 127.0.0.1:28449 \
  --dsn-file .private/pg-runtime.dsn \
  --storage .private/custody \
  --cert .private/ftps.crt --key .private/ftps.key
```

Use a separate port and `--ftps-implicit` for implicit TLS. The server refuses wildcard/control addresses; passive sockets bind to that same approved loopback IP before listening. Active callbacks are disabled unless `--ftps-active` is set. They can connect only to the control peer's numeric IP and ports1024–65535; DNS, another peer and privileged service ports are refused. This callback serves the authenticated protocol operation. It is not the proactive FTPS delivery connector required by sending parity rows.

The FTP username is `<tenant UUID>/<partner UUID>`. Its password is the existing64-character scoped bearer token. The token selects the actor, permissions, namespace root and authority revision through the runtime database role; a username cannot select an actor or grant permissions. Store client credentials in an owner-only configuration reference. Do not put token values in command arguments, logs, source or screenshots. A curl configuration for an OpenSSL build that supports TLS1.3 FTPS session reuse has this shape:

```text
user = "<tenant UUID>/<partner UUID>:<scoped token value>"
cacert = "/absolute/path/to/trusted-ca.pem"
ssl-reqd
tls-max = "1.3"
noproxy = "*"
connect-timeout = 3
max-time = 10
silent
show-error
```

Keep that file mode0600 in an ignored private directory, then use `curl -q --config /absolute/private/client.conf --upload-file /absolute/input.bin ftp://127.0.0.1:28449/input.bin`. Use `ftps://` for an implicit listener. `-q` prevents a global curl configuration from changing this test. Certificate verification stays enabled. The server's TLS1.3 floor applies even when a client cannot set its own minimum-version option. A TLS1.2-only client is refused.

## Acceptance, permissions and interruption

An upload stages a separate object. Successful close hashes and synchronizes its bytes, records the immutable file and namespace/intake transition in PostgreSQL, and only then permits the final success reply. If an intake policy holds that revision, the bytes are accepted into custody and remain unavailable for retrieval until the ordinary checks and release complete. A226 response does not prove scanning, publication, recipient processing or business acceptance.

Detected aborts, TLS failures, data TCP EOF without TLS completion, control loss, quota errors and revoked authority fail the writer before cleanup close. An interrupted overwrite leaves the old accepted revision in place. A clean TLS close without a sender length/manifest contract describes the received stream; it cannot independently prove the sender intended no additional bytes. Losing the final response leaves an uncertain client outcome: inspect authorized file/audit state before retrying. FTP does not supply an exactly-once business contract.

Each data connection must resume the authenticated control session's TLS ticket. Matching an IP address alone is insufficient when clients share a router. Another control session's ticket, an unauthenticated ticket and a new full data handshake are refused. Closing the control session cancels its custody work, closes its data sockets and permanently disables its ticket binding. Current credential revision, path and file permissions are still checked by custody; a TLS ticket grants no file authority.

`TYPE I` preserves opaque bytes. Ordinary `TYPE A` listings and text transfers use the engine's text conversion; signatures and file digests bind the resulting stored immutable bytes. Use binary mode for signed, encrypted or byte-sensitive payloads. REST and APPE can operate on an already accepted file revision. Durable resumption of an interrupted unaccepted upload through governed upload tickets is still required; the reserved `.freightctl` control namespace is unavailable in this adapter.

Listings are paged from PostgreSQL and bounded by `--ftps-list-limit`. `--ftps-max-connections`, `--ftps-max-writers`, `--ftps-session-limit` and `--ftps-idle-limit` protect the initial shared database pool. Connections and data sockets have absolute and idle deadlines. SITE, recursive host operations, symlinks, arbitrary ownership changes, compression and unimplemented metadata operations are unavailable. These operational limits do not qualify the scale or large-file gates.

## Reproduce qualification

`scripts/qualify-ftps.py --postgres-container-id <exact task-owned64-character ID>` requires a bounded512MiB/oneCPU PostgreSQL resource with initialized schema35. It creates a fresh test database, runs the real service/stock-curl/TLS-client integration cases and both public CLI listener modes, compares retained metadata and roles before/after, removes only its test database and restores the initial running state. All raw data, credentials and diagnostics remain in ignored owner-only evidence. The public CI summary validates the original native outputs and actual downloaded bytes before publishing only counts and hashes.

On this Mac, `--native-client-only` explicitly exercises the native TLS1.3 client stand-in and leaves both stock-client qualification flags false. It is not a substitute for the stock-client gate. Its15 cases include wrong tokens, wrong partner/tenant identities, and the12 earlier transfer/interruption cases. The service tests try an existing other partner and tenant with the first identity's token; both must return530 before closing. The CLI fixture also tests nonexistent other identities. A failed login cannot authorize a file command.

The full GitHub profile now requires stock curl **and lftp**, actual PostgreSQL/storage, and both public listener modes on real native Linux ARM/x86. `install-ftps-clients.sh` only runs inside GitHub Actions on Ubuntu24.04; it installs the signed Ubuntu package `lftp=4.9.2-2ubuntu1.1` and records the actual package architecture and GnuTLS version. This GPL stock test client runs as a separate process and is not linked into freightctl or included in a release. Refresh that exact pin through a reviewed change if the repository no longer supplies it; missing installation fails the gate.

`lftp-probe.py` uses an owner-only command file, a fresh `LFTP_HOME`, no user rc, bounded output/retries/time, verified fixture CA/hostname and TLS1.3 only. It compares opaque NUL/CRLF bytes after EPSV, PASV, active upload/download and rename, and exercises listing/create/delete. Its command arguments contain only the protected file reference. The public reporter independently compares all four CLI download files in each mode; a reported success or synthetic record cannot replace those bytes. Fourteen refusal contracts check the reporting boundary. Failed CI output exposes only fixed test names and error categories; raw client diagnostics and credentials stay private. At `b99c8d2`, the dedicated native ARM/x86 lftp/curl jobs pass nine test records and41 commands each; both public CLI modes and all four downloaded byte streams per mode are independently verified. Full native regression replay is still running; the earlier563751e full suites passed569 PostgreSQL records each.

The client flags and TLS priority come from the [lftp manual](https://lftp.yar.ru/lftp-man.html), [Ubuntu's package record](https://packages.ubuntu.com/en/noble-updates/lftp), and [Ubuntu's GnuTLS documentation](https://ubuntu.com/server/docs/explanation/crypto/gnutls/). The pinned engine's full tests and bounded active-address fuzzing stay separate. Long native/FTPS workflows finish the running candidate while the newest pending candidate waits; a later push must not cancel the original qualification replay. No model, scanner or owner-deferred aggregate runs.

Remaining work includes proactive FTPS sending/collection against independent servers, more stock/enterprise clients, token/key/certificate rotation and revocation during active work, selected intake/quarantine journeys, fair admission and sustained load, upload-ticket recovery, IPv6 and firewall/gateway profiles, production certificates/listener configuration, Windows custody, large files, crash/power-loss tests and complete customer journeys. The pinned engine's cryptographic and source boundary is documented in [0016](architecture/0016-ftps-channel-binding.md) and [its source notice](../third_party/ftpserverlib/FREIGHTCTL.md).

The [F061 governance profile](qualification/evidence/F061-ftps-governance.json) coordinates a TLS client stand-in with actual scoped account and intake services. An open writer loses authority after rotation/revocation, cannot replace the old revision or commit an extra file record, and cannot authenticate again with its obsolete token. A fresh rotated token completes a separate transfer. Selected CSV uploads receive custody acceptance while held; valid parsing still needs separate digest/report-bound release, invalid data stays rejected/unavailable, and policy revocation blocks later retrieval. These new cases pass in the final guarded-source native local ARM replay; native stock replay and public CLI/API/browser governance mutation journeys remain open. The full GitHub profile now requires15 native pass records, while local stand-in mode requires all nine.

The [F062 operator journey](qualification/evidence/F062-ftps-cli-governance.json) drives account creation/rotation/revocation and intake register/run/release/revoke through the public CLI while the FTPS peer transfers or waits. Fresh protected credentials and scopes isolate each scenario. Saved-key retries must recover the same committed result; exact expected refusals keep their original exit code and fixed error category. The public summary checks original receipts, namespace views, check/file/policy bindings and ordered peer streams.

Inspect the authorized namespace with `namespace-stat --path /inbox/file.csv` or page it with `namespace-list --path /inbox --path-limit 50`, adding the ordinary `--dsn-file`, `--token-file`, `--tenant` and `--partner` references. Feed the returned `next` into `--path-after`. These read-only commands use the same virtual root, permissions and PostgreSQL role as transfers, with a ten-second context and pages of1–100 entries. Held/rejected files do not acquire a namespace entry merely because an upload received custody acceptance. A stat response is metadata, not proof of downstream business processing.
