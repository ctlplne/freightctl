# FTPS receiving development profile

`serve-ftps` receives uploads and serves authenticated downloads through the same PostgreSQL, namespace, permissions, immutable revisions and intake policy used by the other transfer interfaces. Explicit mode starts with a plaintext greeting and requires `AUTH TLS` before login. `--ftps-implicit` negotiates TLS before the greeting. Both control and data connections require TLS1.3.

This is an implementation under qualification. Native ARM application/database/storage journeys pass with the Python TLS client stand-in. The macOS system curl8.7.1/LibreSSL3.3.6 pairing does not resume its TLS1.3 control session for data and is refused. The dedicated native Linux ARM/x86 stock-curl jobs pass atbef49ed in F059. The full native workflows remain red at D121 before PostgreSQL integration and require replay after its test-contract repair. These component results do not close a full parity row. Windows D103, production networking and the complete FTPS parity rows remain open.

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

On this Mac, `--native-client-only` explicitly exercises the native TLS1.3 client stand-in and leaves `stock_curl_qualified=false`. It is not a substitute for the stock-client gate. GitHub runs full stock qualification on real native Linux ARM/x86 runners, the pinned engine's full tests separately, and bounded active-address fuzzing. No model, scanner or owner-deferred aggregate runs.

Remaining work includes proactive FTPS sending/collection against independent servers, more stock/enterprise clients, token/key/certificate rotation and revocation during active work, selected intake/quarantine journeys, fair admission and sustained load, upload-ticket recovery, IPv6 and firewall/gateway profiles, production certificates/listener configuration, Windows custody, large files, crash/power-loss tests and complete customer journeys. The pinned engine's cryptographic and source boundary is documented in [0016](architecture/0016-ftps-channel-binding.md) and [its source notice](../third_party/ftpserverlib/FREIGHTCTL.md).
