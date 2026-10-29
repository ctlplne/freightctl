# First tenant, partner and administrator

This is the implemented local first-run path. It uses an installed freightctl binary, PostgreSQL, a private filesystem directory and a TLS identity. The current local qualification runs on macOS with an existing PostgreSQL development fixture; a disconnected production installer, native Linux/Windows qualification and independent operator adoption remain open. No model or scanner engine is needed for the initial integrity-only exchange.

The deployment administrator supplies protected PostgreSQL connection references. The migration/setup connection has database administration authority; the running service uses the separate non-owner `freightctl_runtime` connection. Never give the service the deployment-admin reference. For the repository's assisted development fixture, `python3 scripts/dev-db.py` prepares `.private/pg-admin.dsn`, `.private/pg-runtime.dsn` and the runtime password reference. Initial development dependency acquisition needs connectivity; this helper is not the disconnected bundle.

At the repository root, use a private `.private` directory and `umask 077`. The examples use `sh scripts/go.sh run ./cmd/freightctl` in place of an installed `freightctl` binary:

```sh
umask 077
sh scripts/go.sh run ./cmd/freightctl init
sh scripts/go.sh run ./cmd/freightctl setup-plan \
  --tenant-label 'Example customer' \
  --partner-label 'Settlement partner' \
  --admin-label 'First administrator'
```

`setup-plan` writes `.private/setup.json`, creates or reads `.private/first-admin.token`, and opens `.private/custody`. It chooses the tenant, partner, administrator and operation IDs for you. It records the selected names, administrator grants, credential fingerprint and persistent storage identity. The credential value stays in its protected file. Inspect the plan locally before applying it. These labels describe the initial enrollment; general tenant/partner contact and lifecycle administration remain required work.

Explicitly add `--tenant-administration` when this first account should also enroll partners through the tenant directory. The protected plan records that separate authority decision. Without the flag, it receives ordinary partner administration. Existing accounts/plans are not upgraded implicitly. See [partner enrollment and authority lifecycle](partner-enrollment.md).

The plan refuses to overwrite an existing plan. An existing credential is read without replacement, so a partial preparation does not silently rotate it. If preparation fails, preserve and inspect its exact credential/storage references. Both output and credential parents must already be private directories. Existing storage must have mode 0700; secret references must have mode 0600 or stricter. Choose other locations with explicit `--output`, `--token-file` and `--storage` options.

Apply the reviewed plan:

```sh
sh scripts/go.sh run ./cmd/freightctl setup \
  --request-file .private/setup.json > .private/workspace.json
```

Setup checks the exact migration checksums and forced row policies, then takes database locks that also block concurrent legacy enrollment. It refuses any installation that already contains tenants, partners or accounts, unless this exact plan already committed. The first tenant, partner, administrator, immutable `InstallationInitialized` event and original result commit in one PostgreSQL transaction. A failure rolls everything back. The normal runtime role cannot perform this operation. There is no unauthenticated network setup endpoint.

If the response is interrupted, run the same `setup --request-file .private/setup.json` command again. It returns the original IDs, event and initialization time with `replayed: true`. Do not generate a replacement plan to recover a response. A changed plan, replaced credential or different storage identity is refused. A successful retry reports the original enrollment, not the current administrator's live access; ordinary authentication still checks revocation and expiry.

For an existing installation, use the ordinary Accounts workspace or `account-create`, `account-update`, `account-rotate` and `account-revoke` commands. Setup cannot reset an installation or regain access after losing an administrator. Audited emergency recovery remains required work.

For the loopback development profile, create the explicit development TLS identity and start the service:

```sh
sh scripts/go.sh run ./cmd/freightctl dev-cert
sh scripts/go.sh run ./cmd/freightctl serve
```

The default address is `https://127.0.0.1:28446`; enroll appropriate certificate trust for your client. The development certificate is not a production trust configuration. The default service uses `.private/pg-runtime.dsn` and `.private/custody`. If you selected another storage root, supply that same `--storage` reference to the service.

On the sign-in page, choose `.private/workspace.json` under **Workspace reference file (optional)**. It fills the two workspace IDs. Then choose `.private/first-admin.token` under **Account credential file** and connect. A workspace file can supply IDs only: it cannot change the server address, supply credentials, grant permissions or execute commands. Manual workspace ID entry still works for existing accounts.

Choose **Upload file**, select harmless sample bytes, choose a new destination such as `/setup.csv`, and start the upload. With no intake policy configured, acceptance promises persisted bytes with the recorded size and SHA-256; it makes no scanning, signature or business-delivery promise. Download the file from **Files** and compare its SHA-256 with the original. `scripts/qualify-setup.py` repeats this path against an empty real database, then checks the exact downloaded bytes independently with stock curl and again after restarting its own server.

Configure the partner's required intake/signature/scanner policy, least-privileged accounts and approved workflows before business use. Full partner requirements, connectivity testing, invitations/providers, delegated approvals, production activation, independent receipts and operator qualification remain open.
