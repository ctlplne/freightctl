# Artifact exchange CLI

These commands use the same domain services and ordinary scoped credentials as
the [HTTPS adapter](artifact-exchange.md). This is an operator CLI: it opens a
protected non-owner PostgreSQL reference and, for offers/downloads, existing
custody storage. It is not a remote HTTPS client. Database access does not replace
participant authentication, row-level security or current exchange permissions.

| Command | Input and result |
| --- | --- |
| `exchange-endpoint-command` | Protected `--request-file` plus original `--idempotency-key`; a root account manager records create/replace/revoke and its receipt. |
| `exchange-endpoint-list` | Optional `--exchange-after` and `--exchange-limit`; only currently visible endpoint heads and their page cursor. |
| `exchange-endpoint-inspect` | `--exchange-endpoint-id`; one currently visible canonical endpoint version. |
| `exchange-offer` | Protected canonical exchange request plus original key; publish or recover the original exact-revision view. |
| `exchange-incoming` | `--exchange-endpoint-id`, optional `--exchange-after`, `--exchange-limit` from1to100; recipient-only receive page. Restart each new polling cycle without the old cursor. |
| `exchange-inspect` | `--exchange-id`; current recipient-authorized offered/held status. |
| `exchange-download` | `--exchange-id` and explicit new `--output`; verify and sync a local file before returning its JSON result. |

All commands take the ordinary `--dsn-file`, `--token-file`, `--tenant` and
`--partner` references. Offer/download also take `--storage`. They accept the
same trusted deployment `--exchange-max-*` controls as `serve`; these settings
grant no permission. Keep requests and credentials in protected regular files
with mode0600 or stricter. No command reads credentials or request bodies from
artifact contents. A received artifact supplies neither forwarding nor execution
authority; separately authorized replies use new source bytes and a new key.

For example, after accepting the source and registering the endpoint:

```sh
freightctl exchange-offer \
  --dsn-file .private/pg-runtime.dsn --token-file .private/agent-a.token \
  --tenant TENANT_UUID --partner PARTNER_UUID --storage .private/custody \
  --request-file .private/exchange-request.json --idempotency-key original-offer

freightctl exchange-download \
  --dsn-file .private/pg-runtime.dsn --token-file .private/agent-b.token \
  --tenant TENANT_UUID --partner PARTNER_UUID --storage .private/custody \
  --exchange-id EXCHANGE_UUID --output .private/received-artifact
```

The output directory must be private, mode0700 or stricter. The download pins its
directory handle, stages mode0600 bytes there, checks the full length and SHA256,
syncs the file, and publishes a mode0400 file with an exclusive hard link. It
syncs the directory before reporting `local-file-verified-and-synced`. The
filesystem must support those operations. Existing files are never replaced.
An interrupted stream, changed directory, wrong digest or failed authority check
cannot publish partial or substituted bytes. Cleanup uses the pinned directory;
it does not delete a foreign replacement at the original pathname.

A failure after the exclusive link may leave a complete file whose directory sync
is unproven. Inspect that file and verify its identity before deciding what to do;
retry does not overwrite it. This local result proves no business processing and
does not upgrade the server's availability/read-authorization evidence.

Six focused parser/filesystem methods pass on local Darwin ARM, including an
observed directory-substitution failure and its repair. A native PostgreSQL
command-dispatch profile is prepared and compiled; runtime proof remains owed.
This is not a separate-process CLI or stock-client AX qualification. Windows
fails closed before private staging; native ACL/custody support remains owed.
