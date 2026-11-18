# Export and verify selected file revisions

Use `freightctl bundle-export` to take exact file revisions out of a
workspace. The command uses the same read permissions, namespace checks,
and intake release checks as an ordinary download. Select immutable
revision IDs, which identify particular bytes even if a path changes.
A protected request file has this shape:

```json
{"file_ids":["33333333-3333-4333-8333-333333333333"]}
```

```sh
umask 077
freightctl bundle-export --tenant "$TENANT" --partner "$PARTNER" \
  --request-file .private/file-revisions.json \
  --output .private/file-revisions.tar
freightctl bundle-verify --input .private/file-revisions.tar
```

Use the ordinary `--dsn-file`, `--token-file` and `--storage` selectors
for a workspace outside the local defaults. Choose a new archive name in
a private directory. One export can hold 1–64 unique revisions and up to
1 GiB of payload. If any selection is unavailable, the entire export fails.
The command stages the archive privately, checks current authority again
and records the prepared manifest and archive hashes in PostgreSQL. It
seals and syncs the file before linking it to the output name without
overwriting. The event records preparation. A local file or directory-sync
error can leave a verified file whose durable publication still needs
inspection.

## Inspect and recover with ordinary tools

The uncompressed USTAR archive starts with `manifest.json`. Its
`freightctl-portable-files-v1` manifest records the source tenant and
partner, followed by ordered revision IDs, byte lengths, and SHA-256
hashes. Each payload is a regular `files/<revision-id>` member. Use the
archive hash from the original export receipt to identify an expected
copy independently. Offline verification checks the format and every
payload, including the archive framing.

```sh
umask 077
mkdir -m 700 .private/recovered-revisions
tar -tf .private/file-revisions.tar
tar -xf .private/file-revisions.tar -C .private/recovered-revisions
```

Extract into a fresh private directory after verification. Upload recovered
bytes using ordinary destination credentials and intake policy. The
destination issues its own file revision IDs. Keep the source manifest
and the destination acceptance receipts together to trace the move.
Whole-workspace configuration, partner policies, receipt history and
complete exit remain separate work.
