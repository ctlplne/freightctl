# Plan a migration from SFTPGo Community

Use an authorized SFTPGo Community format-17 provider dump. The interface was
exercised with SFTPGo Community 2.7.6. Start with the original backup under its
existing protections and place a private copy in an owner-controlled directory.
The export may contain password hashes, provider credentials, private paths and
command arguments. Keep the export and the generated report in protected storage.
The [SFTPGo dump API](https://github.com/drakkan/sftpgo/blob/v2.7.6/openapi/openapi.yaml#L3644)
can write the dump into SFTPGo's private backups directory.

```sh
umask 077
freightctl migration-plan-sftpgo --source-file .private/sftpgo-dump.json \
  > .private/sftpgo-migration-plan.json
```

The command reads a private regular file without following a final symlink. It
checks JSON structure, unique keys, and the dump format before writing the report.
This profile accepts up to 8 MiB, 32 nested levels and 300,000 JSON tokens. If an
export exceeds those bounds, ask the source administrator for separately scoped
exports. Include action definitions and rules in the same export so the planner
can join them. The command runs offline and writes only the report to standard
output.

The report binds each location to the exact export through `source_sha256`.
A JSON pointer such as `/event_rules/0/actions/1` means the second action entry
in the first rule. Review the corresponding location in the protected source.
Names, conditions, endpoint URLs and action option values stay out of the report.
Inventory rows distinguish fields that are absent, null, or present with a
record count. Counts cover the supplied bytes. Review source-level configuration
and the export's scope when reconciling the estate inventory.

- Rules retain their enabled or disabled source state and trigger type. An
  action edge records the source's order, failure behavior and synchronous flag.
  If the definition is missing, invalid or ambiguous, the link stays blocked.
- A schedule at the start of one UTC hour, every day or on one numeric
  weekday, can produce a calendar fragment. Each source schedule
  gets its own row. Other calendar expressions and trigger types remain visible
  for review. [SFTPGo schedule semantics](https://docs.sftpgo.com/latest/eventmanager/)
- The planner marks fragments `needs_input`. Review all rule filters and
  action effects. Choose the destination source, exact workflow revision,
  effective dates, missed-run policy and execution bounds. Check for overlapping
  rows before using the ordinary [schedule preview and approval](scheduled-workflows.md).
- In `access_records`, follow the references from users and administrators to
  roles and groups, and from users and groups to virtual folders. Primary,
  secondary and membership-only groups stay distinct. A managed group for an
  administrator is its own dependency type. Missing and duplicate definitions
  leave blocked rows. Review effective access and mount boundaries before
  choosing new accounts and re-enrolling credentials.
- API-key rows distinguish user scope from administrator scope. A key tied
  to one account has an owner dependency. An unbound key that can apply
  across the whole source scope stays `unsupported` and needs explicit
  account mapping. For shares, review the owner, read/write scope, selected
  paths, expiry, passphrase and access limits in the protected export before
  issuing replacement access.

Stock export exercises cover disabled scheduled rules and their shared action,
a disabled user with a role, primary group and folder references, scoped
credentials, and a password-protected share. Effective permission and storage
translation, action conversion, and other triggers remain open. Complete
destination adoption needs isolated comparison of actual file selection,
schedules, byte outputs, failures and receipts, followed by reviewed cutover
and rollback.
