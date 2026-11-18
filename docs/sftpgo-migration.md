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

The native exercise covers a stock export, two disabled scheduled rules and
their shared action. Mapping partner permissions, storage, actions and other
triggers is still open. Complete destination adoption needs isolated comparison
of actual file selection, schedules, byte outputs, failures and receipts,
followed by reviewed cutover and rollback.
