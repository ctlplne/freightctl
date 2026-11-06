# Deterministic record projection core

This is an implemented internal processing primitive. It is not yet an advertised
workflow task or application API/CLI/browser/MCP operation. Workflow authority,
approved intents,leases/fencing,quota reservations,immutable output lineage,
receipts,recovery and fresh output checks/release must be integrated and qualified.
Neither a valid row nor a completed projection grants execution or forwarding.

## One parsing path

`checks.StreamRecords` uses the same five validators as ordinary held intake:
CSV,flat JSON,fixed-width,scalar XML and the explicit XLSX table profile. The
normalized source contract determines field order,types,padding,namespace and
spreadsheet/date interpretation. A transformation does not have a looser parser.

Every record has a logical ordinal and independently owned cells. Missing,null
and present values are distinct;present empty text is not null. JSON missing
properties and nulls remain distinct. XML missing and empty elements remain
distinct. XLSX missing cells,blank cells and explicit empty strings remain
distinct. CSV/fixed-width empty fields stay present values. Numeric/date scalar
meaning follows the approved source contract without floating point conversion.
Row order and duplicates remain intact;no implicit sorting/filtering/deduplication.

Record values are transient content and are excluded from automatic JSON metadata
serialization. Reports contain fixed codes,positions,counts,identities and hashes.
Trusted consumers may retain their own row copy without changing parser state.
Consumer errors have a fixed outer message;underlying contents are not printed.

Validated prefix rows can arrive before a later error or complete-source digest
failure. Callbacks must only write private staging. The complete report and
current domain authority remain mandatory before any output can be accepted.

## Reviewed definition

`RecordProjection` schema1/kind`record_projection` binds engine
`freightctl-record-projection-v1`,the exact normalized source-policy hash,ordered
source/target column mappings,output kind and processing budgets. Lookup is exact,
case-sensitive and never fuzzy. Unknown sources,duplicate targets,unknown engine,
executable expressions and unsupported operations refuse before writing.

Conversions are explicit: `identity`,`text` and `normalize_lf`. The latter applies
only to text and changes CRLF/bare CR to LF. Independent `missing`,`null` and
`empty` rules default to `preserve`;explicit alternatives choose empty,null,
missing or error where meaningful. Each rule runs once on the ORIGINAL state,
not recursively on its own result. Each rule,field order,engine and budget is in
the definition hash. Normalization clones mapping storage.

JSON output preserves missing properties,nulls and empty text by default. Typed
numbers are serialized without floating point:required JSON numeric syntax
removes a leading plus/excess integer zeros while retaining exact value,sign and
fractional digits. Text identifiers retain their leading zeros. A numeric empty
value requires an explicit null/missing/error rule;it cannot silently become0.

CSV output uses UTF-8 and LF record separators with ordinary structural quoting.
CSV cannot represent missing/null separately from empty fields;such input refuses
unless the operator explicitly chooses a conversion. CRLF scalar text also needs
an explicit newline conversion because ordinary readers normalize it. No rule
silently changes bytes or drops records to fit the output.

Formula-like text/header prefixes,including whitespace/control/format prefixes,
apostrophe hiding and full-width initiating characters,refuse CSV output.
Structural quoting alone does not establish formula safety. Validated numeric
constants remain numeric. The core does not add an escape that changes the value
or offer an unsafe formula bypass. Choose JSON or another qualified output profile
when CSV cannot preserve the required meaning. Generic spreadsheet import guesses
and later rewrites are not a typed receiver contract;no universal Excel claim.

## Private output and failure

Source and projection timeouts,source parser limits and independent output byte,
record-byte and row limits apply. Output rows must remain one-for-one with source
rows. Exceeding a limit refuses the entire result;it never truncates a scalar or
returns a shortened successful dataset. These are product processing controls,
not arbitrary GitHub build or scan ceilings.

`ProjectRecords` returns a non-nil error for EVERY incomplete/rejected output.
The successful digest is set only after complete input validation,matching counts
and successful output closure. Output I/O errors have fixed non-sensitive codes.
Inside existing `Disk.StageGenerated`,an error removes only the new partial file;
complete output is synced,sealed read-only and verified by actual byte readback.
The focused local filesystem proof does not qualify PostgreSQL quota/acceptance,
worker recovery or any application authority/approval path.

The output data-contract hash is not an intake/release policy. The domain caller
must bind the current approved output policy and require fresh signatures/scanning
and separate release. It cannot inherit the input's successful checks. Source
authority and mandatory source protections also remain the caller's obligations.

## Evidence boundary

Native ARM/x86 qualification prepares stock Python CSV/JSON/ElementTree/fixed
fixtures and actual pinned XlsxWriter bytes. Ten JSON/CSV outputs are checked by a
separate Python JSON/Decimal/CSV receiver for byte hashes,exact money and IDs,
dates,order and duplicates. Stock XLSX row-stream assertions also cover rich
strings,literal formula-looking strings,OOXML escapes and both explicit calendars.
Prepared jobs and local compilation do not establish these native passes.

The source handling follows [RFC8259](https://www.rfc-editor.org/rfc/rfc8259).
CSV refusal accounts for [OWASP's formula-injection guidance](https://community.owasp.org/attacks/CSV_Injection).
Full transformation breadth,XLSX/XML/fixed/EDI outputs,joins/arithmetic/general
schemas,application integration,original customer journeys and actual final-source
acceptance remain mandatory and open. No overall parity or product completion.
