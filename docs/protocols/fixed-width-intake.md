# Fixed-width record intake

The implementation contract is `freightctl-fixed-width-v1`: policy schema3,
kind `fixed_width`, with ordered named columns. Each column declares
`width_bytes` and `padding` (`none`, `space_left` or `space_right`). Widths count
UTF-8 bytes, not displayed characters. A character split by a field boundary is
invalid. Missing padding defaults to `none` during normalization; no trimming is
inferred from the column's type. CSV and JSON policies refuse these extra controls.

Every data record has exactly the sum of its column widths. There is no header.
LF and CRLF terminate records; an exact final record may end at EOF. Bare CR,
empty records, partial records, extra bytes and NUL or invalid UTF-8 cells refuse.
An empty file has zero records; an empty line is an invalid record.
Padding removes only ASCII spaces on the declared side before ordinary text,
integer, exact decimal and YYYY-MM-DD date validation. It never converts values
or changes bytes. Leading-zero identifiers, signs and decimal digits remain data.
An optional padded blank cell is empty; required cells cannot be empty.

The existing byte, row, record, cell and processing-time limits remain enforced.
The declared record plus its longest permitted terminator must fit the record
limit. Parsing retains one bounded record, checks the entire immutable size and
SHA256, and reports codes, positions and counts without raw names or values.

The distinct custody identity is `intake-fixed-width-v1:<policy hash>`. The engine
and success code are `freightctl-fixed-width-v1` and `valid_fixed_width`. Policy,
report and file format must agree in PostgreSQL. Required signature and scanner
controls remain cumulative; parsing does not publish bytes. A separate current,
exact release is required. Receiving or validating content grants no forwarding
or execution authority. Existing CSV/JSON identities and reports stay unchanged.

This contract is not qualification. Native SQL, API, CLI, browser, stock-client,
signature/scanner, recheck/copy and final-source evidence must be recorded before
claims. Local inference and heavy runtimes remain off.

The existing native structured-intake workflow now prepares fixed-width cases
beside its original JSON cases. They cover held exact release, cross-format SQL
refusal, recheck and received-copy provenance, ordinary HTTPS and resumable CLI,
independent GnuPG with clean/unavailable/blocked scanner-protocol fixtures, and
Chrome policy review/original-key recovery/five accessibility states. The scanner
fixture is not malware detection. Go independently checks the browser's policy,
custody cardinality and bytes. These cases are compiled locally; actual native
execution and final-source proof remain owed. F148 retains the item evidence.
