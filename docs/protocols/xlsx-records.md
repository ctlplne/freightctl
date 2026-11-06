# Bounded spreadsheet record parsing

Schema5/`xlsx_records` is an explicit implemented intake profile,with engine
`freightctl-xlsx-records-v1` and immutable custody prefix `intake-xlsx-records-v1:`.
The ordinary register/check/release API and CLI,operator browser and artifact
metadata contracts share its normalized definition. Native application custody,
SQL,signature/scanner/recheck/copy and interface qualification remain owed.

Whole-source length/SHA256 verification precedes package parsing. Successful
reports retain the exact file ID,bytes,digest and policy hash. Required signatures
and scanner verdicts remain cumulative;parser success still requires a separate
current release approval. Existing intake kinds retain their hashes. Source50
adds only the fifth format's file/profile/report guards;retained35 is untouched.

`checks.ValidateXLSX` reads a supplied immutable `io.ReaderAt`;it cannot open a
host path,contact a destination,launch Excel,execute a formula or extract a part.
Its report contains only a fixed code,record count and row/column positions.
Receiving or validating a workbook grants no onward or execution authority.

## Package and resource meaning

`zipcontainer.Open` validates the ZIP32 directory before `archive/zip` allocates
its file index. The caller explicitly supplies compressed-file,central-directory,
part-count,part-size,total-expanded-size,expansion-ratio,name-length and path-depth
limits. These are product input-processing controls,not GitHub runner capacity
gates. Central and local headers,names,flags,sizes and descriptors must agree;
physical spans cannot overlap,leave gaps or hide a prefix/trailer. Only stored
and deflated regular parts are supported. Encrypted,multivolume,ZIP64,special
files,case aliases,duplicate names,URI escapes and unsafe/ambiguous paths refuse.
No nested archive is interpreted and no part is written to the filesystem.

Every part is read to EOF,including unselected parts. Actual expanded length and
CRC32 are checked even when the stored CRC is zero and a standard ZIP reader
would omit that comparison. CRC establishes ZIP member integrity only. The
custody adapter independently binds the complete file length and
cryptographic digest before any check or release claim.

The XML decoder has bounded tokens,depth and attribute count,with explicit
XML1.0/UTF-8 declaration validation. DTDs,entities beyond built-in XML references,
external resolvers and other processing instructions refuse. Known namespaces
and exact element paths supply meaning. Member and worksheet streams are not
loaded as whole documents. Shared strings have separate count and decoded-byte
budgets. Caller context cancellation terminates reads and parsing.

## Workbook and record meaning

The package relationship selects one nonmacro workbook. Exact content types and
internal relationships bind its worksheet,shared-string,style,theme and property
parts. Unknown/active parts,external relationships,formula caches,defined names,
embedded objects,hyperlinks,drawings and alternate-content extensions refuse.
These controls apply to unselected worksheets too. No target is fetched.

The operator names an exact sheet. Its first physical row contains ordered,
case-sensitive headers matching the approved columns. Rows and cell addresses
must increase without duplicate cells or missing row numbers. Missing optional
cells remain empty;missing required values refuse. Duplicate data rows remain
distinct records and no sorting,deduplication or display filtering occurs.

Text columns require real text cells;numeric cells with a `0000` display style
cannot recover a leading-zero identifier. Inline/shared/rich strings preserve
their text. OOXML `_xHHHH_` escapes decode once within each individual text node;
escaped underscores remain literal and UTF-16 surrogate pairs must be valid.
Mixed plain/rich alternatives and repeated text alternatives refuse. Formula-like
literal text stays inert. Generated-export formula escaping is separate work.

Integer and decimal columns require numeric cells. Decimal exponents expand with
bounded string arithmetic;no binary floating point round-trip occurs. Approved
precision,scale and byte limits still apply. Styling is not a conversion rule.

Dates require an explicit `iso_text`,`serial_1900` or `serial_1904` contract. ISO
dates require exact calendar dates in text/date cells. Numeric serial modes must
match the workbook's declared date system;fractions/negative serials refuse.
1900 serial0 and fictitious February29/serial60 refuse;1904 serial0 is January1.
No locale,timezone,display format or time-of-day meaning is guessed.

This profile does not establish every Excel/ODS/legacy-XLS feature,arbitrary
formulas,XSD/general schema or deterministic transformation breadth. Required
spreadsheet/product parity remains open. Native stock-producer parser proof and application
custody and actual final-source customer outcomes are separately owed.

## Sources and qualification

The package interpretation follows [ECMA-376](https://ecma-international.org/publications-and-standards/standards/ecma-376/),
[Microsoft's SpreadsheetML structure](https://learn.microsoft.com/en-us/office/open-xml/spreadsheet/structure-of-a-spreadsheetml-document),
[shared-string structure](https://learn.microsoft.com/en-us/office/open-xml/spreadsheet/working-with-the-shared-string-table)
and [PKWARE APPNOTE6.3.10](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT).
The implementation uses the repository-pinned Go1.26.10 decoder and ZIP reader.

GitHub's document-container workflow prepares stock Python ZIP inputs and pinned
[XlsxWriter3.3.1](https://pypi.org/project/xlsxwriter/3.3.1/) workbooks on native
ARM/x86. The producer is qualification-only,hash pinned and checked against PyPI
and OSV with its full dependency closure before use. A prepared workflow or local
tagged compilation is not an observed native result. Excel itself,licensed peers,
independent business adoption and enterprise readiness remain unqualified.


## Typed policy review

The `xlsx` object binds an exact `sheet`,explicit `date_mode` and these processing
budgets: `max_parts`,`max_directory_bytes`,`max_part_bytes`,
`max_expanded_bytes`,`max_expansion_ratio`,`max_shared_strings`,`max_shared_bytes`.
All values appear in the browser review and definition hash;protected signer and
scanner references survive format changes. Unknown format controls cannot migrate
into another kind. Per-part/shared bytes must fit the total expanded budget.
Shared text budgets measure decoded text;record/token limits also bound transient
parsing. Operational ceilings protect worker pools;they do not impose CI build or
scan capacity limits. General Excel/XLS/ODS and transform breadth remain required.

Native parser-only proof at source1b89447 is recorded in F156. Its actual Python
ZIP and XlsxWriter13-input ARM/x86 passes do not qualify the later governed-intake
adapter or ordinary application custody. The intake workflow prepares actual
stock-produced bytes for native SQL/API/CLI/Chrome/signature/scanner-protocol/
recheck/received-copy proof. Those results,including five browser accessibility
states and original-key recovery,remain owed until executed at the final source.
