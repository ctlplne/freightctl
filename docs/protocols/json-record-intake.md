# Bounded JSON record intake

`freightctl-json-records-v1` checks a complete UTF-8 JSON array of flat objects.
Select policy schema2,kind `json_records`,with the existing typed column rules.
It does not claim general JSON Schema,nested-document or transformation support.
Policy schema1/CSV remains unchanged. A declared field name is case-sensitive;
escaped spellings of the same name are still duplicates. No field,URL,reference
or string can request a file,network contact,model or execution.

Each object uses only declared fields. Required fields must exist and contain
a valid nonempty scalar;optional fields may be missing or null. Text and date
columns require strings. Integer and decimal columns require JSON numbers,
without coercing numeric strings or exponent notation. Existing exact decimal
precision/scale and calendar-date rules apply. Unknown/duplicate fields,nested
values,invalid UTF-8/unpaired surrogate escapes,trailing values and incomplete
arrays fail. Empty arrays have zero data rows;the columns live in the policy.

Existing byte,row,record,column and processing-time allowances remain. Bound
the decoder's reads before allocating a whole record;record/framing spans,
including inter-record whitespace,cannot grow without that bound. Keep only
one bounded object at a time. A pass consumes the complete document and matches
the immutable accepted size and SHA256. Reports contain engine,source/policy
identity,counters,positions and codes;never raw property names,values or errors.

This format goes through the same current policy,immutable revision,signature,
scanner,attempt/lease,idempotency and separately authorized release workflow.
A successful parser answer alone never releases a file. PostgreSQL must bind
the exact report engine/success code to the actual active policy format;CSV and
JSON reports cannot substitute for each other. Receiving/checking an instruction
does not grant forwarding or execution authority. Inference stays off.

Focused pure parser checks are local evidence only. Real PostgreSQL/SQL-forgery,
custody/CLI/API/browser,signature/scanner/refusal/recheck/release,independent byte
and current final-source outcomes remain owed in their authorized environments.

The dedicated `Native JSON intake and custody interfaces` GitHub workflow runs
actual Linux ARM/x86 PostgreSQL/API/custody cases and the original CLI journey
extended with JSON. Independent GnuPG signs the JSON fixture; the scanner-protocol
stand-in establishes protocol behavior only. A separate native x86 Chrome job
reviews the Go-normalized policy hash, discards one actual committed response,
retries its original key, uploads through the ordinary resumable UI and proves
that checks still need a separately reviewed release. Its Go observer verifies
stored policy, exact received bytes and policy/acceptance/release cardinality.
The browser runs five accessibility audits with its sandbox enabled. No native
pass is implied by this workflow configuration; F145 tracks what remains owed.
