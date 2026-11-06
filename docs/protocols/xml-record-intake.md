# XML record intake

`freightctl-xml-records-v1` is the schema4,`xml_records` intake contract. The
`xml` policy object declares `root`,`record` and `namespace`. Root,record and
column names use ASCII XML local names. Namespace is empty or an explicit
bounded ASCII absolute URI;reserved XML/XMLNS namespaces are excluded. The URI
is a comparison string and is never fetched.

One root contains zero or more record elements. Each record contains at most
one scalar element for each declared column,in any order. Unknown/duplicate
fields,nested values,missing required fields and empty required values refuse.
Optional missing/empty fields are permitted. Text,integer,decimal and date rules
operate on XML-decoded text without numeric coercion or implicit trimming.
XML character references and newline normalization retain their standard XML
meaning;the original immutable bytes are never rewritten.

An empty namespace uses unprefixed elements with no namespace declaration,or
an explicit empty default declaration. A nonempty namespace requires exactly
one declaration on the root:default or one named prefix. All elements use that
same prefix choice. Declarations on records/fields,extra attributes,unbound or
changed prefixes and namespace changes refuse. This deliberately small profile
does not claim every valid XML document or a general XSD validator.

Input is UTF-8 XML1.0,with an optional BOM and declaration. A declaration must
be first,contain version1.0,and may name UTF-8 and standalone yes/no in XML order.
Pseudo-attributes need real XML whitespace separators;adjacent attributes refuse.
Comments and CDATA are inert bounded data. DTDs,entity declarations,external
entities,all other processing instructions,attributes,includes and nested
documents are refused. No stylesheet,schema,URL,file or instruction is executed.
XML signatures are not inferred from document content;ordinary detached
signature policy binds the complete accepted byte revision.

Existing file,row,record,cell and time bounds apply before token growth. Root
framing and each record span,including intervening whitespace/comments,are
bounded. Depth is at most three. Success requires one complete root,EOF and
the accepted whole-file length/SHA256. Reports contain identities,counters,
positions and fixed codes,never raw element names,values or parser errors.

Custody identity `intake-xml-records-v1:<hash>`,engine
`freightctl-xml-records-v1` and success `valid_xml_records` must agree with the
actual policy. Existing signature/scanner checks remain cumulative;checks do
not publish bytes. Separate exact release and current permissions remain
required. Receiving/validating grants no forwarding or execution authority.

This is an implementation contract,not qualification. Native PG/API/CLI/UI,
GnuPG/scanner,stock-produced XML,recheck/copy and final-source evidence remain
owed. The general processing parity row and full GOAL remain open.

The native structured-intake profile prepares original CSV/JSON/fixed cases
beside XML cross-format SQL,held release/recheck/received-copy,ordinary HTTPS,
resumable CLI,and sandboxed Chrome review/hash/original-key/held/release cases.
Python ElementTree prepares exact synthetic XML and records its producer version;
GnuPG signs those same bytes. Scanner clean/offline/blocked cases use the existing
protocol stand-in and make no malware-detection claim. Five Chrome accessibility
states and independent Go policy/cardinality/byte observations remain required.
Only focused local parsing/contracts and static compilation have run;actual
native and final-source outcomes are owed in F151.

References:[XML1.0](https://www.w3.org/TR/xml/) and
[Go XML decoder](https://pkg.go.dev/encoding/xml). The implementation uses the
repository-pinned Go toolchain,with no custom entity or charset resolver.
