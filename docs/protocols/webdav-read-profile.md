# DAV namespace read and conditional-mutation profile

This is a partial read/conditional-mutation adapter, not a claim of RFC4918 class1,2 or3 compliance.
The full C-WEBDAV contract remains open: collection/overwrite mutations,properties,locks,outbound server
connections and independent DAV application interoperability still need work.

Use the existing HTTPS listener and an enrolled bearer credential:
`/v1/tenants/{tenant}/partners/{partner}/dav/` followed by an encoded virtual
path. The profile does not accept browser cookies or Basic authentication.
Credentials belong in a protected header file,never in URLs or shell arguments.
The prefix selects a tenant and partner; the ordinary PostgreSQL/RLS identity,
mount root,path modes and current intake policy decide what can be discovered
or read. A URL never refers to a host filesystem path.

- `OPTIONS` authenticates and checks read/list access to the addressed entry.
  It returns `Allow: OPTIONS, PROPFIND, GET, HEAD, PUT, MKCOL, PROPPATCH, MOVE, DELETE, COPY`
  and no DAV compliance class. Refused collection mutation responses omit
  the file-only MOVE, DELETE and COPY operations from their Allow field.
- `PROPFIND` supports explicit Depth0 or1. Missing Depth means infinity and is
  refused with403 and `DAV:propfind-finite-depth`. Other depth values are400.
  The complete collection is limited to1000 immediate children; larger scopes
  fail507 without returning a truncated207 listing. This is a live request
  processing bound,not a GitHub build or binary-size gate.
- Empty property bodies mean allprop. UTF8 `application/xml` and `text/xml`
  support allprop,propname,named prop,and allprop/include. Requests are limited
  to16KiB,32 distinct property names and256 tokens. The parser rejects DTDs,
  entities,duplicate selectors,nested property values and execution directives.
  This finite grammar is narrower than the full DAV extension model.
- Responses are207 XML with namespace-preserving propstat groups:200 for
  available properties and404 for unknown or unavailable requested properties.
  All entries expose displayname and resourcetype. Collections also expose
  getlastmodified; files expose getcontentlength,getcontenttype and getetag.
  File timestamps are not invented where the immutable HTTP reader provides
  no Last-Modified header. Names are XML escaped; href segments are URL encoded.
- Discovery requires read/list rights and checks each child's path mode and
  current file availability. Unreadable or held children are omitted. A shared
  namespace lock prevents a rename or replacement halfway through that answer.
- `GET` and `HEAD` open the ordinary verified immutable revision reader.
  ETags match the existing API's file revision and SHA256. Ranges and HTTP
  conditionals run only after authorization and storage integrity checks;
  bounded reads recheck current authority. Replies retain no-store. A previous
  listing or validator cannot rescue a revoked credential or held file.
- `PUT` creates an absent file using ordinary write authority. It requires
  `If-None-Match: *`,a known Content-Length,an original Idempotency-Key and the
  whole X-Content-SHA256. Missing conditions return428;ambiguous/unsupported
  conditions return400 and unknown lengths return411. The ordinary namespace
  transaction checks absence under its publication lock,before staging bytes or
  recovering a prior command. An existing entry returns412,including a retry
  after successful publication. It is never overwritten. The caller can read
  the current authorized revision to resolve a lost response;412 alone does not
  prove which command created that revision.
- Fresh integrity-only publication returns201 with its exact revision ETag.
  Controlled intake returns202 and its durable held receipt,without an ETag or
  namespace publication. An absent-path retry can recover the original receipt
  with200 and no assertion of current namespace state. Passing checks still
  does not publish:the ordinary separately authorized exact release is required.
  Default-false conditional fields are omitted from historical upload request
  meanings,so existing ordinary upload retries retain their original hashes.
- Conditional file replacement uses one exact strong `If-Match` instead of
  `If-None-Match`. Length,digest and original-key requirements stay the same.
  The ordinary write/read permissions,current path modes,intake availability,
  immutable file ID and digest are checked before staging,under the publication
  lock. A missing or changed current file returns412,including a retry after
  successful replacement. Equal bytes under another custody ID do not match.
  A fresh integrity-only replacement returns200 with `replaced-at-commit` and
  the new revision ETag. Read that authorized revision to resolve a lost reply;
  a precondition failure alone proves no earlier command's outcome.
  The old file's custody bytes and history remain intact. Controlled replacements
  return202 without an ETag and keep the old mapping until separate checked
  release. Pending publication binds both the old file ID and namespace revision,
  so deleting/recreating a path at the same revision cannot satisfy it. Original
  held receipt recovery returns200 with no claim of current publication. The
  optional typed namespace `expected_file_id` guard applies only to replacement
  publication with an explicit expected mapping revision and read/write authority.
  Other protocol upload and command meanings stay unchanged when it is absent.
- `MKCOL` creates one empty collection with an original Idempotency-Key and
  zero body bytes. It uses the same namespace transaction,write permission,
  parent mode,immutable PathCreated event and command receipt as ordinary mkdir.
  Existing paths return405,or412 when If-None-Match:* is supplied. Missing parents
  return409;it never creates intermediate folders. Unsupported bodies return415.
  A fresh201 returns the exact encoded collection Location. If the collection
  was later removed,an original-key200 recovers history without recreating it or
  asserting a current Location. Other conditions are explicitly refused.
- `MOVE` handles one file with an explicit destination decision. It requires
  an original key,the exact strong source If-Match tag,Overwrite:F or T and zero body.
  Destination may be an absolute HTTPS URI with the current authority or an
  absolute URI path;it must name a canonical file in this tenant/partner's DAV
  namespace. Other hosts/scopes,queries,fragments,traversal and control paths
  are refused. No network contact is made to a Destination header.
  The ordinary manage_paths/read authority,path modes,current intake and source
  file ID/SHA256 are checked under the rename lock. File ID is included in the
  existing typed command meaning,so a changed file cannot reuse the old key.
  Fresh201 acknowledges a mapping change with Location;bytes and custody ID do
  not change. GET verifies the resulting revision separately. A stale source or
  occupied destination with Overwrite:F returns412,missing parents409,and directory moves405.
  After a lost reply,the caller must inspect the authorized destination;412 alone
  does not establish which command performed an earlier move. Same-key history
  never authorizes another effect. Directory MOVE remains owed.
  `Overwrite:F` keeps its non-overwrite412 behavior. Explicit `Overwrite:T`
  can replace a file only when its actual destination mode permits writing and
  its current intake remains available. Capture its mapping revision under the
  same lock,then commit target PathRemoved,source PathMoved and one command
  receipt atomically. The old target's immutable custody and separately
  authorized history survive. Fresh overwrite returns204 with no body,Location
  or byte validator;X-Freightctl-Namespace-State is replaced-at-commit and
  X-Freightctl-Event-ID names the move event. This matches the overwrite success
  status in [RFC4918 section9.9.4](https://www.rfc-editor.org/rfc/rfc4918.html#section-9.9.4).
  An absent target still returns201 with Location. A saved receipt never moves
  a restored source or recreates a removed target again. Changed overwrite
  decisions or captured target revisions cannot reuse an old command key.
  Receiving a source file does not grant destination overwrite authority.
- `DELETE` currently removes one file mapping with an exact strong If-Match,
  the original Idempotency-Key and an empty body. Ordinary read/manage_paths,
  parent modes,current intake and immutable file ID/hash are checked under the
  same namespace transaction as its PathRemoved event and command receipt.
  A fresh204 includes X-Freightctl-Event-ID and namespace-state removed-at-commit;
  it carries no byte validator or body. GET/HEAD/PROPFIND then return404 for that
  mapping. Immutable custody bytes and history remain,accessible only through
  independently authorized references. Path removal grants no forwarding or
  execution authority. Absent/stale source conditions return412;an equal-content
  new revision cannot reuse the old command key. Recovering a historical command
  for a restored original file returns200 with not-asserted-original-receipt and
  does not remove the restored mapping again. Directory deletion returns405;
  it never silently substitutes empty-only or partial deletion for the recursive
  semantics in [RFC4918 section9.6](https://www.rfc-editor.org/rfc/inline-errata/rfc4918.html#s-9.6).
  Depth may be absent or infinity;other values,unsupported conditions,bodies,
  Destination and Overwrite headers are refused.
- `COPY` publishes one file into this same scope with an explicit destination
  decision. It requires an original key,exact strong source If-Match,Overwrite:F or T
  and an empty body. Destination uses the same confined URI rules as MOVE.
  Current source read and destination write authority are both required;
  read-only access or manage_paths alone does not grant copying. Verify the
  exact custody bytes before the ordinary atomic PathPublished event/receipt.
  The new mapping has its own ID,current actor ownership and ordinary0640 mode;
  it references the same immutable custody file. Replacing or removing either
  mapping does not change the other. No new artifact acceptance,external transfer
  or execution is implied. With Overwrite:F,existing targets return412 even for the original key.
  Fresh201 names Location;read the authorized target separately for its bytes.
  For an originally absent target later removed,200 can recover only its historical receipt
  without recreating it. Changed source revisions cannot reuse the old key.
  Missing parents return409;collection copy remains405 and unqualified.
  The ordinary namespace API/CLI accepts the same typed copy command with source
  path,target,file_id and expected source mapping revision. It requires the same
  read/write,protected custody verification and namespace capacity checks.
  `Overwrite:T` additionally requires manage_paths,actual destination write
  mode and current destination intake availability. It removes the old mapping
  and publishes a separate new mapping in the same transaction as one receipt.
  Both immutable custody records survive. Source mapping and bytes stay the same.
  Fresh replacement returns204 with an empty body,exact publication event ID and
  replaced-at-commit namespace state. It carries no Location or byte validator.
  See [RFC4918 section9.8.5](https://www.rfc-editor.org/rfc/rfc4918.html#section-9.8.5).
  Capture the target revision under the namespace lock;the typed API/CLI uses
  replace:true with target_revision for an existing destination. Replacing a
  mapping at the configured entry limit consumes no additional live entry;an
  exceeded limit returns507 and rolls removal back. Failed source verification
  also leaves the target intact. A historical200 names only the original receipt,
  and a changed overwrite decision or target revision cannot reuse its key.
  The shared namespace API/CLI also refuses a copy whose canonical source and
  destination are the same. Neither create nor replace may recreate its own
  source mapping;the store independently enforces that boundary.
- `PROPPATCH` changes inert user properties on a file or collection. Discover
  the live `urn:freightctl:namespace` properties `entry-id` and `revision` with
  PROPFIND,then send their exact `UUID:positive-revision` pair as
  `X-Freightctl-Namespace-Revision`,the original Idempotency-Key and UTF8 XML.
  This partial profile uses an explicit namespace condition. A byte ETag cannot
  detect a concurrent metadata edit or a removed/recreated directory;ordinary
  If-Match and DAV lock conditions are refused rather than silently ignored.
  Missing namespace conditions return428,malformed conditions400,and stale or
  replaced resources412. Synthetic root properties are not mutable.
  The request supports ordered DAV set/remove operations. Nested/mixed XML,
  namespace prefixes (including QName text),xml:lang/space and effective xml:base
  survive as data. DTDs,entities,processing instructions inside values,unbound
  prefixes,duplicate attributes and extra wrapper controls are refused. No URI
  is fetched. The whole request is at most16KiB,32 changes,512 tokens and12 value
  levels;expanded typed intents and final snapshots are at most32KiB with32
  stored names. These are request-processing bounds,not GitHub build ceilings.
  Protected DAV and urn:freightctl namespaces return403 and change nothing.
  Remove of an absent name succeeds;repeated names execute in document order.
  Current read/write/manage_paths rights,actual path read/write modes (plus
  collection traversal),resource identity and file availability are required
  under the namespace lock,including before recovering an original receipt.
  The same typed namespace API and CLI use operation:properties,
  expected_entry_id,expected_revision and ordered property_changes objects
  containing operation:set/remove and standalone property_xml strings. Optional
  fields are omitted from historical commands so their request hashes stay the
  same. Prefix spelling and XML text are part of the explicit retry meaning;
  semantically equivalent reserialization is not promised to share a key.
  Commit one PathAttrsChanged event,one namespace revision and one actor-private
  command receipt in one PostgreSQL transaction. Source schema63 adds only a
  column and supplementary guard;the original transition guard and forced RLS
  policies remain. Unjournaled or mismatched property edits are refused.
  Fresh207 names each successful property and returns the committed namespace
  revision/event headers,without a byte ETag. Original-key200 returns only its
  historical JSON receipt and never re-applies values or asserts current state.
  Changed request meanings cannot reuse a key. Stat/list/command receipts and
  model context omit values;ordinary audit feeds and signed snapshots replace
  content-bearing event payloads with their source hash. Receiving a property
  grants no forwarding,approval or execution authority.
  Authorized allprop,named prop and propname discovery include stored values or
  names as requested. COPY clones a private snapshot into the distinct new
  mapping;MOVE retains the snapshot and DELETE retains its tombstone history.
  Normal file replacement retains mapping properties. XML responses have
  no-store,nosniff and a restrictive CSP sandbox. The complete response is
  bounded to8MiB while being built;overflow returns507 before207 headers.
  Native API/CLI/stock-curl PostgreSQL and TLS outcomes remain owed for this
  extension;local parser/static checks do not establish RFC4918 compliance.
- Other mutating DAV methods return405 after authenticating the credential.
  Discovery and unknown properties grant no forwarding or execution authority.
  Requests with traversal,encoded separators,control names,noncanonical Unicode
  or query selectors fail before router path cleaning can redirect them.

The prepared native ARM/x86 profile uses real PostgreSQL and stock curl over
verified TLS. It parses discovery XML independently,interrupts an actual file
response,then reconstructs the exact revision using a range and its ETag. The
API profile also tests empty directory creation,permissions,missing parents and
non-recreating historical receipts,concurrent non-overwriting create transactions,original
receipt recovery,held acceptance and separate release,modes,tenant/partner refusal,credential
revocation,unknown properties and zero delivery/workflow effects. The initial read-only profile passed both native architectures at
`03cd5fd0e46e60d0417b40122e94fd31a2920c35`;
[F358](../qualification/evidence/F358-dav-native-read.json) binds the exact jobs,
client hashes and independent comparisons. F368 binds subsequent conditional PUT and MKCOL qualification on both
architectures at`d960c40fe1d4d7facf11862c331b52fc93dcc0b6`. Later file MOVE
source still needs its original native runtime proof.
The extended stock profile also creates an empty collection through MKCOL,
creates its child through PUT,moves that exact file without overwrite,observes
conflict/stale-source refusals and independently
compares readback. Stock curl proves the declared HTTP methods; it does not qualify a desktop DAV
mount,locking client or independent upstream DAV server.

Protocol references: [RFC4918](https://www.rfc-editor.org/rfc/rfc4918.html),
[HTTP conditions](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.2) and
[428 Precondition Required](https://www.rfc-editor.org/rfc/rfc6585.html#section-3).
