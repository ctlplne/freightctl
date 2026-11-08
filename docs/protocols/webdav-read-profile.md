# DAV namespace read and conditional-mutation profile

This is a partial read/conditional-mutation adapter, not a claim of RFC4918 class1,2 or3 compliance.
The full C-WEBDAV contract remains open: locks,outbound server
connections and independent DAV application interoperability still need work. Implemented
read,property,MOVE,DELETE and COPY profiles also require actual final-source qualification.

Use the existing HTTPS listener and an enrolled bearer credential:
`/v1/tenants/{tenant}/partners/{partner}/dav/` followed by an encoded virtual
path. The profile does not accept browser cookies or Basic authentication.
Credentials belong in a protected header file,never in URLs or shell arguments.
The prefix selects a tenant and partner; the ordinary PostgreSQL/RLS identity,
mount root,path modes and current intake policy decide what can be discovered
or read. A URL never refers to a host filesystem path.

`X-Freightctl-Namespace-Revision` applies only to PROPPATCH and collection MOVE/DELETE/COPY.
PUT,MKCOL,file MOVE/COPY and file DELETE reject that header with400 instead of silently
ignoring it. Use their byte/absence conditions below. A refused namespace
condition is not an evaluated metadata revision or a successful transfer.

The namespace and upload-create CLI command files use the same typed JSON
object parser as their API requests. Keep each file within the existing16KiB
limit and give every field one exact spelling. Duplicate keys,case aliases,
Unicode spellings that Go folds into ASCII fields,invalid UTF8,trailing data
and whole-body null are refused. One extra byte is read to detect an oversized
stream instead of accepting its truncated prefix. Valid Unicode values and
explicit zero-valued options keep their original meanings. Parsing a file does
not grant permissions or make a reviewed state current;ordinary transaction,
revision,mode,intake and idempotency checks still run before execution.

- `OPTIONS` authenticates and checks read/list access to the addressed entry.
  It returns `Allow: OPTIONS, PROPFIND, GET, HEAD, PUT, MKCOL, PROPPATCH, MOVE, DELETE, COPY`
  and no DAV compliance class. Byte-conditioned file methods on directories
  return405 and advertise the separate namespace-conditioned collection
  MOVE/DELETE/COPY profiles below;this is not permission to skip their guards.
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
  never authorizes another effect. The collection profile below is separate.
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
- Collection `MOVE` addresses the canonical collection href with a trailing
  slash. Supply X-Freightctl-Namespace-Revision from authorized discovery,
  an original Idempotency-Key,Overwrite:F,and a same-authority collection
  Destination ending in a slash. It accepts absent Depth or Depth:infinity
  only;finite depths are400 and no prefix is moved. This follows the complete
  collection scope in [RFC4918 section9.9.2](https://www.rfc-editor.org/rfc/rfc4918.html#section-9.9.2).
  Overwrite:T uses the separate destination identity condition below;missing
  destination conditions return428. Replacement always removes the complete
  authorized destination tree;it never substitutes empty-only removal.
  The typed namespace API/CLI uses operation:move_tree,path,target,
  expected_entry_id and expected_revision. Replacement additionally uses the
  exact target_entry_id/target_revision pair and replace:true below.
  Require read,list and manage_paths,actual root/member read/traversal modes,
  current file availability and writable source/destination parents. An alias
  cannot rescue a private member. The root condition identifies the collection;
  it is not a preview digest of all descendants. Under the exclusive namespace
  lock,check the complete current tree before changing any member. Keep the
  existing1000-member processing bound;overflow returns507 without moving a
  prefix. A private member,unavailable release,occupied target or missing parent
  rolls everything back. Missing/changed source identity or revision returns412,
  occupied target412 and missing destination parent409. Self/descendant/control
  targets are forbidden. No Destination URI is contacted;even an empty literal
  fragment is refused. An encoded%23 remains a literal filename character.
  Move every mapping in one transaction,retain IDs,owners,modes,modified times,
  file custody and property snapshots,and commit each exact PathMoved event
  with one actor-private command receipt. Recheck file access/availability after
  the move and authority before commit. Fresh201 names the complete new
  collection Location and collection-moved-at-commit,with no byte ETag. A missing
  original source fails412;inspect the authorized destination after a lost
  response. If the same collection was restored,original-key200 can recover
  only its historical receipt without moving it again or asserting a current
  Location. Another actor cannot recover that receipt,and changed request
  meanings cannot reuse its key. Namespace movement grants no external
  delivery,forwarding or execution authority. Prepared native API/CLI/stock-curl
  proofs include nested members,properties,independent bytes,denied private and
  no-longer-released members,unchanged quotas,oversized retained-state refusal,
  ABA identity,replay and exact no-extra-effect counts;runtime outcomes remain
  owed for the new source. Locks and outbound
  DAV server interoperability remain open.
- File `DELETE` removes one mapping with an exact strong If-Match,
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
  does not remove the restored mapping again. Applying this byte-conditioned
  file profile to a directory returns405;use its separate namespace condition
  and collection href with a trailing slash below.
  Depth may be absent or infinity;other values,unsupported conditions,bodies,
  Destination and Overwrite headers are refused.
- Collection `DELETE` uses a trailing-slash href,an original Idempotency-Key,
  an empty body and `X-Freightctl-Namespace-Revision: entry-UUID:revision`.
  Depth is absent or infinity;finite depth,byte/DAV conditions,Destination,
  Overwrite and ambiguous headers are refused. It removes the complete current
  subtree,as required by [RFC4918 section9.6.1](https://www.rfc-editor.org/rfc/rfc4918.html#section-9.6.1).
  The root condition identifies the collection mapping;it is not a frozen hash
  of the child inventory. Under the exclusive namespace lock,enumerate every
  current member before any write. Require read,list and manage_paths,root
  parent write/traverse,each directory read/write/traverse and each actual
  file-path read mode plus current policy availability. An outside readable
  alias cannot authorize a private child. Refuse root/control paths,wrong kind,
  stale/different root identity/revision,hidden/unavailable children and trees
  exceeding the existing1000-entry operation bound. Failure rolls back the
  whole tree,including every event and receipt;no partial success is reported.
  Fresh204 has no body,ETag or Location;it names collection-removed-at-commit,
  the exact root removal event and X-Freightctl-Removed-Entries including the
  root. Every mapping is an irreversible tombstone with its old custody,owner,
  mode,modified time and inert property snapshot retained;its revision advances
  once. Commit the leaf-first PathRemoved events and one actor-private command
  receipt in the same transaction. Recheck current file availability and
  authority before commit. GET/HEAD/PROPFIND on all removed names return404;
  immutable custody remains available only through independently authorized
  references. This grants no forwarding,execution or new retained-byte access.
  Absent/replaced root retries return412,including after a lost response;
  inspect current authorized state rather than interpreting412 as proof of
  which command removed the collection. Another identity cannot reuse its
  receipt,and a changed request meaning conflicts409. Wrong kind/current policy
  fails409,permission403,and an excessive tree507. Native API/CLI/stock-curl
  whole-tree,refusal,tombstone,custody and retry outcomes remain owed until run.
  To recover the original private commit after losing that204,use the ordinary
  read-only namespace receipt endpoint/CLI with the exact original remove_tree
  command and key. It reads historical evidence without needing the removed
  source,opening custody or issuing DELETE again. Current read/list/manage_paths
  and the unchanged original mount/authority meaning remain required. Its
  original-commit-not-current-state observation never asserts current absence,
  bytes or delivery;see [the receipt contract](../api/namespace-receipts.openapi.json).
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
  Missing parents return409;applying this byte-conditioned file profile to a
  directory returns405. Use its namespace-conditioned collection href below.
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
- Collection `COPY` uses the trailing-slash href,original Idempotency-Key,
  exact root `X-Freightctl-Namespace-Revision`,Overwrite:F,empty body and a
  same-scope/same-HTTPS-authority collection Destination. No URI is contacted.
  Depth0 copies only the collection and its inert properties;absent Depth or
  infinity copies every current member. Depth1 and ambiguous headers are400.
  See [RFC4918 sections9.8.2–3](https://www.rfc-editor.org/rfc/rfc4918.html#section-9.8.2).
  The typed API/CLI uses copy_dir for depth0 and copy_tree for full depth,with
  path,target,expected_entry_id and expected_revision. Both require read,list
  and write;manage_paths grants no substitute for reading or writing. The
  root condition identifies the current source mapping,not a frozen hash of
  its earlier descendants. Under the exclusive namespace lock,require actual
  source path/ancestor modes and current policy for each copied member,plus
  destination-parent write/traverse. An outside alias cannot authorize a
  hidden member. Depth0 does not read,copy or disclose children. Reject root,
  control,self,descendant and noncanonical targets. Overwrite:F requires an
  absent target;explicit T uses the separate identity-bound profile below.
  Preserve the existing1000-member operation and live
  namespace quota;failure rolls back all mappings,events and receipts.
  Verify each distinct immutable file against its actual protected storage,
  size and SHA256 before publishing any mapping,then repeat the current store
  preflight. New mappings have new IDs,the acting owner's ordinary0750/0640
  directory/file modes and the copy's modified time. Their independent property
  snapshots preserve inert XML;files reference the same exact immutable custody.
  Keep both existing SQL guards:initialize a directory with PathCreated,then
  its exact PathAttrsChanged only when properties exist,in this same atomic
  transaction. Its initial final revision is2 when properties were copied,1
  otherwise;each new file is revision1 with its PathPublished snapshot. Changed
  counts mappings,including the root,not events. No FileAccepted,forwarding or
  execution authority is created. Recheck current file access/availability and
  authority before commit. Fresh201 names the new collection Location and
  collection-copied-at-commit,depth and complete result,without a byte ETag.
  Current source/copy names and properties can change independently. Exact
  original-key200 recovers only its private historical result without new
  Location,publication or current-state assertion;changed depth,target or
  command meaning conflicts409. Occupied targets,stale/different source or an
  absent source fail412,missing parents409,permissions403 and capacity507.
  Native API/CLI/stock-curl,whole-tree/shallow,property,mode,mount,corrupt-custody,
  current-policy,capacity,no-extra-effects and retry proof remains owed.
  Locks,outbound server and independent DAV applications
  remain open;this adapter still claims no complete DAV compliance class.
- Collection `MOVE`/`COPY` overwrite requires `Overwrite:T` and both exact
  namespace conditions:source `X-Freightctl-Namespace-Revision` and
  `X-Freightctl-Destination-Revision`,each `entry-UUID:positive-revision` from
  current authorized discovery. The typed API/CLI uses replace:true with
  target_entry_id and target_revision as well as its source pair. Missing
  destination condition is428,malformed/duplicate condition400,and supplying
  it with Overwrite:F is400. Other methods,including byte-conditioned file
  MOVE/COPY,reject this recognized destination condition rather than ignoring
  it. The target must currently be a collection with the exact ID/revision;
  absence,stale values and equal-revision replacement with another ID fail412.
  Source and destination trees must be disjoint in both directions;no self,
  descendant or ancestor replacement. Conditions identify the two roots,
  not frozen hashes of their earlier children. The explicit operation acts
  on their complete current authorized membership under the namespace lock.
  Check every destination directory's read/write/traverse and every actual
  destination file's read/write/current-policy availability,plus writable
  parents,before any transition. Outside aliases cannot rescue a private or
  read-only member. COPY additionally requires current manage_paths alongside
  read/list/write;MOVE retains read/list/manage_paths and its source checks.
  The source and removed destination together must fit the existing1000-entry
  operation bound. COPY preflights projected live namespace capacity;replacing
  at a full limit can succeed when the result fits. No quota or deadline rises.
  Remove the complete destination leaf-first as irreversible tombstones,then
  move or copy the complete requested source scope in the same transaction.
  Depth0 COPY removes the complete destination and installs only the source
  collection/properties;it never merges or copies source children. Preserve
  old custody and property tombstones,MOVE source identities/metadata,and COPY
  independent IDs/ownership/ordinary modes/properties. Commit all exact events
  and one private command receipt together;recheck current file availability
  and authority before commit. A failing child,condition,policy or capacity
  check rolls everything back. Fresh204 has no body,ETag or Location;it names
  collection-replaced-at-commit,the exact new root event and total changed
  mappings(including removed mappings) in X-Freightctl-Changed-Entries.
  An exact COPY retry can recover only historical200;an absent MOVE source
  fails412. The read-only namespace receipt endpoint/CLI can recover the old
  result after a lost204 using the exact original typed command/key,without
  needing either old root or executing again. No response grants forwarding,
  execution or access to removed custody. Native API/CLI/stock-curl complete/
  shallow replacement,private/read-only child,policy,quota,combined-bound,ABA,
  retained-byte and no-extra-effects outcomes remain owed at the new source.
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
- To read property contents explicitly outside DAV,use
  `GET /v1/tenants/{tenant}/partners/{partner}/namespace/properties?path=/data`
  or `freightctl namespace-properties -path /data` with the ordinary protected
  credential/database references. Only one canonical path is accepted;duplicate,
  extra,control-path or malformed selectors fail400 before storage access.
  The response is a `namespace-properties-v1` snapshot with entry identity and
  revision plus a map from expanded `{namespace}name` to standalone XML. The
  observation says authorized-snapshot-at-read:later edits do not change that
  saved answer. This explicit content read shares DAV's read/list,path modes,
  current file policy and shared namespace lock. It does not require management
  permission and grants no write,forwarding,execution or AI disclosure authority.
  Ordinary stat/list still omit values. Native exact API/DAV and actual CLI
  comparisons,read-only access and private-path refusal remain owed for this
  additional surface.
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

## Independent application profile under qualification

The native `dav-application.yml` workflow prepares stock rclone1.76.0 on actual
Linux ARM64 and x86_64 runners. This profile is prepared,not yet qualified.
It builds the unmodified upstream module with Go1.27.3 and its complete default
backend set. The pinned Go module/go.mod sums and upstream tag commit must
match;the actual binary's native build information,dependency inventory and
SHA256 are checked. Complete default source and actual binary vulnerability
reports go through the enforcing pinned converter before any protocol proof.
No dependency replacement,backend-only build,security waiver or arbitrary
GitHub resource ceiling is used. Full private reports stay outside Git.

The client uses an explicit0600 config with `type=webdav`,`vendor=other`,the
scoped HTTPS DAV URL,`auth_redirect=false` and an enrolled `bearer_token`.
The CA is trusted explicitly. Ambient rclone settings,proxies and cloud
credentials are not inherited. Never place credentials in argv,URLs or logs.
Use rclone `lsjson` for finite directory discovery and `copyto` for a single
exact file. This does not imply desktop mounting,locking or upstream server
interoperability;those profiles remain open.

Single-file creation additionally passes `--header 'Idempotency-Key: KEY'`,
`--header-upload 'If-None-Match: *'` and
`--header-upload 'X-Content-SHA256: EXACT_SHA256'`. Use one original key and the
digest of that exact local file. `copyto --no-check-dest` makes the server
evaluate absence even if the client would otherwise skip a same-sized file.
This is a conditional create profile,not a general rclone sync configuration.
The workflow uses an existing authorized parent;it does not qualify multi-file
uploads with one shared key or automatic parent creation.

An existing destination must still fail412. Rclone can attempt DELETE while
cleaning up a failed PUT;that cleanup has no exact file If-Match and remains
refused. The native journey checks that both the failed overwrite and its
cleanup preserve every event,file,mapping,command and onward-effect count.
A nonzero client exit or lost response alone establishes no earlier outcome.
Read the current authorized exact revision or recover the relevant original
receipt through the ordinary product interfaces. Receiving bytes grants no
forwarding,execution or business-acceptance authority.

Pinned primary inputs: [rclone1.76.0](https://github.com/rclone/rclone/releases/tag/v1.76.0),
[WebDAV configuration](https://rclone.org/webdav/),
[client flags](https://rclone.org/flags/),
[exact upstream module](https://github.com/rclone/rclone/blob/e982ff36668f5130d94b4f70409babb3d964df42/go.mod).

The first ARM run at8823d7d passes exact stock acquisition and both enforcing
vulnerability gates,then fails application discovery with exit1. The original
failure is preserved in[F432](../qualification/evidence/F432-first-dav-application-failure.json);
cause and original replay remain owed. Acquisition records runner CPU/physical
memory,binary/archive bytes,wall time,child CPU time and completed-child RSS
without capacity pass/fail thresholds. RSS is not a simultaneous process-tree
measurement. The new[read-only outbound collection](../collection-workflows.md)
uses ordinary reviewed workflows and remains separately under qualification.

## Outbound delivery transport under implementation

F439 adds a separate cryptographic transport capability for one approved stage
path,final path,size and SHA256. The source-only client still exposes only GET
and Close. Both capabilities use the same exact numeric endpoint,pinned CA/name,
TLS1.3,protected bearer or explicit Basic reference,no proxy or redirect,and
live authority checks. The sender cannot supply arbitrary methods,headers or
recipient URIs through the delivery capability.

PUT creates the stage with `If-None-Match: *` and the exact content length.
After exact GET length,SHA256 and EOF verification,a single strong stage ETag
permits one MOVE with `If-Match` and `Overwrite: F`. Only201 acknowledges a
new mapping;replacement,multi-status,redirect and oversized replies fail.
The Destination URI is built from the approved TLS authority and final path.
Reads forbid ranges and transformed encodings and request no caching. Buffers,
response bodies and socket idle periods remain bounded;there is no arbitrary
GitHub capacity ceiling or aggregate file deadline in this transport.

This is the transport needed by the durable delivery worker. It does not yet
expose a new authorized product delivery profile. Worker intent/approval/lease/
fence/receipt integration and independent stock-server native proof remain owed.
A transport error never proves that the receiver retained no bytes. No resend,
DELETE cleanup,business acceptance or power-loss durability follows from a201
or matching final bytes. The receiver must separately enforce private staging
and its approved delivery contract. Native interoperability and the whole DAV
row remain unqualified. Conditional MOVE semantics follow
[RFC4918 sections9.9 and10.6](https://www.rfc-editor.org/rfc/rfc4918.html#section-9.9).
