# DAV namespace read and conditional-create profile

This is a partial read/conditional-create adapter, not a claim of RFC4918 class1,2 or3 compliance.
The full C-WEBDAV contract remains open: replacement and other namespace writes,properties,locks,outbound server
connections and independent DAV application interoperability still need work.

Use the existing HTTPS listener and an enrolled bearer credential:
`/v1/tenants/{tenant}/partners/{partner}/dav/` followed by an encoded virtual
path. The profile does not accept browser cookies or Basic authentication.
Credentials belong in a protected header file,never in URLs or shell arguments.
The prefix selects a tenant and partner; the ordinary PostgreSQL/RLS identity,
mount root,path modes and current intake policy decide what can be discovered
or read. A URL never refers to a host filesystem path.

- `OPTIONS` authenticates and checks read/list access to the addressed entry.
  It returns `Allow: OPTIONS, PROPFIND, GET, HEAD, PUT` and no DAV compliance class.
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
- Other mutating DAV methods return405 after authenticating the credential.
  Discovery and unknown properties grant no forwarding or execution authority.
  Requests with traversal,encoded separators,control names,noncanonical Unicode
  or query selectors fail before router path cleaning can redirect them.

The prepared native ARM/x86 profile uses real PostgreSQL and stock curl over
verified TLS. It parses discovery XML independently,interrupts an actual file
response,then reconstructs the exact revision using a range and its ETag. The
API profile also tests concurrent non-overwriting create transactions,original
receipt recovery,held acceptance and separate release,modes,tenant/partner refusal,credential
revocation,unknown properties and zero delivery/workflow effects. Until their
original GitHub jobs pass at an exact candidate,these runtime outcomes are owed.
The stock profile also creates through PUT,observes its412 retry and independently
compares readback. Stock curl proves the declared HTTP methods; it does not qualify a desktop DAV
mount,locking client or independent upstream DAV server.

Protocol references: [RFC4918](https://www.rfc-editor.org/rfc/rfc4918.html),
[HTTP conditions](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.2) and
[428 Precondition Required](https://www.rfc-editor.org/rfc/rfc6585.html#section-3).
