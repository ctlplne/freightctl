# Protected file references

`internal/protectedfs` checks the opened filesystem object. It does not decide
which tenant,partner or actor may use a credential;those ordinary authorization
and immutable configuration bindings remain separate.

On Unix platforms,the existing permission rule remains:the file is regular and
its permission bits grant nothing to group or other users. Secret reads still
check the original path identity,positive size and the caller's byte bound. New
files use exclusive creation with mode0600. No existing file is overwritten.

Windows file attributes do not express an owner-only permission rule. The
Windows profile uses a protected discretionary access-control list,or DACL:the
operating system's list of who may access this particular object. Creation
attaches an explicit owner-only descriptor before writing any bytes. The owner
must match the runtime process user. Validation obtains the descriptor from the
held handle while `RawConn.Control` keeps that handle alive;it does not query a
second pathname. Reparse points and non-disk objects are refused.

The accepted Windows descriptor has a nonempty,present,protected DACL with at
most256 simple allow entries. Every entry names only the owning runtime user,
has a nonzero access mask and has no inheritance flags. Null or empty DACLs,
unprotected descriptors,other owners/principals,inherited entries,deny entries
and unsupported ACE kinds are refused. This deliberately describes one narrow
profile;it does not claim compatibility with every Windows service,restricted
token,group-based credential arrangement or filesystem.

Token,development certificate and audit identity creation use this seam.
`ReadSecret` checks the same handle before loading its bounded protected byte
buffer. The Windows audit negative fixture grants Everyone read access through
the real DACL API;Unix retains its chmod0644 fixture. The refusal assertion is
unchanged. Native Windows cases also change a held file to broad,null,empty,
inherited and unprotected descriptors,then restore only their exact test-owned
ACLs for cleanup.

Local policy/handle/audit and full ordinary Go units pass;Windows cases are
cross-compiled only. Actual Windows execution,wrong-user/restricted-token and
reparse races remain owed. Storage roots,setup parents,other private writers and
their platform fixtures still need their own implementation and qualification.
This change does not establish Windows product support,power-loss durability or
whole-platform acceptance.

Public certificate and CA references use a separate integrity profile. Unix
retains its existing group/other write refusal (mode0022). On Windows,the same
held-handle descriptor checks remain,including the runtime owner,protected DACL,
simple explicit ACEs and no reparse point. Other principals may receive generic
or mapped file read/execute rights only;data/append/attribute writes,deletion,
ACL/owner changes and all-access grants are refused. The runtime owner must
have an explicit grant. Private keys and credentials always use the stricter
owner-only profile;public-read permission cannot qualify a secret.

FTPS server certificate and client CA reads validate this profile before loading
bytes. Existing identity/size/CA digest/key-pair/host/TLS/channel checks remain.
The original FTPS permission test changes actual Windows DACLs for public read,
other-user write and owner-only access;Unix retains the same chmod states. The
client CA test now also requires refusal of other-user write and acceptance of
public read. Focused local checks and Windows compilation pass;actual Windows
ACL/TLS/profile execution remains owed.

Private directory creation is exclusive. Windows passes the owner-only
descriptor to native creation and receives the newly created directory handle
from that operation. New private flat objects are created relative to a held
`os.Root`,using a pinned parent handle and `NtCreateFile(FILE_CREATE)` on Windows.
The parent must satisfy the private-directory profile;the new object has its
explicit private descriptor before any data is written. Unix retains relative
exclusive0600 creation. Creation never reconstructs a root pathname after its
handle has been opened. Service-owned leaf names exclude separators,alternate
streams,parent traversal and Windows device aliases. Owner directory paths may
contain spaces and Unicode.

The local owned-root rename/replacement,exclusive no-overwrite,private-before-
first-byte and leaf-refusal tests pass. Windows compilation/vet pass;actual
native execution,hostile parent/reparse/race/other-token cases and custody/setup
wiring remain owed. These primitives alone do not qualify Windows custody.

The implementation uses the platform APIs described by Microsoft's
[file security documentation](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights)
and the pinned Go
[Windows security bindings](https://go.dev/src/cmd/vendor/golang.org/x/sys/windows/security_windows.go).
