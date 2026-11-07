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

Private staging and sealed bytes have separate protection states. Unix retains
exact0600 staging and0400 sealing. Windows sealed descriptors grant the runtime
owner read access and FILE_WRITE_ATTRIBUTES,the metadata right required by Go's
handle-relative hard-link publication. They grant no data/append/EA write,
execution,deletion or explicit ACL/owner mutation rights;other principals remain
excluded. Generic public-read trust profiles cannot qualify sealed private data.

Sealing checks the held object before and after changing its descriptor. It is
idempotent for an already sealed file and refuses unsupported/nonprivate states.
Changing permissions cannot revoke an existing writable handle on either
platform. The owner must sync and close that handle before acknowledging or
publishing anything. A new Windows native case requires that reopening for byte
writes fails after close and independently checks the original bytes. Local
sealing/same-object hard-link/idempotency and descriptor mutation cases pass;
actual Windows execution and custody/setup integration remain owed.

The implementation uses the platform APIs described by Microsoft's
[file security documentation](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights)
and the pinned Go
[Windows security bindings](https://go.dev/src/cmd/vendor/golang.org/x/sys/windows/security_windows.go).

Custody now uses these profiles for the configured root,storage identity,
staging,writers,generated slots and sealed acceptance. Missing directories are
created private;existing permissions are validated and never silently changed.
Identity reads and object reads bind `Lstat` to the opened physical file before
using its protection state. Matching a byte digest alone cannot make a writable
partial object readable as immutable custody. Partial reserved slots remain in
place and cannot be adopted as sealed artifacts.

Unix custody retains the original data sync,close,directory sync and recovery
re-sync. The original Windows33ad447 recovery failed because FlushFileBuffers
requires write access: reopening a sealed file for reading cannot flush it.
Granting data writes to sealed custody is not an acceptable repair.

The prepared Windows path flushes the original writable creator handle before
attaching a fixed,small extended attribute to that same held file. This is a
record of a successful data flush,not a domain receipt or permission. It binds
storage identity,service object name,exact length and digest to the native128-bit
file ID and64-bit volume identity. It then flushes again,checks the record,closes
the creator and syncs the held directory before ordinary SQL acceptance. No new
data/append/EA write grant is added to the sealed descriptor.

Recovery opens read-only,checks protection and the exact attached record,hashes
every byte,and persists the held directory. It relies on the proved earlier
data flush;directory sync is not a replacement for flushing data. Missing
records leave reserved objects incomplete and preserved. Invalid records fail
closed;they cannot be hidden by choosing another slot. Copying a record to a
different physical file cannot qualify it,even when name,length and bytes match.
Record parsing is bounded,canonical and rejects unknown or duplicate meaning.
These are filesystem attributes,with no sidecar or new SQL authority.

Filesystems without the required extended-attribute/identity APIs fail closed.
Existing Windows objects without this record are not silently backfilled or
adopted. Copy/restore needs fresh persistence proof for the new physical object.
Actual Windows execution,unsupported-filesystem/restore/restricted-token and
process-death/power-loss outcomes remain owed. F275 retains the original failure
and prepares native failed-flush,read-only recovery and copied-identity cases;
local compilation establishes no Windows persistence claim.

Scanner pathname sockets have a separate private-object profile. Unix retains
the socket-type,exact inode and group/other permission-bit checks. Windows opens
the socket filesystem object with OPEN_REPARSE_POINT and only metadata/security
read rights. It requires the exact native AF_UNIX reparse tag,not a symlink or
another reparse kind,and uses the existing strict held-handle owner/protected
DACL parser. It holds that object without delete sharing for the scan,rechecks
the pathname identity and current ACL after connection and before returning a
verdict,and never changes a deployed socket's permissions.

Windows socket permission bits do not prove privacy. The task-owned synthetic
listener fixture sets and reads an actual private DACL before use. Broad access
must fail before reading a source byte;ordinary files cannot qualify as sockets.
Scanner configuration,database,temp and socket-parent directories also use the
actual private-directory profile. Local Unix socket/replacement/privacy and
scanner-protocol stand-ins pass. Actual Windows socket/ACL/name-pin/protocol
execution and real engine deployment/detection remain owed. F279 records the
original native failure and precise local proof;it makes no malware-detection or
whole-Windows-support claim.

CLI exchange download separates verified staging from final publication. The
same held-root stage operation still enforces exact length,EOF,digest,private
creation,sealing,real file sync and close. Publication still checks that the
requested parent is the original physical directory,links without overwrite,
removes only the owned stage and syncs the held directory. Failure after linking
still reports that a complete file may exist with persistence unproved.

The original Windows adverse fixture tried to rename a parent while its private
child was still open and stopped at Access denied. The active-write Windows case
now requires that exact refusal and unchanged parent,sealed bytes and cleanup.
The original substitution/no-publication/no-foreign-cleanup assertions execute
after the production stage-close boundary,on every platform,before publication.
Unix additionally retains the original during-write replacement case. No data
sharing,ACL or isolation rule is relaxed to enable an attack fixture. Focused
local download cases and Windows compilation pass;actual Windows cases are owed.
