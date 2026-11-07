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

The implementation uses the platform APIs described by Microsoft's
[file security documentation](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights)
and the pinned Go
[Windows security bindings](https://go.dev/src/cmd/vendor/golang.org/x/sys/windows/security_windows.go).
