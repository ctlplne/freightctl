# Legacy SCP file profile

`scp-legacy-file-v1` is an explicitly enabled SSH artifact protocol. It is
separate from modern `scp`,which normally selects the existing SFTP subsystem.
The initial profile sends or receives exact regular files and sequential files
inside an existing authorized directory. It accepts literal `scp -t path` and
`scp -f path`,optional `-d` for an existing receive directory,and `-v`. It does
not expand globs,home directories,variables,commands or remote shells. Recursive
directory creation and `-p` access-time preservation remain unsupported/owed;
they fail before a protocol session starts. No whole SCP parity claim follows.

The [OpenSSH reference wire implementation](https://github.com/openssh/openssh-portable/blob/87f0cd1892e501f835dd210abea5461807c8deba/scp.c)
defines C-mode/size/name records,exact data lengths and zero/error responses.
This profile uses bounded records and buffers,one authenticated SSH channel,the
existing connection/session/idle limits and the shared SFTP writer slots. It
accepts only canonical virtual names and regular permission bits;filenames
cannot select another path,escape a directory or enter protocol-control paths.
Paths are relative to the current account root,never the host filesystem.

Enable with `serve-sftp --legacy-scp`. The default remains subsystem-only.
Both transports use the registered SSH key/current account and the ordinary
PostgreSQL/RLS,namespace and immutable custody services. A file header receives
permission to send bytes only after its ordinary writer opens. An incomplete
body or nonzero sender terminator marks that writer failed before cleanup.
The final zero response follows successful durable close,whole-file SHA256,
transactional acceptance and current intake binding. Held bytes remain held.
It proves local acceptance only,never publication of a held file or downstream
business processing. A lost final response remains ambiguous;legacy SCP has no
application idempotency/recovery ticket. Do not silently retry an uncertain copy.

Downloads use the exact verified immutable revision and recheck current key,
account,path and intake authority on each bounded read. A peer's zero response
is transport acknowledgement;it does not prove independent persistence or
business acceptance. Receiving grants no forwarding or execution authority.

Native OpenSSH `scp -O` upload/download,independent bytes,partial-body/nonzero
terminator,revocation/foreign-root/held refusal and modern SFTP compatibility
proofs belong in GitHub on actual ARM/x86. Local parser/compilation checks cannot
qualify them. Recursive/preservation/other-peer/full J02 and incumbent edition
comparison remain owed. No local peer,model or other heavyweight runtime runs.
