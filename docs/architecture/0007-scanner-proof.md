# 0007: bind a required scan to exact held bytes and an expiring profile

Accepted for local engineering. Add an optional immutable scanner reference to the existing intake policy, preserving old canonical policy hashes. The required order is detached signature, scan, CSV, separate operator release. A detection rejects before parsing. Unavailability cannot become a clean verdict.

Use a library-only private Unix INSTREAM adapter with bounded chunks and correlated, bounded replies. Pin the exact engine/database VERSION before and after one stream session, plus protected configuration bytes and expiry. Send actual verified custody bytes rather than a daemon-visible host filename. Store metadata and hashes, never payload or raw diagnostic text, in the report/event.

Scanner enrollment is local administrative configuration, like connection enrollment. HTTP clients can select registered references, inspect sanitized metadata and revoke under ordinary grants; they cannot supply host paths. Profile mutation is forbidden. Revocation and expiry prevent future availability of affected released revisions through the shared SQL gate.

Two separate PostgreSQL admission slots bound scan concurrency across processes. Existing check leases, authority checks and revision fencing still govern result acceptance. Passing does not publish. Release binds the exact report and source, validates current profile/configuration and consumes only an unexpired snapshot. Engine outage after a completed scan does not erase that snapshot; profile revocation or expiry can stop future reads.

Migration 13 appends one forced-RLS domain relation and minimal release-proof columns. Existing grants and migrations remain unchanged. Event, policy, verdict and release guards reject incomplete/mismatched proofs. All thirty-one domain relations are required under the non-owner runtime.

This protocol trusts the private socket's operator. Reading a pinned config does not attest the loaded daemon or full database. Operational detection, process isolation/resources, signature-feed lifecycle and independent malware qualification remain separate mandatory gates. No daemon, signature database or local model is loaded for this change. See [operator details and limits](../scanners.md).
