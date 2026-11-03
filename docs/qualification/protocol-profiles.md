# Protocol acceptance contracts

Baseline `2026-10-29.1` adds [structured contracts](protocol-profiles.json) to the existing 13 AS1/AS2/AS3/AS4/OFTP2/PeSIT rows. It preserves all 83 row IDs, states and incumbent observations. All13 rows covered by those six contracts remain planned. The new records define what must be proved before a support claim; they provide no runtime or vendor interoperability evidence.

| Contract | Specification and target | Still required before qualification |
| --- | --- | --- |
| PP-AS1 | [RFC 3335](https://www.rfc-editor.org/rfc/rfc3335.html): SMTP and protected MIME messages/receipts | Select security and mailbox/relay profiles; qualify independent sending and receiving. |
| PP-AS2 | [RFC 4130](https://www.rfc-editor.org/rfc/rfc4130.html): HTTP messages and sync/async MDNs | Pin security, canonicalization, identifiers and callback authority; qualify both directions and rollover. |
| PP-AS3 | [RFC 4823](https://www.rfc-editor.org/rfc/rfc4823.html): MIME/CMS over FTP | Select carrier security and push/pull mapping; qualify messages and receipts separately from FTP transport. |
| PP-AS4 | [OASIS AS4 1.0](https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/profiles/AS4-profile/v1.0/os/AS4-profile-v1.0-os.html): ebHandler target | Pin deployment/security and peer profiles; qualify all applicable clauses, including both Push/Pull roles. |
| PP-OFTP2 | [RFC 5024](https://www.rfc-editor.org/rfc/rfc5024.html): secure TCP/IP target, restart and EERP/NERP | Pin records/security/peer profiles; retain any baseline-required legacy-network/VAN gaps. |
| PP-PESIT | Exact permitted specification/version remains unselected | Resolve the actual profile and native client/server; preserve both committed rows. |

Identical AS2 retries recover the saved receipt; changed-content ID reuse is refused. This corrects the earlier blanket duplicate-rejection wording. [RFC 4130 §5.5](https://www.rfc-editor.org/rfc/rfc4130.html#section-5.5).

MDN means message disposition notification: a protocol receipt. MIC means message integrity check: a message digest. EERP/NERP are OFTP2 positive/negative end responses.

The register separates specification selection from deployment readiness. Each contract has four open prerequisites: security/custody, numeric resource bounds, a pinned independent peer and complete normative requirement coverage. Named specifications can reference older algorithms; a reference does not enable them. Resolve security-policy incompatibilities explicitly and keep conformance gaps visible. Minimum cases cannot replace applicable normative clauses or narrow GOAL.md.

The common cases come from GOAL.md: tenant/partner isolation, promised persistence, exact retry meaning, current authority, bounded work, honest receipts, independent byte verification and ordinary browser/API/CLI operation with AI disabled. Protocol-specific cases add the wire behavior. A receipt proves only its documented boundary; it cannot alone establish downstream business processing.

Before changing a protocol row to verified, record its candidate, environment, steps, independent peer version/digest, observed roles and a passing artifact for every required case. Resolve each prerequisite with hashed evidence. The checker verifies references, digests and declared coverage; a human still must inspect whether those artifacts actually prove the claimed behavior. Synthetic validator fixtures never qualify a protocol.

Run the lightweight ledger checks locally:

```sh
python3 scripts/check-records.py
python3 scripts/test-records.py
```

The same refusal tests are wired into core CI; GitHub execution remains unverified. No protocol conformance command is advertised before its implementation exists. Exact incumbent editions, gateway/client versions, permitted PeSIT material, security profiles and independent peers remain open under R001/R008. No model, malware database or new service is needed for these record checks.


## FTPS receiving development profile

The [receiving profile](../ftps.md) and [F058](evidence/F058-ftps-receiving.json) describe the current implementation. Its two receiving rows are implementing, and its proactive sending rows remain planned. This profile is distinct from the six independently gated AS-family/legacy contracts above.

| Boundary | Current mechanism and evidence |
| --- | --- |
| Role/security | Explicit AUTH TLS and implicit receiving/authenticated retrieval; TLS1.3 with certificate verification and a distinct control-session ticket key. Data must resume that authenticated control session. |
| Network | Numeric loopback control and passive sockets; EPSV/PASV; explicitly enabled PORT/EPRT callbacks restricted to the same numeric peer and unprivileged ports. RFC2428 alternate delimiter covered. |
| Files | Shared scoped PostgreSQL/custody; binary bytes unchanged, ordinary ASCII text conversion, listings/directories/rename/delete, accepted-prefix REST and append. No host filesystem driver. |
| Acceptance | Success follows staged-byte sync/hash and the metadata/intake transaction. Held data stays unpublished; no scan/business/ exactly-once promise follows from226. Detected abort, control loss, missing/foreign tickets and unnotified EOF preserve the old accepted revision. |
| Current proof | F060: native Linux ARM/x86 stock curl service and public CLI modes pass at563751e; full PostgreSQL suites pass569 records each and engine suites pass223 with one visible privileged-port20 skip. The expanded native ARM stand-in passes15 protocol/identity/interruption cases per service/CLI mode. Pinned stock lftp/curl atb99c8d2 pass on both native Linux architectures: nine test records/41 commands each with exact CLI bytes and cleanup. Mac curl/LibreSSL resumption pairing remains refused. |
| Still required | Full stock/vendor/client, active lifecycle/intake/ticket recovery, production TLS/listeners, IPv6/firewall/gateway, larger/longer/crash/platform and whole-row acceptance; proactive remote FTPS sending and collection. |
