# Browser file exchange

The HTTPS service now serves a file workspace at `/`. It supports enrolled-account sign-in, file browsing, bounded upload, pause/reload/resume, intake inspection, required checks, separate release review and native streaming download. These actions use the existing PostgreSQL custody and permission services.

This is a development profile. A clean installer, first-admin/partner onboarding, human identities, SSO/MFA, delegated review, broad browser/platform coverage and independent operator qualification remain required. Real malware detection and the fresh independent signature regression are still open. Local inference stays off.

## Connect an enrolled account

Follow [the development setup](development.md) to initialize task-owned PostgreSQL, enroll the account and start `freightctl serve` with its TLS certificate and custody store. Open its HTTPS origin. Enter the tenant and partner UUIDs and select the protected account credential file. The server establishes a session under exactly that account's current permissions.

Use a dedicated trusted HTTPS hostname for an actual deployment. Browser cookies belong to a host, not a TCP port; unrelated applications on that host are part of its trust boundary. The loopback qualification uses synthetic identities in an isolated browser context and an explicit fixture certificate SPKI pin. It changes no host/browser certificate trust store. Reverse-proxy and production deployment profiles remain unqualified.

The account credential is read into a bounded byte buffer for sign-in, then cleared where the application controls it. No account token, file contents or filename is saved in localStorage, sessionStorage or an application database in the browser. The browser necessarily retains its short-lived session cookie. It is HttpOnly/Secure/SameSite=Strict; JavaScript cannot read it. Browser/HTTP libraries and JavaScript strings make copies the application cannot reliably lock or erase. No RAM-erasure or browser-at-rest certification is claimed.

Sessions default to ten minutes. The server flag `--browser-session-seconds` selects an absolute lifetime of 1–600 seconds for a deployment; clients cannot extend it. Reload restores an unexpired session without rereading the account credential. Expiry, sign-out, changed account policy or parent credential changes stop later actions and bounded reads. Sign in again to resume owned work. Login replay retains its original expiry. Signing out revokes the session in PostgreSQL and clears its cookie; it does not delete files or checkpoints.

## Send and resume a file

Choose **Upload file**, select the source and review its absolute virtual destination. The destination is inside the account's mounted workspace, never a host filesystem path. The current UI creates new paths; it refuses an existing file rather than silently replacing a revision.

The client computes SHA-256 in one worker using 1 MiB slices. This is the file's byte fingerprint. It then opens an actor-owned upload ticket fixing destination, length and digest. Each bounded chunk is acknowledged only after the existing durable checkpoint transaction. Progress shows the last server-confirmed offset, not bytes merely sent over the network.

**Pause upload** cancels the current request. The server might already have committed that chunk. After reconnect/reload, find the ticket in **Saved uploads**, select **Resume**, and choose the original complete file. The client verifies its full length/fingerprint, obtains current server progress and sends only the missing suffix. Another file cannot replace the ticket's source. Another account, including a same-partner administrator, cannot list or resume its private ticket.

Saved-upload listing is keyset-paginated, at most 100 records per request. It filters actor, current mount and authority revision. A separate boolean reports whether older open jobs need access-policy review without revealing paths under an old mount. Current UI pages use 50 records. **Stop upload** marks an open ticket aborted; retained pieces remain charged and are not automatically deleted. Cleanup, governed rebind, batch upload and larger estate qualification remain work.

Completion means the server verified and durably accepted the exact full bytes. The receipt distinguishes integrity-only acceptance from held intake. It does not establish malware clearance, dispatch, recipient consumption or business acknowledgment. A completed ticket retains its original acceptance meaning after later policy changes or release.

## Inspect and release held revisions

To prepare a file for an enrolled SFTP or FTPS client, open **Uploads**, choose the original file and its destination, then select **Prepare transfer ticket**. The browser computes its full SHA-256 and saves the expected size and destination without sending file bytes. The saved details show the ticket's exact **SFTP transfer path** and **FTPS transfer path**. Use your verified server identity and enrolled account in the transfer client; FTPS requires binary mode. These paths identify a private receiving job, not a published file.

Select **Refresh upload status** to read the receiver's committed offset. After a server crash, send the suffix starting at that recorded offset; bytes sent after it may need to be sent again. Reloading the page discovers the same actor-owned ticket under **Saved uploads**. Another account cannot inspect it merely because that account administers the same partner.

If the final transfer reply was lost, refresh or reload and inspect the saved acceptance record, its **Accepted file ID**, digest and acceptance boundary before sending again. A full progress bar without completed acceptance is insufficient. A held file still needs its required checks and separate reviewed release; **Inspect intake check** uses the ordinary intake controls. This read recovers the committed file identity and acceptance state; it does not invent a transport reply or prove downstream business delivery. See [the shared ticket profile](protocols/resumable-uploads.md).

The new browser/FTPS crash journey is prepared in [F067](qualification/evidence/F067-ftps-browser-tickets.json). Runtime qualification remains pending until its original native GitHub browser profile completes; static checks alone do not qualify it.

**Intake checks** shows this account's held revisions and current result. A required detached signature can be attached as a bounded public sidecar (at most 32 KiB). Private signing keys remain with their owner. The existing signature parser rejects unsupported/private/mixed packets and binds the artifact to the exact source, policy and check revision. Fresh positive independent signature qualification for the current candidate remains open because the offline peer cannot start; the UI does not relax the age policy.

**Run required checks** invokes the ordinary bounded check service. Signature, selected scanner and CSV rules execute in their required order. A missing/unverified scanner fails the check; rejected or failed bytes remain held. The UI cannot override the scanner, choose another signer, force a clean result or bypass an attempt limit. Operational scanner enrollment remains a separate administrator CLI operation using protected local references.

A passing check remains held. **Review release** opens a separate dialog with source SHA-256, policy SHA-256, report SHA-256 and expected check revision. **Release file** submits precisely that decision. The server rechecks current access, revisions, policy, proof expiry and actual bytes in its normal transaction. A stale decision fails. Normal path permissions and current intake policy still govern later downloads.

Downloads stream through the browser's native download manager, with the authorized virtual basename as the suggested filename. Payloads do not become an in-memory JavaScript Blob. The server validates exact storage bytes and rechecks current authority/release before bounded reads. A pre-stream refusal provides a readable browser page; ordinary API clients keep machine-readable JSON. Already-delivered bytes cannot be recalled.

## Build and local verification

The runtime server needs the committed embedded assets; it does not fetch a CDN or run Node. Frontend development uses exact versions in `web/package-lock.json`. Runtime dependency notices are retained in `web/THIRD_PARTY_NOTICES.txt` and the embedded notice asset. Core distribution still requires the owner's final licensing approval.

```sh
npm --prefix web ci --ignore-scripts
npm --prefix web run typecheck
npm --prefix web run build
npm --prefix web run check-built
PLAYWRIGHT_BROWSERS_PATH="$PWD/.cache/freightctl-playwright" node web/node_modules/playwright/cli.js install chromium --only-shell
python3 scripts/qualify-browser.py
```

Run from the root on local main. `check-built` rebuilds in memory and compares every artifact. Go tests also verify embedded output/source hashes. Browser acquisition is explicit and uses the task cache. The native journey uses one headless browser at a time, real loopback PostgreSQL, actual storage, and stock curl as an independent byte observer. It covers pause/reload, process restart, wrong-source refusal, CSV checking, exact release, native download, private actor/tenant views, expiry and selected accessibility scans. It retains protected raw outputs and safe references. It does not close the complete clean-install/business-file journeys or substitute for all required security, adoption, platform, performance and release gates.

| Operational bound | Current profile |
| --- | --- |
| Active browser sessions | Eight per actor; original-key replay creates no new session. |
| Session expiry | 1–600 seconds, selected by server configuration; no silent renewal. |
| Distinct logout receipts | Sixteen per session; identical-key replay adds no new event. |
| Client file buffering | One 1 MiB hash slice and one bounded transfer chunk at a time; native download streaming. Actual browser/OS overhead is separate. |
| JSON response | At most 256 KiB in the client. |
| Chunk/file/ticket bounds | Server [upload-ticket profile](protocols/resumable-uploads.md) and custody configuration remain authoritative. |
| Processing deadline | Normal check budget, at most 60 seconds; separate bounded HTTP wait. |

These protect a development deployment; they are not commercial limits or benchmark results. Fair scheduling, retention, recovery/rebind and production capacity remain required.
