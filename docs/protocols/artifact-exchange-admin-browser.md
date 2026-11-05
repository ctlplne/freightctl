# Receive endpoint administration

With a root account carrying `admin` and `accounts_manage`, choose **Receive
endpoints**. **Check endpoint directory** reads currently visible heads;
**Manage** inspects the selected head again. **New receive endpoint** prepares a
new immutable endpoint ID. These actions move no artifact bytes.

Choose **Check participant accounts**, then choose a recipient and allowed
senders. A recipient needs read/list; a sender needs read/deliver. Only active
accounts are selectable. Each selection pins its actor ID, current authority
revision and SHA256 of its exact namespace-root bytes. Pages preserve selections;
removing one needs an explicit action. Existing definitions retain their original
bindings until the manager explicitly reviews a replacement. Fresh account reads
do not silently rotate a binding or grant credentials.

Review creation, replacement or revocation. The review shows exact participants,
root fingerprints, endpoint ID and expected revision. Confirming sends one typed
command through the existing same-origin CSRF session, ordinary endpoint service
and forced-RLS transaction. Replacement uses the inspected revision; a concurrent
change refuses rather than overwriting it. Revocation carries no new definition,
preserves its prior definition hash and permanently closes that endpoint ID.
Older receive views lose future retrieval when their endpoint head changes. Prior
recipient copies cannot be recalled.

The original command and retry key stay fixed while its review is open. If the
response is lost, **Confirm or recover endpoint command** retries that exact
meaning. The receipt must match the endpoint ID, next revision, state, definition
hash and original manager before it is shown. **Use confirmed endpoint version**
starts another review from the confirmed version. Clearing an uncertain review
does not undo a possible commit; inspect the endpoint before another change.
Reload recovery for endpoint-management reviews is not yet implemented. The saved
offer-recovery file does not contain endpoint-management authority.

The server rechecks manager and participant authority at commit; a selected
account snapshot supplies no authority of its own. Client session changes refuse
before contact and again before disclosure. Wrong roles, malformed/foreign
bindings, unexpected receipt fields, dishonest pages and substituted receipts
refuse. No credential values, private operation receipts, raw artifact bytes or
model context are displayed or created by this editor.

The original native Chrome profile is extended with a separate root-manager
session, actual human ingress plus account selection, reviewed create, exact same-key replay,
changed-recipient replacement and revocation. It preserves all earlier proof and
requires seventeen accessibility states plus exactly three immutable versions,
three command receipts and one revoked revision3 head. Local adapter/canonical
checks and compilation do not establish that runtime proof. Actual Chrome/HTTPS/
PostgreSQL qualification, response-loss/reload recovery and all affected original
journeys remain owed. Local inference and heavy runtimes stay off.
