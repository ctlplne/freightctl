# Operator provisioning for an agent's SFTP route

An operator with current root `admin` and `connections_manage` permissions may
provision one exact active, operator-owned SFTP connection for a named actor
in the same tenant and partner. The command pins the operator's source ID,
version and definition hash, and the recipient's actor ID and authority
revision. The recipient must already have root `read`, `deliver`, and
`workflow_execute` permissions. The operation makes a distinct actor-owned
registration with the same approved transport definition and protected
credential references. The operator remains the author of the journal record.
The recipient's credential, root and grants stay untouched.

Use the HTTPS endpoint or the local `connection-provision` command with the
same operator credential, request body, and stable idempotency key. The
HTTPS request reads at most 4 KiB of command metadata. Keep the authorization
header in a protected file and verify the server certificate.
[OpenAPI contract](../api/operator-connection-provisioning.openapi.json)

```sh
curl --cacert ./ca.pem --header @./operator.headers \
  --header 'Content-Type: application/json' \
  --header 'Idempotency-Key: provision-sftp-20261118' \
  --data-binary @./provision.json \
  "$FREIGHTCTL_HTTPS_ORIGIN/v1/tenants/$TENANT/partners/$PARTNER/connections/provisioning/commands"
```

```sh
freightctl connection-provision --dsn-file ./pg-runtime.dsn \
  --token-file ./operator.token --tenant "$TENANT" --partner "$PARTNER" \
  --request-file ./provision.json --idempotency-key provision-sftp-20261118
```

Prepare one of the following command bodies.

```json
{
  "operation": "provision",
  "recipient_actor_id": "recipient UUID",
  "recipient_authority_revision": 1,
  "source": {"id": "operator connection UUID", "version": 1, "hash": "definition SHA-256"}
}
```

```json
{
  "operation": "revoke",
  "provision_event_id": "original provision event UUID",
  "connection": {"id": "recipient connection UUID", "version": 1, "hash": "definition SHA-256"}
}
```

The original operator can revoke the new registration by its original event
and exact reference. Both operations store their receipt and connection state
in the same transaction. A retry under the same key recovers the original
receipt. The new registration has its own lifecycle. Revoking the operator's
source revision affects the operator's registration. Retire the recipient's
registration explicitly when withdrawing its route. A shared remote key is
still subject to its ordinary rotation and revocation.

The receipt carries the operator and recipient identities, the source and new
connection references, the recorded state, and the event ID. No connection
bytes or private credential references appear in the receipt. The recipient
uses ordinary actor-private connection lookup and the existing workflow
approval, dispatch policy, and worker guards. No peer contact occurs while
provisioning. Live revocation fences future work through the same registered
connection checks used for ordinary sending.

HTTP returns the same typed result and `replayed` field as the CLI. The local
stock replay recovers an HTTP provision receipt through the CLI, reads the
assigned route only as its recipient, and verifies that HTTP revocation stops
queued work before the receiver is contacted.
[F518 replay](../qualification/evidence/F518-operator-connection-provisioning-https.json)

This command requires schema 67. Its projector uses a dedicated non-login
role with forced tenant and partner row security. The ordinary runtime keeps
actor-private reads and writes. The tested schema 66 upgrade retained the
original connection, journal, and migration checksums. [F505 replay](../qualification/evidence/F505-operator-connection-provisioning.json)
