import { asCollectionConnections } from "./collections-types";
import { digestBytes } from "./crypto";
import { ApiError, object, uuid, type Session } from "./types";

const sha256 = /^[0-9a-f]{64}$/;
const root = digestBytes(new TextEncoder().encode("/"));

export const connectionProvisionAllowed = (session: Session) =>
  session.identity.root_policy_digest === root &&
  session.identity.permissions.includes("admin") &&
  session.identity.permissions.includes("connections_manage");

export function connectionProvisionScope(session: Session) {
  const who = session.identity;
  return JSON.stringify([
    who.tenant_id,
    who.partner_id,
    who.actor_id,
    who.authority_revision,
    who.root_policy_digest,
  ]);
}

interface Reference {
  id: string;
  version: number;
  hash: string;
}

export interface Recipient {
  id: string;
  label: string;
  authority_revision: number;
}

export type ProvisionCommand =
  | {
      operation: "provision";
      source: Reference;
      recipient_actor_id: string;
      recipient_authority_revision: number;
    }
  | {
      operation: "revoke";
      connection: Reference;
      provision_event_id: string;
    };

export interface PendingProvision {
  command: ProvisionCommand;
  key: string;
}

function bad(): never {
  throw new ApiError("invalid_server_response", 502);
}

function exact(value: unknown, required: string[], optional: string[] = []) {
  const o = object(value);
  if (
    required.some((k) => !Object.hasOwn(o, k)) ||
    Object.keys(o).some((k) => !required.includes(k) && !optional.includes(k))
  )
    bad();
  return o;
}

function id(value: unknown): string {
  if (typeof value !== "string" || !uuid(value)) bad();
  return value;
}

function integer(value: unknown, max = Number.MAX_SAFE_INTEGER): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > max
  )
    bad();
  return value;
}

function reference(value: unknown, max = 2147483647): Reference {
  const o = exact(value, ["id", "version", "hash"]);
  if (typeof o.hash !== "string" || !sha256.test(o.hash)) bad();
  return { id: id(o.id), version: integer(o.version, max), hash: o.hash };
}

function sameRef(left: Reference, right: Reference) {
  return (
    left.id === right.id &&
    left.version === right.version &&
    left.hash === right.hash
  );
}

export function asPendingProvision(value: unknown): PendingProvision {
  const o = exact(value, ["command", "key"]);
  const c = object(o.command);
  const key = id(o.key);
  if (c.operation === "provision") {
    exact(c, [
      "operation",
      "source",
      "recipient_actor_id",
      "recipient_authority_revision",
    ]);
    return {
      key,
      command: {
        operation: "provision",
        source: reference(c.source),
        recipient_actor_id: id(c.recipient_actor_id),
        recipient_authority_revision: integer(c.recipient_authority_revision),
      },
    };
  }
  if (c.operation !== "revoke") bad();
  exact(c, ["operation", "connection", "provision_event_id"]);
  return {
    key,
    command: {
      operation: "revoke",
      connection: reference(c.connection, 1),
      provision_event_id: id(c.provision_event_id),
    },
  };
}

function asAssignment(value: unknown, actor: string) {
  const o = exact(
    value,
    [
      "profile",
      "operation",
      "operator_actor_id",
      "operator_authority_revision",
      "recipient_actor_id",
      "recipient_authority_revision",
      "source",
      "connection",
      "state",
      "revision",
      "event_id",
    ],
    ["provision_event_id"],
  );
  const source = reference(o.source),
    connection = reference(o.connection, 1);
  const recipient = id(o.recipient_actor_id),
    event = id(o.event_id);
  const authority = integer(o.recipient_authority_revision);
  const operatorAuthority = integer(o.operator_authority_revision);
  if (
    o.profile !== "operator-provisioned-connection-v1" ||
    o.operator_actor_id !== actor ||
    recipient === actor ||
    source.id === connection.id ||
    source.hash !== connection.hash
  )
    bad();
  const fields = {
    source,
    connection,
    recipient,
    authority,
    operatorAuthority,
    event,
  };
  if (
    o.operation === "provision" &&
    o.state === "active" &&
    o.revision === 1 &&
    o.provision_event_id === undefined
  )
    return { ...fields, recorded: "assigned" as const, provisionEvent: event };
  if (
    o.operation === "revoke" &&
    o.state === "revoked" &&
    o.revision === 2 &&
    o.provision_event_id !== event
  )
    return {
      ...fields,
      recorded: "withdrawn" as const,
      provisionEvent: id(o.provision_event_id),
    };
  return bad();
}

export function asProvisionResult(
  value: unknown,
  session: Session,
  command: ProvisionCommand,
) {
  const o = exact(value, ["resource", "replayed"]);
  const receipt = asAssignment(o.resource, session.identity.actor_id);
  if (
    typeof o.replayed !== "boolean" ||
    (!o.replayed &&
      receipt.operatorAuthority !== session.identity.authority_revision)
  )
    bad();
  if (command.operation === "provision") {
    if (
      receipt.recorded !== "assigned" ||
      !sameRef(receipt.source, command.source) ||
      receipt.recipient !== command.recipient_actor_id ||
      receipt.authority !== command.recipient_authority_revision
    )
      bad();
  } else if (
    receipt.recorded !== "withdrawn" ||
    !sameRef(receipt.connection, command.connection) ||
    receipt.provisionEvent !== command.provision_event_id
  )
    bad();
  return { receipt, replayed: o.replayed };
}

function page<T>(
  value: unknown,
  field: string,
  parse: (v: unknown) => T,
  key: (v: T) => string,
) {
  const o = exact(value, [field], ["next"]),
    values = o[field];
  if (!Array.isArray(values) || values.length > 20) bad();
  const rows = values.map(parse);
  if (new Set(rows.map(key)).size !== rows.length) bad();
  const next = o.next === undefined ? "" : id(o.next);
  if (next && (rows.length !== 20 || key(rows[19]!) !== next)) bad();
  return { rows, next };
}

export function asProvisionSources(value: unknown) {
  const { connections, next } = asCollectionConnections(value);
  if (
    connections.length > 20 ||
    connections.some((c) => c.protocol !== undefined) ||
    (next && (connections.length !== 20 || connections[19]?.id !== next))
  )
    bad();
  return { rows: connections, next: next ?? "" };
}

export function asProvisionRecipients(value: unknown, actor: string) {
  return page(
    value,
    "recipients",
    (v): Recipient => {
      const o = exact(v, ["id", "label", "authority_revision"]);
      const recipient = id(o.id);
      if (
        recipient === actor ||
        typeof o.label !== "string" ||
        o.label.length > 128
      )
        bad();
      return {
        id: recipient,
        label: o.label,
        authority_revision: integer(o.authority_revision),
      };
    },
    (v) => v.id,
  );
}

export function asProvisionAssignments(value: unknown, actor: string) {
  return page(
    value,
    "assignments",
    (v) => asAssignment(v, actor),
    (v) => v.connection.id,
  );
}
