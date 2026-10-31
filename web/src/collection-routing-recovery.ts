import { ApiError, type Identity } from "./types";
import { operationKey, digestBytes } from "./crypto";
import { canonicalWorkflowBytes } from "./schedules-types";

type KeyStorage = Pick<
  Storage,
  "getItem" | "setItem" | "removeItem" | "key" | "length"
>;
const memory = new Map<string, string>();
const validKey = (v: unknown): v is string =>
  typeof v === "string" && /^[A-Za-z0-9._:-]{1,128}$/.test(v);

// Persist only an opaque command nonce under a scoped request fingerprint.
// Neither credentials, file names, plans nor request bodies go into storage.
export function routingKeyReference(
  identity: Identity,
  job: string,
  operation: string,
  record: string,
  body: unknown,
): string {
  return (
    `freightctl:routing:${identity.tenant_id}:${identity.partner_id}:${identity.actor_id}:${job}:` +
    digestBytes(canonicalWorkflowBytes({ operation, record, body }))
  );
}

export function savedRoutingKey(
  reference: string,
  storage?: KeyStorage,
): string | undefined {
  try {
    const value = storage?.getItem(reference);
    if (validKey(value)) return value;
  } catch {
    /* Memory retains the key while the current review stays open. */
  }
  return memory.get(reference);
}

export function retainRoutingKey(
  reference: string,
  storage?: KeyStorage,
): { key: string; persisted: boolean } {
  const prior = savedRoutingKey(reference, storage);
  const key = prior ?? operationKey();
  if (!memory.has(reference) && memory.size >= 64)
    throw new ApiError("pending_routing_commands_limit", 409);
  memory.set(reference, key);
  let persisted = false;
  try {
    if (storage) {
      let pending = 0;
      const prefix = reference.slice(0, reference.lastIndexOf(":") + 1);
      for (let i = 0; i < storage.length; i++)
        if (storage.key(i)?.startsWith(prefix)) pending++;
      if (!prior && pending >= 16)
        throw new ApiError("pending_routing_commands_limit", 409);
      storage.setItem(reference, key);
      persisted = storage.getItem(reference) === key;
    }
  } catch (error) {
    if (error instanceof ApiError) throw error;
  }
  return { key, persisted };
}

export function forgetRoutingKey(
  reference: string,
  storage?: KeyStorage,
): void {
  memory.delete(reference);
  try {
    storage?.removeItem(reference);
  } catch {
    /* No execution authority is stored. */
  }
}
