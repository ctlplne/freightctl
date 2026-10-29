import { ApiError, object, uuid } from "./types";
import { digestBytes } from "./crypto";

export interface OnboardingContact {
  id: string;
  name: string;
  role: string;
  email: string;
  phone: string;
}
export interface OnboardingRequirement {
  id: string;
  name: string;
  contact_id: string;
  direction: string;
  protocol: string;
  required_receipt: string;
  receipt_contract: string;
  notes: string;
}
export interface OnboardingDefinition {
  schema_version: 1;
  name: string;
  contacts: OnboardingContact[];
  requirements: OnboardingRequirement[];
}
export interface OnboardingCommand {
  plan_id: string;
  expected_version: number;
  expected_authority_revision: number;
  definition: OnboardingDefinition;
}
export interface OnboardingSummary {
  id: string;
  version: number;
  definition_hash: string;
  state: "draft";
  name: string;
  author_id: string;
  event_id: string;
  created_at: string;
}
export interface OnboardingPlan extends OnboardingSummary {
  definition: OnboardingDefinition;
}
export const onboardingProtocols = [
  "sftp",
  "https",
  "ftps-explicit",
  "ftps-implicit",
  "webdav",
  "as1",
  "as2",
  "as3",
  "as4",
  "oftp2",
  "pesit",
  "smtp",
  "queue",
  "other",
];
const invalid = (): never => {
  throw new ApiError("invalid_server_response", 502);
};
function text(
  o: Record<string, unknown>,
  key: string,
  maximum: number,
  required = false,
  multiline = false,
): string {
  const v = o[key];
  if (
    typeof v !== "string" ||
    new TextEncoder().encode(v).length > maximum ||
    (required && v.length === 0) ||
    (!multiline && v !== v.trim()) ||
    v !== v.normalize("NFC") ||
    /[\ud800-\udfff]/u.test(v) ||
    (multiline
      ? /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/
      : /[\u0000-\u001f\u007f-\u009f]/
    ).test(v)
  )
    invalid();
  return v as string;
}
function id(o: Record<string, unknown>, key: string): string {
  const v = text(o, key, 36, true);
  if (!uuid(v)) invalid();
  return v;
}
function number(
  o: Record<string, unknown>,
  key: string,
  positive = false,
): number {
  const v = o[key];
  if (
    typeof v !== "number" ||
    !Number.isSafeInteger(v) ||
    v < (positive ? 1 : 0)
  )
    invalid();
  return v as number;
}
function list(o: Record<string, unknown>, key: string, max: number): unknown[] {
  const v = o[key];
  if (!Array.isArray(v) || v.length > max) invalid();
  return v as unknown[];
}
export function asOnboardingDefinition(value: unknown): OnboardingDefinition {
  const o = object(value);
  if (o.schema_version !== 1) invalid();
  const contacts = list(o, "contacts", 64).map((raw) => {
    const c = object(raw);
    return {
      id: id(c, "id"),
      name: text(c, "name", 128, true),
      role: text(c, "role", 64, true),
      email: text(c, "email", 254, true),
      phone: text(c, "phone", 64),
    };
  });
  const ids = new Set(contacts.map((c) => c.id));
  if (!contacts.length || ids.size !== contacts.length) invalid();
  const requirements = list(o, "requirements", 64).map((raw) => {
    const r = object(raw);
    const result = {
      id: id(r, "id"),
      name: text(r, "name", 128, true),
      contact_id: id(r, "contact_id"),
      direction: text(r, "direction", 16, true),
      protocol: text(r, "protocol", 32, true),
      required_receipt: text(r, "required_receipt", 16, true),
      receipt_contract: text(r, "receipt_contract", 512, false, true),
      notes: text(r, "notes", 2048, false, true),
    };
    if (
      !ids.has(result.contact_id) ||
      !["send", "receive"].includes(result.direction) ||
      !onboardingProtocols.includes(result.protocol) ||
      !["transport", "integrity", "business"].includes(result.required_receipt)
    )
      invalid();
    return result;
  });
  if (
    !requirements.length ||
    new Set(requirements.map((r) => r.id)).size !== requirements.length
  )
    invalid();
  const d: OnboardingDefinition = {
    schema_version: 1,
    name: text(o, "name", 128, true),
    contacts,
    requirements,
  };
  if (
    new TextEncoder().encode(
      JSON.stringify(d).replace(
        /[<>&\u2028\u2029]/g,
        (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`,
      ),
    ).length >
    24 * 1024
  )
    invalid();
  return d;
}
export function onboardingFingerprint(
  definition: OnboardingDefinition,
): string {
  // Match Go's fixed struct-field ordering and encoding/json HTML escaping.
  const canonical = JSON.stringify(asOnboardingDefinition(definition)).replace(
    /[<>&\u2028\u2029]/g,
    (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
  const bytes = new TextEncoder().encode(canonical);
  try {
    return digestBytes(bytes);
  } finally {
    bytes.fill(0);
  }
}
export function asOnboardingSummary(value: unknown): OnboardingSummary {
  const o = object(value),
    hash = text(o, "definition_hash", 64, true),
    when = text(o, "created_at", 64, true);
  if (
    o.state !== "draft" ||
    !/^[0-9a-f]{64}$/.test(hash) ||
    !Number.isFinite(Date.parse(when))
  )
    invalid();
  return {
    id: id(o, "id"),
    version: number(o, "version", true),
    definition_hash: hash,
    state: "draft",
    name: text(o, "name", 128, true),
    author_id: id(o, "author_id"),
    event_id: id(o, "event_id"),
    created_at: when,
  };
}
export function asOnboardingPlan(value: unknown): OnboardingPlan {
  const o = object(value),
    summary = asOnboardingSummary(o),
    definition = asOnboardingDefinition(o.definition);
  if (
    summary.name !== definition.name ||
    summary.definition_hash !== onboardingFingerprint(definition)
  )
    invalid();
  return { ...summary, definition };
}
export function asOnboardingPage(value: unknown): {
  plans: OnboardingSummary[];
  authority_revision: number;
  next?: string;
} {
  const o = object(value);
  return {
    plans: list(o, "plans", 100).map(asOnboardingSummary),
    authority_revision: number(o, "authority_revision", true),
    ...(o.next !== undefined ? { next: id(o, "next") } : {}),
  };
}
export function asOnboardingView(value: unknown): {
  plan: OnboardingPlan;
  authority_revision: number;
} {
  const o = object(value);
  return {
    plan: asOnboardingPlan(o.plan),
    authority_revision: number(o, "authority_revision", true),
  };
}
export function asOnboardingResult(
  value: unknown,
  command: OnboardingCommand,
  actor: string,
): OnboardingPlan {
  const o = object(value),
    p = asOnboardingPlan(o.plan);
  if (
    typeof o.replayed !== "boolean" ||
    p.id !== command.plan_id ||
    p.version !== command.expected_version + 1 ||
    p.author_id !== actor ||
    p.definition_hash !== onboardingFingerprint(command.definition) ||
    JSON.stringify(p.definition) !==
      JSON.stringify(asOnboardingDefinition(command.definition))
  )
    invalid();
  return p;
}
