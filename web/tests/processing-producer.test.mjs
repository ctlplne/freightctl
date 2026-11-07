import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { build } from "esbuild";
const built = await build({
  entryPoints: [
    new URL("../src/processing-types.ts", import.meta.url).pathname,
  ],
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const p = await import(
  "data:text/javascript;base64," +
    Buffer.from(built.outputFiles[0].contents).toString("base64")
);
const id = (n) =>
  `${String(n).repeat(8)}-${String(n).repeat(4)}-4${String(n).repeat(3)}-8${String(n).repeat(3)}-${String(n).repeat(12)}`;
const actor = {
  tenant_id: id(1),
  partner_id: id(2),
  actor_id: id(3),
  authority_revision: 7,
  root_policy_digest: createHash("sha256").update("/processor").digest("hex"),
};
const session = { identity: actor };
const ref = { id: id(4), version: 2, hash: "a".repeat(64) };
const context = {
  namespace_root: "/processor",
  authority_revision: 7,
  policy: ref,
};
const binding = {
  profile: "producer-processing-output-policy-v1",
  policy_id: ref.id,
  policy_version: ref.version,
  policy_hash: ref.hash,
  publisher_id: id(5),
  producer: actor,
};
const plan = {
  schema_version: 3,
  profile: "producer-record-projection-v1",
  output_binding: binding,
};
test("browser pins the selected producer policy and current participant without reinterpreting legacy review", () => {
  assert.deepEqual(p.processingPlanProfile(plan, context, session), plan);
  assert.deepEqual(
    p.processingPlanProfile(
      { schema_version: 2, profile: "scoped-record-projection-v1" },
      context,
      session,
    ),
    { schema_version: 2, profile: "scoped-record-projection-v1" },
  );
  for (const mutate of [
    (x) => (x.schema_version = 2),
    (x) => (x.profile = "scoped-record-projection-v1"),
    (x) => (x.output_binding.producer.actor_id = id(6)),
    (x) => x.output_binding.producer.authority_revision++,
    (x) => (x.output_binding.producer.root_policy_digest = "f".repeat(64)),
    (x) => x.output_binding.policy_version++,
    (x) => (x.output_binding.policy_hash = "f".repeat(64)),
    (x) => (x.output_binding.approved = true),
    (x) => (x.output_binding.producer.permissions = ["admin"]),
  ]) {
    const changed = structuredClone(plan);
    mutate(changed);
    assert.throws(() => p.processingPlanProfile(changed, context, session));
  }
});
