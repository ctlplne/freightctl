import assert from "node:assert/strict";
import { test } from "node:test";
import { build } from "esbuild";
const built = await build({
  entryPoints: [
    new URL("../src/processing-output-types.ts", import.meta.url).pathname,
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
const actor = "11111111-1111-4111-8111-111111111111";
const session = { identity: { actor_id: actor } };
const row = {
  id: "22222222-2222-4222-8222-222222222222",
  version: 1,
  definition_hash: "a".repeat(64),
  state: "output_active",
  revision: 1,
  producer_id: actor,
  producer_binding_current_at_observation: true,
  kind: "json_records",
  column_count: 3,
};
const page = {
  profile: "producer-processing-output-policy-v1",
  policies: [row],
};
test("output contract discovery keeps only this producer's current supported contracts", () => {
  const mixed = structuredClone(page);
  mixed.policies.push({
    ...row,
    id: "33333333-3333-4333-8333-333333333333",
    producer_id: "44444444-4444-4444-8444-444444444444",
  });
  mixed.policies.push({
    ...row,
    id: "55555555-5555-4555-8555-555555555555",
    producer_binding_current_at_observation: false,
  });
  const result = p.processingOutputCatalog(mixed, session);
  assert.equal(result.policies.length, 1);
  assert.deepEqual(result.policies[0].reference, {
    id: row.id,
    version: row.version,
    hash: row.definition_hash,
  });
  assert.equal(JSON.stringify(result).includes("producer_id"), false);
  for (const mutate of [
    (x) => (x.profile = "invented"),
    (x) => (x.policies[0].revision = 2),
    (x) => (x.policies[0].state = "output_revoked"),
    (x) => (x.policies[0].producer_binding_current_at_observation = "true"),
    (x) => (x.policies[0].approved = true),
    (x) => (x.policies[0].definition_hash = "invalid"),
    (x) => (x.next = "private-path"),
  ]) {
    const bad = structuredClone(page);
    mutate(bad);
    assert.throws(() => p.processingOutputCatalog(bad, session));
  }
});
