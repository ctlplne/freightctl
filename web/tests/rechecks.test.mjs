import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";
const bundle = await build({
  entryPoints: [new URL("../src/rechecks-types.ts", import.meta.url).pathname],
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const {
  parseRecheckPlan,
  parseRecheck,
  parseRecheckPreview,
  parseRecheckView,
  recheckFingerprint,
} = await import(
  "data:text/javascript;base64," +
    Buffer.from(bundle.outputFiles[0].contents).toString("base64")
);
const fixture = JSON.parse(
  await readFile(
    new URL("fixtures/recheck-definition.json", import.meta.url),
    "utf8",
  ),
);
const policies = JSON.parse(
  await readFile(
    new URL("fixtures/recheck-policies.json", import.meta.url),
    "utf8",
  ),
);
const expected = (
  await readFile(
    new URL("fixtures/recheck-golden.sha256", import.meta.url),
    "utf8",
  )
).trim();
const row = () => ({
  id: "00000030-1111-4111-8111-111111111111",
  source_file_id: fixture.plan.source.file.id,
  definition: structuredClone(fixture),
  definition_hash: expected,
  state: "proposed",
  revision: 1,
  new_file_id: "",
  result: {},
});
test("re-check immutable hash matches Go/Python including Unicode, HTML escapes, zero mode and worker lease", () => {
  assert.equal(recheckFingerprint(fixture), expected);
  assert.deepEqual(parseRecheckPlan(fixture.plan), fixture.plan);
  assert.equal(parseRecheck(row()).definition_hash, expected);
  assert.equal(
    parseRecheckPreview({
      plan: fixture.plan,
      ...policies,
      effects: "Create held bytes only",
    }).plan.reason,
    fixture.plan.reason,
  );
});
test("re-check review rejects changed source, policy, signature, slots and injected execution fields", () => {
  for (const mutate of [
    (r) => (r.definition.plan.source.file.sha256 = "f".repeat(64)),
    (r) => r.definition.plan.source.check.attempts++,
    (r) => (r.definition.plan.target.command.mode = 420),
    (r) => (r.definition.plan.policy.hash = "f".repeat(64)),
    (r) => (r.definition.plan.source.signature.data_sha256 = "f".repeat(64)),
    (r) => (r.definition.plan.source.check.lease_until = "not a date"),
    (r) =>
      (r.definition.staging_slots[1].signature_object_id =
        r.definition.staging_slots[0].signature_object_id),
    (r) =>
      (r.definition.staging_slots[0].signature_object_id = r.source_file_id),
    (r) => (r.definition.plan.run_shell = "untrusted"),
    (r) => (r.state = "released"),
    (r) => (r.revision = 4),
    (r) => (r.new_file_id = r.source_file_id),
  ]) {
    const r = row();
    mutate(r);
    assert.throws(() => parseRecheck(r));
  }
});
test("copied receipt binds held child, exact signature metadata and preserved source meaning", () => {
  const r = row(),
    slot = r.definition.staging_slots[0],
    p = r.definition.plan;
  r.state = "copied";
  r.revision = 3;
  r.new_file_id = slot.file_id;
  r.result = {
    kind: "file_recheck_copy",
    acceptance: "durable-held-pending-checks-and-release",
    file: {
      ...p.source.file,
      id: slot.file_id,
      policy: "intake-csv-v1:" + p.policy.hash,
    },
    signature: {
      ...p.source.signature,
      file_id: slot.file_id,
      object_id: slot.signature_object_id,
      policy_hash: p.policy.hash,
    },
  };
  assert.equal(parseRecheck(r).state, "copied");
  for (const mutate of [
    (x) => (x.result.signature.sha256 = "f".repeat(64)),
    (x) => x.result.signature.key.version++,
    (x) => (x.result.file.policy = p.source.file.policy),
    (x) => (x.result.acceptance = "released"),
    (x) => (x.result.signature.storage_id = x.id),
    (x) => (x.result.approved = true),
  ]) {
    const x = structuredClone(r);
    mutate(x);
    assert.throws(() => parseRecheck(x));
  }
});
test("private view verifies both policy definitions and preserves historical state", () => {
  const v = {
    kind: "file_recheck",
    recheck: row(),
    current: true,
    code: "current",
    previous_policy: policies.previous_policy,
    selected_policy: policies.current_policy,
  };
  assert.equal(parseRecheckView(v).current, true);
  for (const mutate of [
    (x) => x.previous_policy.definition.max_rows++,
    (x) => x.selected_policy.reference.version++,
    (x) => delete x.previous_policy,
    (x) => delete x.selected_policy,
    (x) => (x.code = "copied"),
  ]) {
    const x = structuredClone(v);
    mutate(x);
    assert.throws(() => parseRecheckView(x));
  }
  const historical = { ...v, current: false, code: "historical_or_changed" };
  assert.equal(parseRecheckView(historical).current, false);
});
