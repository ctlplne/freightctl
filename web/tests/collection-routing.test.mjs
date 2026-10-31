import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const bundle = await build({
  stdin: {
    contents:
      'export * from "./src/collection-routing-types"; export { asCollectionView, asCollectionConfiguration } from "./src/collections-types"; export { programFingerprint } from "./src/programs-types";',
    resolveDir: fileURLToPath(new URL("..", import.meta.url)),
    loader: "ts",
  },
  bundle: true,
  write: false,
  format: "esm",
  platform: "browser",
  target: "es2022",
});
const p = await import(
  "data:text/javascript;base64," +
    Buffer.from(bundle.outputFiles[0].contents).toString("base64")
);
const fixtures = JSON.parse(
  await readFile(
    new URL("fixtures/collection-routing.json", import.meta.url),
    "utf8",
  ),
);
const fresh = (name = "send") => {
  const f = structuredClone(fixtures[name]);
  f.view = p.asCollectionView(
    f.view,
    f.view.job.id,
    f.selection.expected_authority_revision,
  );
  f.workflow = p.asCollectionConfiguration(f.workflow);
  return f;
};
const preview = (f) =>
  p.asCapturedRoutingPreview(
    f.preview,
    f.view,
    f.selection,
    f.workflow,
    f.prior,
  );
const inputPreview = (f) =>
  p.asCapturedRoutingInputPreview(
    f.input_preview,
    f.view.inputs[0].id,
    f.view,
    f.workflow,
    f.preview.definition,
  );

test("Go fingerprints, exact original facts and independent browser decisions agree for send and local outcomes", () => {
  for (const name of ["send", "local"]) {
    const f = fresh(name),
      reviewed = preview(f),
      plan = inputPreview(f);
    assert.equal(
      p.capturedRoutingHash(reviewed.definition),
      f.preview.definition_hash,
    );
    assert.equal(
      plan.execution_plan_hash,
      reviewed.definition.inputs[0].plan_hash,
    );
    assert.equal(plan.execution_plan.facts.source.collection_id, f.view.job.id);
    assert.equal(
      plan.execution_plan.facts.source.manifest_hash,
      f.view.job.manifest_hash,
    );
    assert.equal(
      plan.execution_plan.facts.source.name,
      f.view.inputs[0].source_name,
    );
    assert.equal(plan.external_contact, false);
    assert.equal(
      p.asCapturedRoutingRecord(f.authorization, f.view).state,
      "proposed",
    );
    if (name === "local") {
      assert.deepEqual(plan.selected_effects, []);
      assert.equal(plan.execution_plan.local_reason, "reviewed_local_outcome");
      assert.equal(reviewed.definition.previous.id, f.prior.id);
    } else {
      assert.deepEqual(
        plan.selected_effects.map((x) => x.step_id),
        ["send"],
      );
      assert.equal(reviewed.definition.previous, undefined);
    }
  }
});

test("rehashing cannot replace capture identity, target revision, authority or complete owned-input bindings", () => {
  for (const mutate of [
    (d) => d.collection.revision++,
    (d) => (d.collection.definition_hash = "f".repeat(64)),
    (d) => (d.collection.id = d.storage_id),
    (d) => d.original_workflow.version++,
    (d) => d.workflow.version++,
    (d) => (d.workflow.hash = "f".repeat(64)),
    (d) => (d.manifest_hash = "f".repeat(64)),
    (d) => d.authority_revision++,
    (d) => (d.storage_id = d.collection.id),
    (d) => (d.namespace_root = "/other"),
    (d) => (d.inputs[0].file_id = d.storage_id),
    (d) => (d.inputs[0].input_id = d.storage_id),
    (d) => d.inputs.push(structuredClone(d.inputs[0])),
    (d) => (d.extend_deadline = true),
  ]) {
    const f = fresh();
    mutate(f.preview.definition);
    f.preview.definition_hash = p.capturedRoutingHash(f.preview.definition);
    assert.throws(() => preview(f));
  }
  for (const mutate of [
    (f) => (f.view.inputs[0].state = "queued"),
    (f) => (f.view.inputs[0].run_id = f.view.job.id),
    (f) => (f.view.local_states[0].state = "held_or_unavailable"),
    (f) => (f.view.current_authority = false),
    (f) => (f.workflow.state = "revoked"),
    (f) => f.workflow.approval_authority++,
    (f) => (f.preview.external_contact = true),
    (f) => (f.preview.approval_required = false),
  ]) {
    const f = fresh();
    mutate(f);
    assert.throws(() => preview(f));
  }
});

test("a changed prior decision makes the proposal stale even if a caller recomputes its fingerprint", () => {
  for (const mutate of [
    (f) => {
      f.prior.state = "revoked";
      f.prior.revision = 3;
    },
    (f) => {
      f.prior.id = f.view.job.id;
    },
    (f) => {
      f.preview.definition.previous.revision++;
      f.preview.definition_hash = p.capturedRoutingHash(f.preview.definition);
    },
    (f) => {
      delete f.preview.definition.previous;
      f.preview.definition_hash = p.capturedRoutingHash(f.preview.definition);
    },
  ]) {
    const f = fresh("local");
    mutate(f);
    assert.throws(() => preview(f));
  }
});

test("self-consistent plan and authorization hashes cannot invent source facts or select another recipient", () => {
  for (const mutate of [
    (p) => (p.facts.source.name = "invented.csv"),
    (p) => (p.facts.source.collection_id = p.facts.file.id),
    (p) => (p.facts.source.manifest_hash = "f".repeat(64)),
    (p) => (p.facts.source.batch_id = p.facts.file.id),
    (p) => p.facts.source.index++,
    (p) => p.facts.source.file_count++,
    (p) => (p.selected_steps = ["another_receiver"]),
    (p) => (p.local_reason = "invented_exception"),
  ]) {
    const f = fresh();
    mutate(f.input_preview.execution_plan);
    const forged = p.programFingerprint(f.input_preview.execution_plan);
    f.input_preview.execution_plan_hash = forged;
    f.preview.definition.inputs[0].plan_hash = forged;
    f.preview.definition_hash = p.capturedRoutingHash(f.preview.definition);
    assert.throws(() => inputPreview(f));
  }
  for (const mutate of [
    (f) => (f.input_preview.source.sha256 = "f".repeat(64)),
    (f) => f.input_preview.source.size_bytes++,
    (f) => f.input_preview.workflow.version++,
    (f) =>
      (f.input_preview.selected_effects[0].connection.hash = "f".repeat(64)),
    (f) =>
      f.input_preview.potential_effects.push(
        structuredClone(f.input_preview.potential_effects[0]),
      ),
    (f) => (f.input_preview.external_contact = true),
    (f) => (f.preview.definition.inputs[0].plan_hash = "f".repeat(64)),
  ]) {
    const f = fresh();
    mutate(f);
    assert.throws(() => inputPreview(f));
  }
});

test("approval records retain fixed lifecycle, acyclic prior decisions and private job identity", () => {
  for (const mutate of [
    (r) => (r.job_id = r.id),
    (r) => (r.definition_hash = "f".repeat(64)),
    (r) => r.revision++,
    (r) => (r.state = "executed"),
    (r) => (r.approval_authority = 3),
    (r) => (r.version = 2147483648),
    (r) => (r.definition.inputs[0].plan_hash = "f".repeat(64)),
    (r) => (r.hidden_recipient = true),
  ]) {
    const f = fresh();
    mutate(f.authorization);
    assert.throws(() => p.asCapturedRoutingRecord(f.authorization, f.view));
  }
  const f = fresh("local");
  f.authorization.version = f.authorization.definition.previous.version;
  assert.throws(() => p.asCapturedRoutingRecord(f.authorization, f.view));
});

test("history is bounded, version ordered and correlated to one original job", () => {
  const f = fresh("local"),
    page = { authorizations: [f.prior, f.authorization], next: 2 };
  assert.equal(p.asCapturedRoutingHistory(page, f.view, 0, 2).next, 2);
  for (const mutate of [
    (x) => x.authorizations.reverse(),
    (x) => (x.authorizations[1].id = x.authorizations[0].id),
    (x) => (x.next = 1),
    (x) => (x.next = 2147483648),
    (x) => (x.authorizations[1].job_id = x.authorizations[1].id),
  ]) {
    const bad = structuredClone(page);
    mutate(bad);
    assert.throws(() => p.asCapturedRoutingHistory(bad, f.view, 0, 2));
  }
  assert.throws(() => p.asCapturedRoutingHistory(page, f.view, 1, 2));
  assert.throws(() => p.asCapturedRoutingHistory(page, f.view, 0, 1));
  assert.throws(() =>
    p.asCapturedRoutingHistory({ authorizations: [], next: 2 }, f.view, 0, 2),
  );
});

test("original-key receipts bind exact record, job, fingerprint, state and revision across response loss", () => {
  const f = fresh(),
    a = f.authorization;
  const action = {
    kind: "workflow_collection_routing",
    id: a.id,
    job_id: a.job_id,
    version: a.version,
    definition_hash: a.definition_hash,
    state: a.state,
    revision: a.revision,
  };
  const expected = {
    job: a.job_id,
    hash: a.definition_hash,
    state: "proposed",
    revision: 1,
    version: a.version,
    id: a.id,
  };
  for (const replayed of [false, true])
    assert.deepEqual(
      p.asCapturedRoutingResult({ resource: action, replayed }, expected)
        .resource,
      action,
    );
  for (const mutate of [
    (a) => (a.id = f.view.job.id),
    (a) => (a.job_id = a.id),
    (a) => (a.definition_hash = "f".repeat(64)),
    (a) => a.version++,
    (a) => a.revision++,
    (a) => (a.state = "approved"),
    (a) => (a.kind = "workflow_run"),
  ]) {
    const r = structuredClone(action);
    mutate(r);
    assert.throws(() =>
      p.asCapturedRoutingResult({ resource: r, replayed: true }, expected),
    );
  }
});

test("64 input fingerprints fit the unchanged budget and unknown fields or ambiguous ownership fail closed", () => {
  const f = fresh(),
    d = structuredClone(f.preview.definition);
  d.inputs = Array.from({ length: 64 }, (_, i) => ({
    input_id: `00000000-0000-0000-0000-${String(i + 100).padStart(12, "0")}`,
    file_id: `00000000-0000-0000-0000-${String(i + 200).padStart(12, "0")}`,
    plan_hash: "e".repeat(64),
  }));
  assert.equal(p.asCapturedRoutingDefinition(d).inputs.length, 64);
  d.inputs.push({
    input_id: "00000000-0000-0000-0000-000000000999",
    file_id: "00000000-0000-0000-0000-000000000998",
    plan_hash: "e".repeat(64),
  });
  assert.throws(() => p.asCapturedRoutingDefinition(d));
  for (const mutate of [
    (d) => d.inputs.push(structuredClone(d.inputs[0])),
    (d) => (d.inputs[0].file_id = "../outside"),
    (d) => (d.authority_revision = Number.MAX_SAFE_INTEGER + 1),
    (d) =>
      (d.previous = {
        id: d.collection.id,
        version: 1,
        definition_hash: d.manifest_hash,
        revision: 0,
      }),
    (d) => (d.expires_at = "later"),
  ]) {
    const d = structuredClone(f.preview.definition);
    mutate(d);
    assert.throws(() => p.asCapturedRoutingDefinition(d));
  }
});

test("stopped capture history stays inspectable while its old proposal cannot become current execution authority", () => {
  const f = fresh();
  f.view.job.state = "cancelled";
  f.view.job.revision++;
  f.view.current_authority = false;
  f.view.observed_state = "cancelled";
  assert.equal(
    p.asCapturedRoutingRecord(f.authorization, f.view).definition_hash,
    f.authorization.definition_hash,
  );
  assert.throws(() => preview(f));
});
