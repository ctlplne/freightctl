import test, { after } from "node:test";
import assert from "node:assert/strict";
import { readFile, writeFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";
import { fileURLToPath, pathToFileURL } from "node:url";
const bundle = await build({
  stdin: {
    contents:
      'export * from "./src/collection-handoffs-types"; export * from "./src/collection-routing-recovery"; export { asCollectionView, asCollectedRun, asCollectedWork, collectionWorkflowHash } from "./src/collections-types";',
    resolveDir: fileURLToPath(new URL("..", import.meta.url)),
    loader: "ts",
  },
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const scratch = await mkdtemp(join(tmpdir(), "freightctl-handoff-contract-"));
after(() => rm(scratch, { recursive: true }));
const modulePath = join(scratch, "contract.mjs");
await writeFile(modulePath, bundle.outputFiles[0].contents, { mode: 0o600 });
const p = await import(pathToFileURL(modulePath).href);
const fixture = JSON.parse(
  await readFile(
    new URL("fixtures/collection-handoffs.json", import.meta.url),
    "utf8",
  ),
);
const fresh = () => {
  const f = structuredClone(fixture);
  f.original = p.asCollectionView(
    f.original,
    f.original.job.id,
    f.selection.expected_authority_revision,
  );
  return f;
};
const view = (f) =>
  p.asCollectionView(
    f.view,
    f.view.job.id,
    f.selection.expected_authority_revision,
  );
const preview = (f) =>
  p.asCollectionHandoffPreview(f.preview, f.original, f.selection);
const metadata = (f) =>
  p.asCollectionHandoffView(f.metadata, view(f), f.completed.id);
test("actual PostgreSQL/Go handoff fingerprint, old and new compiler decisions, public identities and immutable assignment agree", () => {
  const f = fresh(),
    r = preview(f),
    m = metadata(f),
    v = view(f);
  assert.equal(
    p.collectionHandoffHash(r.definition),
    f.proposed.definition_hash,
  );
  assert.deepEqual(r.source_plan.selected_steps, ["first"]);
  assert.deepEqual(r.definition.plan.selected_steps, ["second"]);
  assert.equal(
    r.source_plan.facts.source.name,
    f.original.inputs[0].source_name,
  );
  assert.equal(m.effects[0].user, "receiver");
  assert.match(m.effects[0].key_fingerprint, /^SHA256:/);
  assert.equal(m.current_bindings, false);
  assert.equal(m.binding_reason, "completed");
  assert.equal(v.inputs[0].run_id, f.original.inputs[0].run_id);
  assert.equal(v.replacements[0].current_run_id, f.completed.planned_run_id);
  const i = v.inputs[0],
    d = v.job.definition,
    context = {
      job: v.job,
      workflow: r.source_workflow,
      handoff: { view: v, metadata: m },
    };
  const next = p.asCollectedRun(f.successor_run, i, d, context);
  assert.equal(next.run.id, f.completed.planned_run_id);
  assert.equal(next.run.execution_plan_hash, r.definition.plan_hash);
  const work = p.asCollectedWork(
    {
      replayed: true,
      dispatch: {
        run_id: next.run.id,
        step_id: next.steps[0].id,
        delivery_id: next.steps[0].delivery_id,
      },
      status: f.successor_run,
    },
    i,
    d,
    context,
  );
  assert.equal(work.run.id, next.run.id);
  assert.equal(i.run_id, f.original.inputs[0].run_id);
  assert.equal(
    p.asCollectedRun(f.original_run, i, d, {
      job: v.job,
      workflow: r.source_workflow,
    }).observed_state,
    "cancelled",
  );
  assert.throws(() => p.asCollectedRun(f.original_run, i, d, context));
});
test("original-key mutation receipts are bound to the reviewed definition, identity, state and revision", () => {
  const f = fresh(),
    r = preview(f);
  for (const [name, revision] of [
    ["proposed", 1],
    ["approved", 2],
    ["completed", 3],
  ]) {
    const raw = {
      resource: { kind: "workflow_collection_handoff", handoff: f[name] },
      replayed: true,
    };
    const expected = {
      hash: r.definition_hash,
      state: name,
      revision,
      id: f.proposed.id,
    };
    assert.equal(
      p.asCollectionHandoffResult(raw, f.original, r, expected).replayed,
      true,
    );
    for (const bad of [
      { ...expected, id: f.original.job.id },
      { ...expected, hash: "f".repeat(64) },
      { ...expected, revision: revision + 1 },
    ])
      assert.throws(() => p.asCollectionHandoffResult(raw, f.original, r, bad));
  }
});
test("a rehashed forged plan cannot replace original captured facts, compiler decisions or old intent bindings", () => {
  for (const mutate of [
    (f) => (f.preview.definition.plan.facts.source.name = "invented.csv"),
    (f) => (f.preview.definition.plan.facts.file.sha256 = "f".repeat(64)),
    (f) => (f.preview.definition.plan.selected_steps = ["first"]),
    (f) => (f.preview.definition.plan.decisions[0].step = "first"),
    (f) => (f.preview.definition.intents[0].ordinal = 2),
    (f) => (f.preview.definition.intents[0].step_id = "second"),
    (f) => f.preview.definition.intents.push(f.preview.definition.intents[0]),
    (f) => (f.preview.definition.collection.id = f.view.inputs[0].file_id),
    (f) => (f.preview.definition.collection.revision = f.view.job.revision + 1),
    (f) => (f.preview.definition.storage_id = f.view.inputs[0].file_id),
    (f) => f.preview.definition.authority_revision++,
    (f) => f.preview.source_plan.facts.source.index++,
    (f) => (f.preview.definition.source_run.plan_hash = "f".repeat(64)),
    (f) => (f.preview.definition.namespace_root = "/other"),
    (f) => (f.preview.definition.approved = true),
  ]) {
    const f = fresh();
    mutate(f);
    f.preview.definition_hash = p.collectionHandoffHash(f.preview.definition);
    assert.throws(() => preview(f));
  }
});
test("changed workflow source, catalog identities and unknown fields cannot enter handoff review", () => {
  for (const mutate of [
    (f) =>
      (f.preview.workflow.definition.source.manifest = "different.ready.json"),
    (f) => (f.preview.effects[0].connection.hash = "f".repeat(64)),
    (f) => (f.preview.effects[0].host_fingerprint = "invalid"),
    (f) => (f.preview.effects[0].key_fingerprint = "invalid"),
    (f) => (f.preview.effects[0].user = "\nreceiver"),
    (f) => (f.preview.effects[0].private_key = "injected"),
    (f) => (f.preview.source_effects = []),
    (f) => (f.preview.workflow.state = "draft"),
    (f) => (f.preview.external_contact = true),
    (f) => (f.preview.approval_required = false),
  ]) {
    const f = fresh();
    mutate(f);
    assert.throws(() => preview(f));
  }
  const f = fresh();
  f.preview.workflow.definition.source.target_directory = "/other";
  f.preview.workflow.definition_hash = p.collectionWorkflowHash(
    f.preview.workflow.definition,
  );
  f.preview.definition.workflow.hash = f.preview.workflow.definition_hash;
  f.selection.workflow.hash = f.preview.workflow.definition_hash;
  f.preview.definition_hash = p.collectionHandoffHash(f.preview.definition);
  assert.throws(() => preview(f));
});
test("successor view refuses invented or duplicate links and preserves deduplicated original-job lineage", () => {
  for (const mutate of [
    (r, f) => (r.input_id = f.view.job.id),
    (r, f) => (r.job_id = f.completed.id),
    (r, f) => (r.original_run_id = f.completed.planned_run_id),
    (r, f) => (r.current_run_id = r.original_run_id),
    (r, f) => (r.source_run_id = r.current_run_id),
    (r, f) => (r.authority = true),
  ]) {
    const f = fresh();
    mutate(f.view.replacements[0], f);
    assert.throws(() => view(f));
  }
  const f = fresh();
  f.view.replacements.push(f.view.replacements[0]);
  assert.throws(() => view(f));
  const dedup = fresh();
  dedup.view.job.id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const v = view(dedup);
  assert.equal(v.replacements[0].job_id, fixture.original.job.id);
  assert.equal(v.inputs[0].first_job_id, fixture.original.job.id);
  assert.throws(() =>
    p.asCollectionHandoffView(dedup.metadata, v, dedup.completed.id),
  );
});
test("completed and withdrawn history never become current authority; revoked metadata stays inspectable", () => {
  const f = fresh();
  f.metadata.current_bindings = true;
  assert.throws(() => metadata(f));
  const stale = fresh();
  stale.metadata.workflow.state = "revoked";
  stale.metadata.workflow.revision++;
  assert.equal(metadata(stale).workflow.state, "revoked");
  for (const mutate of [
    (f) => (f.metadata.handoff.source_run_id = f.completed.planned_run_id),
    (f) => (f.metadata.handoff.revision = 1),
    (f) => (f.metadata.binding_reason = "current"),
  ]) {
    const f = fresh();
    mutate(f);
    assert.throws(() => metadata(f));
  }
  const history = p.asCollectionHandoffHistory(
    { handoffs: [fixture.completed] },
    fixture.original,
  );
  assert.equal(history.handoffs[0].id, fixture.completed.id);
  assert.equal(history.handoffs[0].definition, undefined);
  assert.throws(() =>
    p.asCollectionHandoffHistory(
      { handoffs: [fixture.completed], next: fixture.completed.id },
      fixture.original,
    ),
  );
});
test("saved handoff nonces are scoped to actor, job, exact operation and body, without persisting plans", () => {
  const values = new Map();
  const storage = {
    get length() {
      return values.size;
    },
    key: (i) => [...values.keys()][i] ?? null,
    getItem: (k) => values.get(k) ?? null,
    setItem: (k, v) => values.set(k, v),
    removeItem: (k) => values.delete(k),
  };
  const identity = {
    tenant_id: "11111111-1111-4111-8111-111111111111",
    partner_id: "22222222-2222-4222-8222-222222222222",
    actor_id: "33333333-3333-4333-8333-333333333333",
  };
  const body = {
    definition_hash: fixture.completed.definition_hash,
    expected_revision: 2,
  };
  const ref = p.routingKeyReference(
    identity,
    fixture.view.job.id,
    "handoff_execute",
    fixture.completed.id,
    body,
  );
  const retained = p.retainRoutingKey(ref, storage);
  assert.equal(retained.persisted, true);
  assert.equal(p.savedRoutingKey(ref, storage), retained.key);
  for (const other of [
    p.routingKeyReference(
      { ...identity, actor_id: identity.partner_id },
      fixture.view.job.id,
      "handoff_execute",
      fixture.completed.id,
      body,
    ),
    p.routingKeyReference(
      identity,
      fixture.view.job.id,
      "handoff_approve",
      fixture.completed.id,
      body,
    ),
    p.routingKeyReference(
      identity,
      fixture.view.job.id,
      "handoff_execute",
      fixture.completed.id,
      { ...body, expected_revision: 1 },
    ),
  ])
    assert.equal(p.savedRoutingKey(other, storage), undefined);
  assert.equal(
    [...values.values()].some((v) =>
      v.includes(fixture.completed.definition_hash),
    ),
    false,
  );
  p.forgetRoutingKey(ref, storage);
  assert.equal(p.savedRoutingKey(ref, storage), undefined);
});
