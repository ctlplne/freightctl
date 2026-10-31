import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const bundle = await build({
  stdin: {
    contents:
      'export * from "./src/collection-routing-types"; export * from "./src/collection-routing-recovery"; export { asCollectionView, asCollectionConfiguration, asCollectedRun, asCollectedWork, asCollectionRunPreview } from "./src/collections-types"; export { programFingerprint } from "./src/programs-types";',
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
const legacy = JSON.parse(
  await readFile(new URL("fixtures/collections.json", import.meta.url), "utf8"),
).plain;
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

function metadataFixture(name = "send") {
  const f = fresh(name),
    record = structuredClone(f.authorization);
  record.state = "approved";
  record.revision = 2;
  record.approval_authority = f.selection.expected_authority_revision;
  return {
    ...f,
    metadata: {
      authorization: record,
      workflow: f.workflow,
      effects: f.input_preview.potential_effects,
      current_authority: true,
    },
  };
}
function authorizedRun(name = "send") {
  const f = metadataFixture(name),
    status = structuredClone(legacy.run),
    input = f.view.inputs[0];
  input.state = "queued";
  input.run_id = status.run.id;
  Object.assign(status.run, {
    workflow_id: f.workflow.id,
    workflow_version: f.workflow.version,
    workflow_hash: f.workflow.definition_hash,
    routing_authorization_id: f.authorization.id,
    execution_plan: f.input_preview.execution_plan,
    execution_plan_hash: f.input_preview.execution_plan_hash,
  });
  if (name === "local") {
    status.steps = [];
    status.observed_state = "kept_local";
    status.run.state = "kept_local";
  }
  const context = {
    workflow: legacy.workflow,
    job: f.view.job,
    routing: { view: f.view, metadata: f.metadata },
  };
  return { ...f, status, input, context };
}

test("effective metadata keeps pending proposals distinct and retains revoked target history", () => {
  const f = metadataFixture();
  assert.equal(
    p.asCapturedRoutingMetadata(f.metadata, f.view).current_authority,
    true,
  );
  const pending = {
    authorization: null,
    effects: [],
    current_authority: false,
    proposal: f.authorization,
  };
  assert.equal(
    p.asCapturedRoutingMetadata(pending, f.view).proposal.state,
    "proposed",
  );
  f.metadata.authorization.state = "revoked";
  f.metadata.authorization.revision = 3;
  f.metadata.workflow.state = "revoked";
  f.metadata.workflow.revision++;
  f.metadata.current_authority = false;
  const historical = p.asCapturedRoutingMetadata(
    f.metadata,
    f.view,
    f.authorization.id,
  );
  assert.equal(historical.authorization.state, "revoked");
  assert.equal(historical.workflow.definition_hash, f.workflow.definition_hash);
  assert.deepEqual(historical.effects, f.input_preview.potential_effects);
  for (const mutate of [
    (m) => (m.current_authority = true),
    (m) => (m.workflow.definition_hash = "f".repeat(64)),
    (m) => (m.effects[0].connection.hash = "f".repeat(64)),
    (m) => (m.proposal = m.authorization),
    (m) => (m.key_reference = "/private/key"),
  ]) {
    const m = structuredClone(f.metadata);
    mutate(m);
    assert.throws(() => p.asCapturedRoutingMetadata(m, f.view));
  }
  assert.throws(() =>
    p.asCapturedRoutingMetadata(
      {
        authorization: null,
        effects: f.metadata.effects,
        current_authority: false,
      },
      f.view,
    ),
  );
});

test("run inspection and work preserve exact authorization, target workflow and original plan lineage", () => {
  const f = authorizedRun();
  const result = p.asCollectedRun(
    f.status,
    f.input,
    f.view.job.definition,
    f.context,
  );
  assert.equal(result.run.routing_authorization_id, f.authorization.id);
  assert.equal(result.run.workflow_version, f.workflow.version);
  assert.equal(
    result.run.execution_plan_hash,
    f.preview.definition.inputs[0].plan_hash,
  );
  assert.equal(
    result.run.execution_plan.facts.source.collection_id,
    f.view.job.id,
  );
  const work = {
    status: f.status,
    dispatch: {
      run_id: f.status.run.id,
      step_id: f.status.steps[0].id,
      delivery_id: f.status.steps[0].delivery_id,
    },
    replayed: true,
  };
  assert.equal(
    p.asCollectedWork(work, f.input, f.view.job.definition, f.context).run
      .routing_authorization_id,
    f.authorization.id,
  );
  assert.equal(
    p.asCollectionRunPreview(
      f.input_preview,
      f.input,
      f.view.job.definition,
      f.context,
    ).execution_plan_hash,
    result.run.execution_plan_hash,
  );
});

test("a dropped or substituted routing reference cannot hide behind matching file and workflow facts", () => {
  for (const mutate of [
    (f) => delete f.status.run.routing_authorization_id,
    (f) => (f.status.run.routing_authorization_id = f.view.job.id),
    (f) => (f.status.run.execution_plan_hash = "f".repeat(64)),
    (f) => f.status.run.workflow_version--,
    (f) => (f.status.run.workflow_hash = f.view.job.workflow_hash),
    (f) =>
      (f.context.routing.metadata.authorization.definition_hash = "f".repeat(
        64,
      )),
    (f) => (f.context.routing.view.job.manifest_hash = "f".repeat(64)),
    (f) => (f.status.run.source.sha256 = "f".repeat(64)),
  ]) {
    const f = authorizedRun();
    mutate(f);
    assert.throws(() =>
      p.asCollectedRun(f.status, f.input, f.view.job.definition, f.context),
    );
  }
  // The unchanged legacy workflow/file references would previously discard
  // an extra authorization field. Legacy contexts now explicitly refuse it.
  const r = structuredClone(legacy.run),
    input = structuredClone(legacy.view.inputs[0]);
  r.run.routing_authorization_id = fixtures.send.authorization.id;
  assert.throws(() => p.asCollectedRun(r, input, legacy.view.job.definition));
});

test("revoked local outcomes remain inspectable without current execution permission", () => {
  const f = authorizedRun("local");
  f.context.routing.metadata.authorization.state = "revoked";
  f.context.routing.metadata.authorization.revision = 3;
  f.context.routing.metadata.current_authority = false;
  f.context.routing.metadata.workflow.state = "revoked";
  const r = p.asCollectedRun(
    f.status,
    f.input,
    f.view.job.definition,
    f.context,
  );
  assert.equal(r.observed_state, "kept_local");
  assert.deepEqual(r.steps, []);
  assert.equal(r.run.routing_authorization_id, f.authorization.id);
});

function keyStorage() {
  const data = new Map();
  return {
    getItem: (k) => data.get(k) ?? null,
    setItem: (k, v) => data.set(k, v),
    removeItem: (k) => data.delete(k),
    key: (i) => [...data.keys()][i] ?? null,
    get length() {
      return data.size;
    },
    data,
  };
}
const identity = {
  tenant_id: "00000001-1111-4111-8111-111111111111",
  partner_id: "00000002-1111-4111-8111-111111111111",
  actor_id: "00000003-1111-4111-8111-111111111111",
};

test("reload recovery stores only scoped nonces and reuses the same key for the exact reviewed command", () => {
  const f = fresh(),
    store = keyStorage(),
    body = {
      selection: f.selection,
      definition_hash: f.preview.definition_hash,
    };
  const ref = p.routingKeyReference(
    identity,
    f.view.job.id,
    "propose",
    "",
    body,
  );
  const first = p.retainRoutingKey(ref, store),
    next = p.retainRoutingKey(ref, store);
  assert.equal(first.persisted, true);
  assert.equal(next.key, first.key);
  assert.equal(p.savedRoutingKey(ref, store), first.key);
  const stored = JSON.stringify([...store.data]);
  for (const text of [
    f.view.inputs[0].source_name,
    "selection",
    "definition_hash",
    "execution_plan",
    "credential",
    f.workflow.definition.name,
  ])
    assert.equal(stored.includes(text), false);
  for (const mutate of [
    (x) => (x.actor_id = f.view.job.id),
    (x) => (x.partner_id = f.view.job.id),
    (x) => (x.tenant_id = f.view.job.id),
  ]) {
    const other = { ...identity };
    mutate(other);
    assert.notEqual(
      p.routingKeyReference(other, f.view.job.id, "propose", "", body),
      ref,
    );
  }
  assert.notEqual(
    p.routingKeyReference(
      identity,
      f.view.job.id,
      "approve",
      f.authorization.id,
      body,
    ),
    ref,
  );
  assert.notEqual(
    p.routingKeyReference(identity, f.view.job.id, "propose", "", {
      ...body,
      definition_hash: "f".repeat(64),
    }),
    ref,
  );
  p.forgetRoutingKey(ref, store);
  assert.equal(store.data.size, 0);
  assert.equal(p.savedRoutingKey(ref, store), undefined);
});

test("untrusted or unavailable browser storage cannot inject command bodies or discard an in-flight key", () => {
  const f = fresh(),
    store = keyStorage(),
    ref = p.routingKeyReference(
      identity,
      f.view.job.id,
      "withdraw",
      f.authorization.id,
      {
        definition_hash: f.authorization.definition_hash,
        expected_revision: 1,
      },
    );
  store.setItem(ref, '{"approved":true}');
  const retained = p.retainRoutingKey(ref, store);
  assert.match(retained.key, /^[a-zA-Z0-9._:-]{1,128}$/);
  const broken = {
    ...store,
    getItem() {
      throw new Error("unavailable");
    },
    setItem() {
      throw new Error("unavailable");
    },
  };
  assert.equal(p.retainRoutingKey(ref, broken).key, retained.key);
  p.forgetRoutingKey(ref, store);
});
