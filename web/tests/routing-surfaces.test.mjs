import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";
const bundle = await build({
  entryPoints: ["src/collections-types.ts"],
  absWorkingDir: new URL("..", import.meta.url).pathname,
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const p = await import(
  "data:text/javascript;base64," +
    Buffer.from(bundle.outputFiles[0].contents).toString("base64")
);
const routing = JSON.parse(
  await readFile(new URL("fixtures/routing.json", import.meta.url), "utf8"),
);
const legacy = JSON.parse(
  await readFile(new URL("fixtures/collections.json", import.meta.url), "utf8"),
).plain;
function fixture(name = "north_loop") {
  const f = structuredClone(routing[name]),
    base = structuredClone(legacy);
  const workflow = {
    ...base.workflow,
    definition: f.definition,
    definition_hash: f.definition_hash,
    state: "approved",
  };
  const ref = {
    id: workflow.id,
    version: workflow.version,
    hash: workflow.definition_hash,
  };
  const effects = f.definition.steps.map((s) => ({
    step_id: s.id,
    connection: s.connection,
    address: "127.0.0.1:22022",
    directory: "/receiver",
    final_name_pattern: "<delivery UUID>-" + s.filename,
    host_fingerprint: "SHA256:" + "A".repeat(43),
  }));
  const input = {
    ...base.view.inputs[0],
    first_job_id: f.facts.source.collection_id,
    workflow_id: workflow.id,
    source_name: f.facts.source.name,
    size_bytes: f.facts.file.size_bytes,
    sha256: f.facts.file.sha256,
    file_id: f.facts.file.id,
    object_id: f.facts.file.id,
    run_id: base.run.run.id,
  };
  const definition = {
    ...base.view.job.definition,
    workflow: ref,
    source: f.definition.source,
    effects,
  };
  const manifest = {
    schema_version: 1,
    batch_id: f.facts.source.batch_id,
    files: [
      {
        name: input.source_name,
        size_bytes: input.size_bytes,
        sha256: input.sha256,
      },
      { name: "sibling.csv", size_bytes: 1, sha256: "c".repeat(64) },
    ],
  };
  const job = {
    ...base.view.job,
    id: input.first_job_id,
    workflow_id: ref.id,
    workflow_version: ref.version,
    workflow_hash: ref.hash,
    definition,
    manifest,
    manifest_hash: p.collectionHash(manifest),
    captured: true,
  };
  f.facts.source.manifest_hash = job.manifest_hash;
  // Use the browser compiler only to construct this synthetic response; the
  // independent Go golden contract remains in programs.test.mjs.
  const plan = p.compileCollectionProgram(workflow.definition, f.facts);
  const run = {
    ...base.run,
    run: {
      ...base.run.run,
      id: input.run_id,
      file_id: input.file_id,
      source: f.facts.file,
      workflow_id: ref.id,
      workflow_version: ref.version,
      workflow_hash: ref.hash,
      authority_revision: definition.authority_revision,
      execution_plan: plan,
      execution_plan_hash: p.collectionHash(plan),
    },
    steps: plan.selected_steps.map((id, i) => ({
      ...base.run.steps[0],
      id,
      ordinal: i + 1,
      delivery_id: "10000000-0000-0000-0000-" + String(i + 1).padStart(12, "0"),
    })),
    observed_state: plan.local_reason ? "kept_local" : "queued",
  };
  const preview = {
    workflow: ref,
    source: f.facts.file,
    potential_effects: effects,
    selected_effects: plan.selected_steps.map((id) =>
      effects.find((e) => e.step_id === id),
    ),
    execution_plan: plan,
    execution_plan_hash: p.collectionHash(plan),
    external_contact: false,
  };
  return { workflow, input, definition, job, run, preview };
}
test("collection definitions preserve all Go schema-2 programs and exact canonical hashes", () => {
  for (const f of Object.values(routing).filter((f) => f.definition.source)) {
    const d = p.asCollectionWorkflow(f.definition);
    assert.equal(p.collectionWorkflowHash(d), f.definition_hash);
    assert.deepEqual(d.program, f.definition.program);
  }
  const d = structuredClone(routing.north_loop.definition);
  d.schema_version = 1;
  assert.throws(() => p.asCollectionWorkflow(d));
  delete d.program;
  assert.equal(p.asCollectionWorkflow(d).schema_version, 1);
});
test("input preview and private run inspection bind the selected order or explicit local outcome to the original manifest", () => {
  for (const name of ["north_loop", "explicit_local"]) {
    const f = fixture(name),
      context = { workflow: f.workflow, job: f.job };
    const preview = p.asCollectionRunPreview(
      f.preview,
      f.input,
      f.definition,
      context,
    );
    const run = p.asCollectedRun(f.run, f.input, f.definition, context);
    assert.deepEqual(run.run.execution_plan, preview.execution_plan);
    assert.equal(run.steps.length, preview.selected_effects.length);
    if (name === "explicit_local")
      assert.equal(run.observed_state, "kept_local");
  }
});
test("a rehashed plan cannot replace original source facts, recipients, order, workflow approval or local disposition", () => {
  for (const mutate of [
    (f) => {
      f.run.run.execution_plan.facts.source.name = "other.csv";
    },
    (f) => {
      f.run.run.execution_plan.selected_steps.reverse();
    },
    (f) => {
      f.run.run.execution_plan.decisions[0].matched = false;
    },
    (f) => {
      f.job.manifest.files.reverse();
      f.job.manifest_hash = p.collectionHash(f.job.manifest);
    },
    (f) => {
      f.workflow.definition.program.nodes[0].then[0].steps = ["south"];
    },
    (f) => {
      delete f.run.run.execution_plan;
      delete f.run.run.execution_plan_hash;
    },
    (f) => {
      f.run.observed_state = "kept_local";
    },
    (f) => {
      f.run.run.execution_plan.local_reason = "hidden_keep";
    },
  ]) {
    const f = fixture();
    mutate(f);
    if (f.run.run.execution_plan)
      f.run.run.execution_plan_hash = p.collectionHash(
        f.run.run.execution_plan,
      );
    assert.throws(() =>
      p.asCollectedRun(f.run, f.input, f.definition, {
        workflow: f.workflow,
        job: f.job,
      }),
    );
  }
  const f = fixture();
  f.preview.selected_effects = [f.preview.potential_effects[1]];
  assert.throws(() =>
    p.asCollectionRunPreview(f.preview, f.input, f.definition, {
      workflow: f.workflow,
      job: f.job,
    }),
  );
  assert.throws(() => p.asCollectedRun(f.run, f.input, f.definition));
});

test("a workflow diff cannot conceal a changed routing program behind an unchanged catalog", () => {
  const f = fixture(),
    current = { ...f.workflow, version: 2 },
    before = { ...f.workflow.definition, schema_version: 1 };
  delete before.program;
  const diff = {
    workflow_id: current.id,
    from_version: 1,
    to_version: 2,
    from_hash: p.collectionWorkflowHash(before),
    to_hash: current.definition_hash,
    before,
    after: current.definition,
    name_changed: false,
    order_changed: false,
    program_changed: true,
    added_steps: [],
    removed_steps: [],
    changed_steps: [],
  };
  assert.equal(p.asWorkflowDifference(diff, current).program_changed, true);
  for (const mutate of [
    (d) => {
      d.program_changed = false;
    },
    (d) => {
      d.from_version = 2;
    },
    (d) => {
      d.changed_steps = ["north"];
    },
    (d) => {
      d.after.program.nodes[0].when.text = "south-*.csv";
      d.to_hash = p.collectionWorkflowHash(d.after);
    },
  ]) {
    const v = structuredClone(diff);
    mutate(v);
    assert.throws(() => p.asWorkflowDifference(v, current));
  }
});
