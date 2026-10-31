import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const built = await build({
  absWorkingDir: web,
  entryPoints: ["src/onboarding-tests-types.ts"],
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const {
  asTestPreview,
  asTestStart,
  asTestPage,
  asTestView,
  testDefinitionHash,
} = await import(
  "data:text/javascript;base64," +
    Buffer.from(built.outputFiles[0].contents).toString("base64")
);
const fixture = JSON.parse(
    await readFile(
      path.join(web, "tests/fixtures/onboarding-test.json"),
      "utf8",
    ),
  ),
  fresh = () => structuredClone(fixture),
  author = "0000000b-1111-4111-8111-111111111111",
  id = "0000000c-1111-4111-8111-111111111111";
function result() {
  const p = fresh().preview,
    d = p.definition;
  return {
    replayed: false,
    resource: {
      kind: "onboarding_test",
      test: {
        id,
        run_id: id,
        author_id: author,
        definition: d,
        definition_hash: p.definition_hash,
        created_at: "2026-10-30T23:00:00Z",
        created_event_id: "0000000d-1111-4111-8111-111111111111",
      },
      run: {
        id,
        workflow_id: d.workflow.id,
        workflow_version: d.workflow.version,
        workflow_hash: d.workflow.hash,
        file_id: d.file.id,
        source: structuredClone(d.file),
        storage_id: d.storage_id,
        namespace_root: d.namespace_root,
        authority_revision: d.authority_revision,
        state: "queued",
        revision: 1,
      },
    },
  };
}
test("onboarding test preview independently hashes the exact Go typed definition", () => {
  const f = fresh(),
    p = asTestPreview(f.preview, f.selection);
  assert.equal(testDefinitionHash(p.definition), f.preview.definition_hash);
  for (const mutate of [
    (p) => (p.definition.probe.hash = "9".repeat(64)),
    (p) => (p.definition.file.sha256 = "9".repeat(64)),
    (p) => (p.connection.address = "other.invalid:22"),
    (p) => (p.external_contact = true),
    (p) => (p.production_active = true),
    (p) => (p.definition.namespace_root = "/other"),
    (p) => p.definition.workflow.version++,
  ]) {
    const f = fresh();
    mutate(f.preview);
    assert.throws(() => asTestPreview(f.preview, f.selection));
  }
});
test("test creation and history cannot adopt another actor, run or reviewed definition", () => {
  const p = fresh().preview;
  assert.equal(asTestStart(result(), author, p).id, id);
  for (const mutate of [
    (v) => (v.resource.test.author_id = id),
    (v) => (v.resource.run.id = author),
    (v) => (v.resource.run.workflow_hash = "9".repeat(64)),
    (v) =>
      (v.resource.run.source = {
        ...v.resource.run.source,
        sha256: "9".repeat(64),
      }),
    (v) => (v.resource.test.definition.file.id = id),
    (v) => (v.resource.test.run_id = author),
    (v) => (v.resource.kind = "approved"),
  ]) {
    const v = result();
    mutate(v);
    assert.throws(() => asTestStart(v, author, p));
  }
  const row = result().resource.test;
  assert.equal(
    asTestPage({ tests: [row] }, author, p.definition.plan.id).tests.length,
    1,
  );
  assert.throws(() =>
    asTestPage({ tests: [row, row] }, author, p.definition.plan.id),
  );
  const view = {
    test: row,
    status: {
      run: result().resource.run,
      steps: [
        {
          id: p.definition.step_id,
          delivery_id: "0000000e-1111-4111-8111-111111111111",
          state: "queued",
          attempts: 0,
        },
      ],
      observed_state: "queued",
      observed_reason: "awaiting_worker",
    },
    current_bindings: true,
    binding_reason: "current",
    production_active: false,
  };
  assert.equal(
    asTestView(view, author, { id, hash: p.definition_hash }).current_bindings,
    true,
  );
  for (const mutate of [
    (v) => v.status.run.workflow_version++,
    (v) => v.status.run.source.size_bytes++,
    (v) => (v.status.run.source.accepted_event_id = id),
    (v) => (v.status.run.storage_id = id),
    (v) => v.status.run.authority_revision++,
    (v) => (v.status.steps[0].state = "approved"),
  ]) {
    const changed = structuredClone(view);
    mutate(changed);
    assert.throws(() =>
      asTestView(changed, author, { id, hash: p.definition_hash }),
    );
  }
  view.production_active = true;
  assert.throws(() =>
    asTestView(view, author, { id, hash: p.definition_hash }),
  );
});
