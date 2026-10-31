import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";
const built = await build({
  entryPoints: ["src/onboarding-releases-types.ts"],
  absWorkingDir: new URL("..", import.meta.url).pathname,
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const {
  asReleasePreview,
  asReleaseView,
  asReleasePage,
  asReleaseResult,
  asProductionPreview,
  asProductionResult,
  asProductionPage,
  asProductionStatus,
  releaseHash,
} = await import(
  "data:text/javascript;base64," +
    Buffer.from(built.outputFiles[0].contents).toString("base64")
);
const fixture = JSON.parse(
    await readFile(
      new URL("fixtures/onboarding-release.json", import.meta.url),
      "utf8",
    ),
  ),
  fresh = () => structuredClone(fixture),
  author = fixture.view.release.author_id,
  id = "00000016-1111-4111-8111-111111111111";
test("release approval binds every requirement, original test and readable effect with Go hashes", () => {
  const f = fresh();
  assert.equal(
    asReleasePreview(f.preview, f.plan, f.selection, author).definition_hash,
    releaseHash(f.preview.definition),
  );
  for (const mutate of [
    (p) => p.definition.proofs.pop(),
    (p) => p.definition.proofs.push(structuredClone(p.definition.proofs[0])),
    (p) => (p.definition.proofs[0].test_hash = "9".repeat(64)),
    (p) => (p.tests[0].definition.effect.address = "other.invalid:22"),
    (p) => (p.tests[0].author_id = id),
    (p) => (p.tests[0].definition.file.sha256 = "9".repeat(64)),
    (p) => (p.production_active = true),
    (p) => (p.external_contact = true),
  ]) {
    const f = fresh();
    mutate(f.preview);
    assert.throws(() =>
      asReleasePreview(f.preview, f.plan, f.selection, author),
    );
  }
  const changed = fresh();
  changed.plan.definition.requirements.push({
    ...changed.plan.definition.requirements[0],
    id,
  });
  assert.throws(() =>
    asReleasePreview(changed.preview, changed.plan, changed.selection, author),
  );
});
test("approval cannot become activation and production preview freezes its source and activation epoch", () => {
  const f = fresh(),
    summary = f.view.release,
    view = asReleaseView(f.view, f.plan, author, summary),
    preview = asProductionPreview(
      f.production,
      view,
      f.production.definition.requirement_id,
      f.production.definition.file.id,
    );
  assert.equal(preview.definition_hash, releaseHash(preview.definition));
  for (const mutate of [
    (v) => (v.release.state = "approved"),
    (v) => (v.current_bindings = false),
    (v) => (v.production_active = false),
    (v) => (v.release.approved_revision = 0),
    (v) => (v.release.definition.proofs[0].snapshot_hash = "9".repeat(64)),
    (v) => (v.tests[0].definition.effect.filename = "other.bin"),
  ]) {
    const g = fresh();
    mutate(g.view);
    assert.throws(() => asReleaseView(g.view, g.plan, author, g.view.release));
  }
  for (const mutate of [
    (p) => p.definition.release.revision++,
    (p) => (p.definition.file.sha256 = "9".repeat(64)),
    (p) => (p.definition.effect.filename = "other.bin"),
    (p) => (p.external_contact = true),
  ]) {
    const p = structuredClone(f.production);
    mutate(p);
    assert.throws(() =>
      asProductionPreview(
        p,
        view,
        f.production.definition.requirement_id,
        f.production.definition.file.id,
      ),
    );
  }
  const approved = { ...summary, state: "approved", revision: 2 };
  assert.throws(() =>
    asReleaseResult(
      {
        replayed: false,
        resource: { kind: "onboarding_release", release: approved },
      },
      author,
      f.plan,
      summary.definition_hash,
      "active",
    ),
  );
  assert.equal(
    asReleasePage({ releases: [summary] }, author, f.plan.id).releases.length,
    1,
  );
  assert.throws(() =>
    asReleasePage({ releases: [summary, summary] }, author, f.plan.id),
  );
});
function result() {
  const f = fresh(),
    d = f.production.definition;
  return {
    replayed: false,
    resource: {
      kind: "onboarding_production",
      dispatch: {
        id,
        author_id: author,
        definition: d,
        definition_hash: f.production.definition_hash,
        created_event_id: "00000017-1111-4111-8111-111111111111",
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
test("production receipts and history preserve exact run/source identity without inventing execution", () => {
  const f = fresh(),
    expected = asProductionResult(result(), author, f.view, f.production);
  assert.equal(expected.id, id);
  for (const mutate of [
    (r) => (r.resource.run.source.sha256 = "9".repeat(64)),
    (r) => r.resource.run.authority_revision++,
    (r) => (r.resource.run.id = author),
    (r) => r.resource.dispatch.definition.release.revision++,
    (r) => (r.resource.dispatch.author_id = id),
  ]) {
    const r = result();
    mutate(r);
    assert.throws(() => asProductionResult(r, author, f.view, f.production));
  }
  const row = {
    id,
    release: f.production.definition.release,
    requirement_id: f.production.definition.requirement_id,
    file_id: f.production.definition.file.id,
    definition_hash: f.production.definition_hash,
  };
  assert.equal(
    asProductionPage({ dispatches: [row] }, f.view).dispatches.length,
    1,
  );
  assert.throws(() => asProductionPage({ dispatches: [row, row] }, f.view));
  const response = {
    dispatch: result().resource.dispatch,
    status: {
      run: result().resource.run,
      steps: [
        {
          id: f.view.tests[0].definition.step_id,
          delivery_id: "00000018-1111-4111-8111-111111111111",
          state: "queued",
          attempts: 0,
          observation: {},
        },
      ],
      observed_state: "queued",
      observed_reason: "awaiting_worker",
    },
    current_bindings: true,
  };
  assert.equal(
    asProductionStatus(response, f.view, expected, author).state,
    "queued",
  );
  const inconsistent = structuredClone(f.view);
  inconsistent.release.revision = 5;
  assert.throws(() =>
    asProductionStatus(response, inconsistent, expected, author),
  );
  response.status.run.source.accepted_event_id = id;
  assert.throws(() => asProductionStatus(response, f.view, expected, author));
});
