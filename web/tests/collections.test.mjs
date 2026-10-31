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
const fixtures = JSON.parse(
  await readFile(new URL("fixtures/collections.json", import.meta.url), "utf8"),
);
const fresh = (name = "plain") => structuredClone(fixtures[name]);
const view = (f) =>
  p.asCollectionView(f.view, f.view.job.id, 3, f.preview.definition_hash);
test("Go source-only, forwarding and encrypted definitions keep exact canonical workflow and job hashes", () => {
  for (const f of Object.values(fixtures)) {
    const c = p.asCollectionConfiguration(f.workflow);
    assert.equal(p.collectionWorkflowHash(c.definition), c.definition_hash);
    assert.equal(
      p.asCollectionWorkflowPreview(f.workflow_preview, c.definition)
        .external_contact,
      false,
    );
    assert.equal(
      p.asCollectionPreview(f.preview, f.selection, 3, c).definition_hash,
      f.preview.definition_hash,
    );
    assert.equal(view(f).job.captured, true);
    assert.equal(view(f).business_acceptance, "unknown");
  }
  assert.equal(fixtures.local.workflow.definition.steps.length, 0);
  assert.equal(fixtures.local.view.inputs[0].run_id, null);
});
test("source, target, host identity, byte bounds and approval metadata cannot keep a reviewed job fingerprint", () => {
  for (const mutate of [
    (d) => (d.source.target_directory = "/other"),
    (d) => (d.source_connection.host_fingerprint = "SHA256:" + "D".repeat(43)),
    (d) => (d.source_connection.key_fingerprint = "SHA256:" + "E".repeat(43)),
    (d) => d.source.max_file_bytes++,
    (d) => d.timeout_seconds++,
    (d) => d.authority_revision++,
    (d) => (d.effects[0].connection.hash = "f".repeat(64)),
  ]) {
    const f = fresh();
    mutate(f.preview.definition);
    assert.throws(() => p.asCollectionPreview(f.preview, f.selection, 3));
  }
});
test("rehashing cannot substitute a different selected workflow, timeout, authority or declared source", () => {
  for (const mutate of [
    (d) => (d.workflow.hash = "f".repeat(64)),
    (d) => d.timeout_seconds++,
    (d) => d.authority_revision++,
    (d) => (d.source.target_directory = "/other"),
  ]) {
    const f = fresh();
    mutate(f.preview.definition);
    f.preview.definition_hash = p.collectionHash(f.preview.definition);
    assert.throws(() =>
      p.asCollectionPreview(
        f.preview,
        f.selection,
        3,
        p.asCollectionConfiguration(f.workflow),
      ),
    );
  }
  const f = fresh();
  f.view.job.definition.source.target_directory = "/other";
  f.view.job.definition_hash = p.collectionHash(f.view.job.definition);
  assert.throws(() => view(f));
});
test("invented completion rules, authorities, traversal and oversized bounds are rejected before review", () => {
  for (const mutate of [
    (s) => (s.completion_contract = "stable-size"),
    (s) => (s.manifest = "../settlement.ready.json"),
    (s) => (s.manifest = "ordinary.csv"),
    (s) => (s.target_directory = "/incoming/../outside"),
    (s) => (s.target_directory = "/incoming/.freightctl"),
    (s) => (s.target_directory = "/incoming/NUL"),
    (s) => (s.max_files = 65),
    (s) => (s.max_total_bytes = 2 ** 40),
    (s) => (s.approved = true),
    (s) => (s.connection.version = 2147483648),
  ]) {
    const s = fresh().preview.definition.source;
    mutate(s);
    assert.throws(() => p.asCollectionSource(s));
  }
});
test("producer and immutable input receipts stay correlated to exact names, bytes, original job and object", () => {
  for (const mutate of [
    (v) => (v.job.manifest.files[0].sha256 = "f".repeat(64)),
    (v) => (v.inputs[0].file_id = "00000055-1111-4111-8111-111111111111"),
    (v) => (v.inputs[0].source_identity = "f".repeat(64)),
    (v) => (v.inputs[0].workflow_id = "00000055-1111-4111-8111-111111111111"),
    (v) => (v.inputs[0].input_identity = "f".repeat(64)),
    (v) => (v.inputs[0].target_path = "/outside"),
    (v) => (v.inputs[0].capture_fence = 8),
    (v) => (v.inputs = []),
  ]) {
    const f = fresh();
    mutate(f.view);
    assert.throws(() => view(f));
  }
});
test("an unfinished batch cannot claim publication or a complete capture and lease histories cannot be invented", () => {
  for (const mutate of [
    (v) => (v.job.captured = false),
    (v) => (v.job.attempts = 9),
    (v) => (v.job.fence = 2),
    (v) => (v.job.lease_owner = "00000055-1111-4111-8111-111111111111"),
    (v) => (v.job.deadline_at = "2026-10-31T13:00:00Z"),
    (v) => (v.inputs[0].state = "pending"),
    (v) => (v.current_authority = "yes"),
    (v) => (v.business_acceptance = "accepted"),
    (v) =>
      (v.local_states[0].input_id = "00000055-1111-4111-8111-111111111111"),
  ]) {
    const f = fresh();
    mutate(f.view);
    assert.throws(() => view(f));
  }
  const f = fresh("local");
  f.view.job.state = "reading";
  f.view.job.captured = false;
  f.view.job.lease_owner = f.view.inputs[0].capture_owner;
  f.view.job.lease_until = f.view.job.deadline_at;
  f.view.observed_state = "reading";
  assert.throws(() => view(f));
  f.view.local_states[0].state = "awaiting_batch_capture";
  assert.equal(view(f).job.captured, false);
});
test("empty queued jobs require no prior source contact and a stale authority cannot be presented as current", () => {
  const f = fresh();
  const j = f.view.job;
  Object.assign(j, {
    state: "queued",
    captured: false,
    revision: 1,
    fence: 0,
    attempts: 0,
    manifest: null,
    manifest_hash: null,
    reason: "awaiting_collection_worker",
  });
  Object.assign(f.view, {
    inputs: [],
    local_states: [],
    observed_state: "queued",
  });
  assert.equal(view(f).job.attempts, 0);
  f.view.job.definition.authority_revision = 4;
  f.view.job.definition_hash = p.collectionHash(f.view.job.definition);
  assert.throws(() => p.asCollectionView(f.view, j.id, 3));
  f.view.current_authority = false;
  f.view.observed_state = "attention";
  assert.equal(p.asCollectionView(f.view, j.id, 3).current_authority, false);
});
test("private action receipts cannot become another job, an approval or a sending permission", () => {
  const f = fresh();
  const expected = {
    id: f.view.job.id,
    hash: f.preview.definition_hash,
    states: ["captured"],
    revision: 4,
  };
  assert.equal(
    p.asCollectionResult(f.action, expected).resource.state,
    "captured",
  );
  for (const mutate of [
    (a) => (a.resource.id = "00000055-1111-4111-8111-111111111111"),
    (a) => (a.resource.definition_hash = "f".repeat(64)),
    (a) => (a.resource.kind = "approved"),
    (a) => (a.resource.state = "approved"),
    (a) => a.resource.revision++,
    (a) => (a.approved = true),
  ]) {
    const a = structuredClone(f.action);
    mutate(a);
    assert.throws(() => p.asCollectionResult(a, expected));
  }
});
test("registered source metadata never accepts raw credential references or detached source fields", () => {
  const f = fresh(),
    c = f.preview.definition.source_connection;
  assert.equal(
    p.asCollectionConnections({ connections: [c] }).connections.length,
    1,
  );
  assert.throws(() =>
    p.asCollectionConnections({
      connections: [{ ...c, key_reference: "/private/key" }],
    }),
  );
  assert.throws(() => p.asCollectionConnections({ connections: [c, c] }));
  assert.throws(() =>
    p.asCollectionWorkflowPreview(
      { ...f.workflow_preview, external_contact: true },
      f.workflow.definition,
    ),
  );
});
test("downstream inspection binds the accepted digest and ordered run to the original input", () => {
  const f = fresh();
  assert.equal(
    p.asCollectedRun(f.run, f.view.inputs[0], f.preview.definition).run.id,
    f.run.run.id,
  );
  f.run.run.source.sha256 = "f".repeat(64);
  assert.throws(() =>
    p.asCollectedRun(f.run, f.view.inputs[0], f.preview.definition),
  );
});
