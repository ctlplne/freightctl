import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
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
const fixture = JSON.parse(
  await readFile(
    new URL("fixtures/local-collections.json", import.meta.url),
    "utf8",
  ),
);
const fresh = () => structuredClone(fixture);
const hash = (v) => createHash("sha256").update(v).digest("hex");

test("Go local source review and captured receipt retain exact canonical root-bound meaning", () => {
  const f = fresh(),
    w = p.asCollectionConfiguration(f.workflow);
  assert.equal(p.collectionWorkflowHash(w.definition), w.definition_hash);
  const review = p.asCollectionWorkflowPreview(
    f.workflow_preview,
    w.definition,
  );
  assert.equal(review.external_contact, false);
  assert.equal(review.collection.kind, "local.collect");
  const preview = p.asCollectionPreview(f.preview, f.selection, 3, w);
  assert.equal(preview.definition.source_connection.local.read_only, true);
  assert.equal(
    preview.definition.source_connection.local.profile,
    "freightctl-local-collection-source-v1",
  );
  const v = p.asCollectionView(
    f.view,
    f.view.job.id,
    3,
    f.preview.definition_hash,
  );
  assert.equal(v.job.captured, true);
  assert.equal(v.business_acceptance, "unknown");
  assert.equal(v.inputs[0].run_id, null);
  assert.equal(v.job.definition.effects.length, 0);
  assert.equal(JSON.stringify(v).includes('root_reference"'), false);
});

test("rehashing cannot invent local source authority or mix network protocols", () => {
  for (const mutate of [
    (d) => (d.source.kind = "sftp.collect"),
    (d) => (d.source.kind = "ftps.collect"),
    (d) => (d.source_connection.protocol = "sftp"),
    (d) => (d.source_connection.address = "127.0.0.1:22"),
    (d) => (d.source_connection.user = "operator"),
    (d) => (d.source_connection.directory = "/unapproved"),
    (d) => (d.source_connection.local.read_only = false),
    (d) => (d.source_connection.local.profile = "unapproved-local-profile"),
    (d) =>
      (d.source_connection.local.root_reference = "/PRIVATE_HOST_REFERENCE"),
    (d) => (d.source_connection.local.directory = "/PRIVATE_HOST_ROOT"),
    (d) => (d.source_connection.local.execute = true),
    (d) => (d.source_connection.local.root_fingerprint = "D".repeat(64)),
    (d) => (d.source_connection.ftps = {}),
    (d) => (d.source_connection.host_fingerprint = "SHA256:" + "A".repeat(43)),
  ]) {
    const f = fresh();
    mutate(f.view.job.definition);
    f.view.job.definition_hash = p.collectionHash(f.view.job.definition);
    assert.throws(() =>
      p.asCollectionView(f.view, f.view.job.id, 3, f.view.job.definition_hash),
    );
  }
});

test("root substitution and the old path-only identity cannot inherit reviewed capture", () => {
  for (const mutate of [
    (d) => (d.source_connection.local.root_fingerprint = "e".repeat(64)),
    (d) =>
      (d.source_identity = hash(
        d.source_connection.id + ":" + d.source_connection.directory,
      )),
  ]) {
    const f = fresh();
    mutate(f.view.job.definition);
    f.view.job.definition_hash = p.collectionHash(f.view.job.definition);
    assert.throws(() =>
      p.asCollectionView(f.view, f.view.job.id, 3, f.view.job.definition_hash),
    );
  }
  for (const field of [
    "root_reference_sha256",
    "configuration_sha256",
    "root_fingerprint",
  ]) {
    const f = fresh();
    f.view.job.definition.source_connection.local[field] = "e".repeat(64);
    assert.throws(() =>
      p.asCollectionView(f.view, f.view.job.id, 3, f.preview.definition_hash),
    );
  }
});

test("unimplemented local calendar and local outward delivery remain refused", () => {
  const source = fresh().workflow.definition.source;
  source.completion_contract = "immutable-files-sha256-scheduled-manifest-v1";
  source.manifest = "settlement-{due_utc}.ready.json";
  assert.throws(() => p.asCollectionSource(source));
  const w = fresh().workflow.definition;
  w.steps = [
    {
      id: "send",
      kind: "local.deliver",
      connection: w.source.connection,
      filename: "one.csv",
    },
  ];
  assert.throws(() => p.asCollectionWorkflow(w));
});
