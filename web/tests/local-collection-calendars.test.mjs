import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";
import { createHash } from "node:crypto";

const bundle = await build({
  entryPoints: ["src/arrivals-types.ts"],
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
    new URL("fixtures/local-scheduled-arrivals.json", import.meta.url),
    "utf8",
  ),
);
const fresh = (phase = "waiting") => structuredClone(fixture[phase]);
const view = (v) => p.asArrivalView(v, fixture.occurrence, 1);

test("synthetic Go local calendar snapshots retain exact root,UTC occurrence and frozen manifest", () => {
  for (const phase of ["waiting", "ready", "admitted", "captured"]) {
    const v = view(fresh(phase));
    assert.deepEqual(v, fresh(phase));
    assert.equal(v.schedule.definition.source.kind, "local.collect");
    assert.equal(
      v.schedule.definition.collection.source_connection.local.read_only,
      true,
    );
    assert.equal(v.schedule.definition.effects.length, 0);
  }
  const captured = view(fresh("captured"));
  assert.equal(captured.collection.inputs[0].run_id, null);
  assert.equal(captured.collection.business_acceptance, "unknown");
});

test("local calendar cannot change reviewed root,protocol,authority,UTC due or manifest binding", () => {
  for (const mutate of [
    (v) => (v.schedule.definition.collection.source.kind = "sftp.collect"),
    (v) =>
      (v.schedule.definition.collection.source_connection.protocol = "sftp"),
    (v) =>
      (v.schedule.definition.collection.source_connection.local.read_only = false),
    (v) =>
      (v.schedule.definition.collection.source_connection.local.execute = true),
    (v) =>
      (v.schedule.definition.collection.source_connection.local.root_reference =
        "PRIVATE_HOST_REFERENCE"),
    (v) =>
      (v.schedule.definition.collection.source_connection.local.root_fingerprint =
        "e".repeat(64)),
    (v) =>
      (v.arrival.definition.manifest_name =
        "settlement-20261031T085733Z.ready.json"),
    (v) => (v.arrival.definition.due_at = "2026-11-01T06:30:00Z"),
    (v) => (v.arrival.definition.schedule.hash = "e".repeat(64)),
    (v) => v.schedule.definition.authority_revision++,
  ]) {
    const v = fresh("captured");
    mutate(v);
    assert.throws(() => view(v));
  }
});

test("independently rehashed calendar metadata cannot substitute a different captured source or storage", () => {
  const hash = (v) =>
    createHash("sha256").update(JSON.stringify(v)).digest("hex");
  for (const mutate of [
    (v) =>
      (v.schedule.definition.collection.source_connection.local.root_fingerprint =
        "e".repeat(64)),
    (v) =>
      (v.schedule.definition.collection.source_connection.local.configuration_sha256 =
        "e".repeat(64)),
    (v) =>
      (v.schedule.definition.storage_id =
        "00000055-1111-4111-8111-111111111111"),
  ]) {
    const v = fresh("captured");
    mutate(v);
    v.schedule.definition_hash = hash(v.schedule.definition);
    v.arrival.definition.schedule.hash = v.schedule.definition_hash;
    v.arrival.definition_hash = hash(v.arrival.definition);
    v.collection.job.definition.schedule.schedule.hash =
      v.schedule.definition_hash;
    v.collection.job.definition_hash = hash(v.collection.job.definition);
    assert.throws(() => view(v));
  }
});
