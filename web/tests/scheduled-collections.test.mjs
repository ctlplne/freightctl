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
const source = () => ({
  ...structuredClone(fixtures.plain.preview.definition.source),
  completion_contract: "immutable-files-sha256-scheduled-manifest-v1",
  manifest: "settlement-{due_utc}.ready.json",
});
test("scheduled source requires exactly one UTC due token and preserves its explicit contract", () => {
  const s = source();
  assert.deepEqual(p.asCollectionSource(s), s);
  for (const manifest of [
    "settlement.ready.json",
    "{due_utc}-{due_utc}.ready.json",
    "../{due_utc}.ready.json",
    "settlement-{due_utc}.csv",
    "settlement-{local_time}.ready.json",
  ])
    assert.throws(() => p.asCollectionSource({ ...s, manifest }));
  assert.throws(() =>
    p.asCollectionSource({ ...s, completion_contract: p.collectionContract }),
  );
});
test("scheduled collection binds its original absolute cutoff and verified occurrence manifest", () => {
  const j = structuredClone(fixtures.plain.view.job);
  const d = j.definition;
  d.source = source();
  d.timeout_seconds = 60;
  d.schedule = {
    schedule: {
      id: "00000055-1111-4111-8111-111111111111",
      version: 1,
      hash: "a".repeat(64),
    },
    occurrence_id: "00000056-1111-4111-8111-111111111111",
    due_at: "2026-10-31T12:00:00Z",
    arrival_deadline_at: "2026-10-31T12:00:30Z",
    deadline_at: "2026-10-31T12:01:00Z",
    manifest_name: "settlement-20261031T120000Z.ready.json",
    manifest_hash: j.manifest_hash,
  };
  j.created_at = "2026-10-31T12:00:05Z";
  j.next_at = j.created_at;
  j.deadline_at = d.schedule.deadline_at;
  j.definition_hash = p.collectionHash(d);
  assert.deepEqual(p.asCollectionJob(j), j);
  for (const mutate of [
    (j) => (j.deadline_at = "2026-10-31T12:01:05Z"),
    (j) =>
      (j.definition.schedule.manifest_name =
        "settlement-20261031T120001Z.ready.json"),
    (j) =>
      (j.definition.schedule.arrival_deadline_at =
        j.definition.schedule.deadline_at),
    (j) => (j.definition.schedule.manifest_hash = "f".repeat(64)),
    (j) => delete j.definition.schedule,
  ]) {
    const v = structuredClone(j);
    mutate(v);
    v.definition_hash = p.collectionHash(v.definition);
    assert.throws(() => p.asCollectionJob(v));
  }
});
