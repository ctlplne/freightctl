import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";
const built = await build({
  entryPoints: [new URL("../src/schedules-types.ts", import.meta.url).pathname],
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const p = await import(
  "data:text/javascript;base64," +
    Buffer.from(built.outputFiles[0].contents).toString("base64")
);
const legacy = Object.values(
  JSON.parse(
    await readFile(new URL("fixtures/schedules.json", import.meta.url), "utf8"),
  ),
)[0].preview.definition;
const task = JSON.parse(
  await readFile(
    new URL("fixtures/processing-workflow.json", import.meta.url),
    "utf8",
  ),
).definition.processing;
const definition = {
  ...structuredClone(legacy),
  schema_version: 2,
  effects: [],
  source: { ...structuredClone(legacy.source), kind: "owned_released_records" },
  processing: { profile: "owned-record-processing-schedule-v1", task },
};
test("processing calendars bind the whole separately approved task and retain legacy delivery hashes", () => {
  const decoded = p.asScheduleDefinition(definition);
  assert.deepEqual(decoded, definition);
  assert.deepEqual(p.asScheduleDefinition(legacy), legacy);
  for (const change of [
    (x) => (x.schema_version = 1),
    (x) => delete x.processing,
    (x) => (x.processing.profile = "implicit-forwarding"),
    (x) => (x.source.kind = "sftp.collect"),
    (x) => (x.effects = structuredClone(legacy.effects)),
    (x) => (x.processing.task.definition.engine = "shell"),
    (x) => (x.processing.task.approved = true),
  ]) {
    const bad = structuredClone(definition);
    change(bad);
    assert.throws(() => p.asScheduleDefinition(bad));
  }
});
test("schedule discovery names an owned processing source explicitly and refuses mixed collection authority", () => {
  const item = {
    id: definition.workflow.id,
    version: definition.workflow.version,
    hash: definition.workflow.hash,
    name: "Approved task",
    processing: definition.processing,
  };
  assert.deepEqual(
    p.asSchedulableWorkflows({ workflows: [item] }).workflows[0].processing,
    item.processing,
  );
  const bad = {
    ...item,
    processing: { ...item.processing, profile: "unqualified" },
  };
  assert.throws(() => p.asSchedulableWorkflows({ workflows: [bad] }));
});

test("processing calendar hash matches independent Python and Go over complete task meaning", async () => {
  const fixture = JSON.parse(
    await readFile(
      new URL("fixtures/processing-schedule.json", import.meta.url),
      "utf8",
    ),
  );
  const actual = p.asScheduleDefinition(fixture.definition);
  assert.deepEqual(actual, fixture.definition);
  assert.equal(p.scheduleHash(actual), fixture.definition_hash);
});
