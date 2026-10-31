import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";
const bundle = await build({
  entryPoints: ["src/programs-types.ts"],
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
  await readFile(new URL("fixtures/routing.json", import.meta.url), "utf8"),
);
test("browser independently reproduces all Go routing plans and canonical fingerprints", () => {
  for (const [name, f] of Object.entries(fixtures)) {
    assert.equal(
      p.programFingerprint(f.definition),
      f.definition_hash,
      name + " definition",
    );
    const plan = p.compileProgram(f.definition, f.facts);
    assert.deepEqual(plan, f.plan, name);
    assert.equal(p.programFingerprint(plan), f.plan_hash, name + " plan");
    assert.deepEqual(p.asExecutionPlan(f.plan, f.definition, f.facts), f.plan);
  }
});
test("server plans cannot substitute recipients, source facts, order, control trace or local disposition", () => {
  const original = fixtures.north_loop;
  for (const mutate of [
    (v) => v.selected_steps.reverse(),
    (v) => v.selected_steps.push("south"),
    (v) => (v.facts.source.name = "south-settlement.csv"),
    (v) => (v.decisions[0].matched = false),
    (v) => (v.local_reason = "hidden_local"),
    (v) => (v.decisions[1].steps = ["south"]),
    (v) => (v.approved = true),
  ]) {
    const v = structuredClone(original.plan);
    mutate(v);
    assert.throws(() =>
      p.asExecutionPlan(v, original.definition, original.facts),
    );
  }
});
test("untrusted program metadata cannot add network authority or escape loop and integer bounds", () => {
  for (const mutate of [
    (d) => (d.program.nodes[0].kind = "exec"),
    (d) => (d.program.nodes[0].when.field = "model.approved_recipient"),
    (d) => (d.program.nodes[0].then[0].steps = ["outside"]),
    (d) => (d.program.nodes[0].then[0].steps = ["north", "north"]),
    (d) => (d.program.nodes[0].then[0].body[0].step_variable = "missing"),
    (d) => (d.program.nodes[0].then[0].variable = "constructor"),
  ]) {
    const d = structuredClone(fixtures.north_loop.definition);
    mutate(d);
    assert.throws(() => p.compileProgram(d, fixtures.north_loop.facts));
  }
  const f = structuredClone(fixtures.operator_lt_file_size_bytes);
  f.definition.program.nodes[0].when.number = 9007199254740993;
  assert.throws(() => p.compileProgram(f.definition, f.facts));
});
