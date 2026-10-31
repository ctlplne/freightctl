import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";
const bundle = await build({
  entryPoints: ["src/schedules-types.ts"],
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
    await readFile(new URL("fixtures/schedules.json", import.meta.url), "utf8"),
  ),
  fresh = (name = "plain") => structuredClone(fixtures[name]),
  preview = (f) => p.asSchedulePreview(f.preview, f.selection, 1);
test("Go canonical schedule hashes bind HTML-sensitive names, frozen fold offsets and both encryption shapes", () => {
  for (const f of Object.values(fixtures)) {
    const v = preview(f);
    assert.equal(p.scheduleHash(v.definition), v.definition_hash);
    assert.equal(v.external_contact, false);
    assert.equal(v.upcoming.length, 2);
    assert.equal(v.upcoming[0].local_time, v.upcoming[1].local_time);
    assert.notEqual(v.upcoming[0].at, v.upcoming[1].at);
    assert.equal(
      p.asScheduleView(f.view, f.summary.id, 1, 1).current_authority,
      true,
    );
  }
});
test("tampered destination and encryption metadata cannot keep the reviewed hash or detached effect copy", () => {
  for (const mutate of [
    (d) => (d.effects[0].address = "untrusted.invalid:22"),
    (d) => (d.effects[0].host_fingerprint = "SHA256:other"),
    (d) => (d.effects[0].encryption.key.hash = "f".repeat(64)),
  ]) {
    const f = fresh("encrypted");
    mutate(f.preview.definition);
    assert.throws(() => preview(f));
  }
  const f = fresh();
  f.preview.effects[0].address = "untrusted.invalid:22";
  assert.throws(() => preview(f));
});
test("even rehashed source scope, schedule policy or authority cannot replace the selected request", () => {
  for (const mutate of [
    (d) => (d.source.directory = "/other"),
    (d) => (d.source.recursive = true),
    (d) => d.authority_revision++,
    (d) => (d.missed_run_policy = "all"),
    (d) => (d.calendar.time_zone = "UTC"),
    (d) => d.execution_deadline_seconds++,
  ]) {
    const f = fresh();
    mutate(f.preview.definition);
    f.preview.definition_hash = p.scheduleHash(f.preview.definition);
    assert.throws(() => preview(f));
  }
  for (const k of ["external_contact", "approval_required"]) {
    const f = fresh();
    f.preview[k] = !f.preview[k];
    assert.throws(() => preview(f));
  }
});
test("calendar holes, invalid dates and invented civil-time labels are refused without consulting host time zone", () => {
  for (const mutate of [
    (d) => (d.calendar.offset_rules[0].until = "2024-11-03T05:59:59Z"),
    (d) => (d.calendar.local_times = ["25:00:00"]),
    (d) => (d.calendar.holidays = ["2024-02-30"]),
    (d) => (d.calendar.starts_at = "2024-02-30T00:00:00Z"),
    (d) => (d.calendar.weekdays = [0, 0]),
    (d) => (d.calendar.gap_policy = "guess"),
  ]) {
    const f = fresh();
    mutate(f.preview.definition);
    f.preview.definition_hash = p.scheduleHash(f.preview.definition);
    assert.throws(() => preview(f));
  }
  const f = fresh();
  f.preview.upcoming[0].local_time = "2024-11-03T02:30:00";
  assert.throws(() => preview(f));
  assert.equal(
    p.calendarContains(
      fixtures.plain.preview.definition.calendar,
      "2024-11-03T07:30:00Z",
    ),
    false,
  );
});
test("processing budgets, exact filename rules, duplicate effects and oversized metadata cannot be broadened", () => {
  for (const mutate of [
    (d) => (d.max_catch_up = 101),
    (d) => (d.max_active_runs = 65),
    (d) => (d.max_files_per_occurrence = 65),
    (d) => (d.late_start_grace_seconds = 0),
    (d) => (d.source.filename_regex = ".*"),
    (d) => d.effects.push(d.effects[0]),
  ]) {
    const f = fresh();
    mutate(f.preview.definition);
    assert.throws(() => p.asScheduleDefinition(f.preview.definition));
  }
  const f = fresh();
  f.preview.definition.effects = Array.from({ length: 16 }, (_, i) => ({
    ...f.preview.definition.effects[0],
    step_id: "step_" + i,
    directory: "/" + "x".repeat(3000),
  }));
  assert.throws(() => p.asScheduleDefinition(f.preview.definition));
});
test("private schedule status and original receipts remain bound to exact IDs, versions and authority", () => {
  const f = fresh();
  for (const mutate of [
    (v) => (v.schedule.id = fixtures.encrypted.summary.id),
    (v) => v.schedule.version++,
    (v) => v.schedule.approval_authority++,
    (v) => v.pending_runs.push(v.pending_runs[0]),
  ]) {
    const v = structuredClone(f.view);
    mutate(v);
    assert.throws(() => p.asScheduleView(v, f.summary.id, 1, 1));
  }
  const expected = {
      hash: f.summary.definition_hash,
      id: f.summary.id,
      version: 1,
      state: "active",
      revision: 2,
    },
    value = {
      replayed: true,
      resource: { kind: "workflow_schedule", schedule: f.summary },
    };
  assert.equal(p.asScheduleResult(value, expected).id, f.summary.id);
  value.resource.schedule = fixtures.encrypted.summary;
  assert.throws(() => p.asScheduleResult(value, expected));
});
test("occurrence claim counts, private input lineage and queue-only tick receipts cannot invent a run", () => {
  const f = fresh(),
    o = p.asOccurrenceView(f.occurrence, f.history.occurrences[0]);
  assert.equal(o.inputs[0].run_id, f.run.run.id);
  assert.equal(p.asScheduleTick(f.tick, f.summary).run_ids.length, 1);
  for (const mutate of [
    (v) => (v.inputs[0].occurrence_id = fixtures.encrypted.summary.id),
    (v) => v.inputs.push(v.inputs[0]),
  ]) {
    const v = structuredClone(f.occurrence);
    mutate(v);
    assert.throws(() => p.asOccurrenceView(v, f.history.occurrences[0]));
  }
  for (const mutate of [
    (v) => (v.resource.external_contact = true),
    (v) => (v.resource.run_ids = []),
    (v) => (v.resource.schedule.id = fixtures.encrypted.summary.id),
    (v) => (v.resource.occurrences[0].input_count = 0),
  ]) {
    const v = structuredClone(f.tick);
    mutate(v);
    assert.throws(() => p.asScheduleTick(v, f.summary));
  }
});
test("run inspection and execution replies cannot switch file, workflow, step or delivery identity", () => {
  const f = fresh(),
    input = f.occurrence.inputs[0],
    definition = f.preview.definition;
  assert.equal(p.asScheduledRun(f.run, input, definition).run.id, input.run_id);
  for (const mutate of [
    (v) => (v.run.file_id = fixtures.encrypted.summary.id),
    (v) => (v.run.workflow_hash = "f".repeat(64)),
    (v) => (v.steps[0].id = "another_step"),
  ]) {
    const v = structuredClone(f.run);
    mutate(v);
    assert.throws(() => p.asScheduledRun(v, input, definition));
  }
  const v = {
    replayed: false,
    dispatch: {
      run_id: input.run_id,
      step_id: f.run.steps[0].id,
      delivery_id: f.run.steps[0].delivery_id,
    },
    status: f.run,
  };
  assert.equal(p.asScheduledWork(v, input, definition).run.id, input.run_id);
  v.dispatch.delivery_id = fixtures.encrypted.summary.id;
  assert.throws(() => p.asScheduledWork(v, input, definition));
});
test("bounded workflow and schedule pages preserve unique private references and valid continuation", () => {
  const f = fresh();
  assert.equal(p.asSchedulePage(f.page).schedules.length, 1);
  f.page.schedules.push(f.page.schedules[0]);
  assert.throws(() => p.asSchedulePage(f.page));
  const workflows = {
    workflows: [{ ...f.selection.workflow, name: "Settlement" }],
    next: fixtures.encrypted.summary.id,
  };
  assert.throws(() => p.asSchedulableWorkflows(workflows));
});
