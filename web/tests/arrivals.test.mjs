import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";
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
const fixtures = JSON.parse(
  await readFile(
    new URL("fixtures/scheduled-arrivals.json", import.meta.url),
    "utf8",
  ),
);
const fresh = (phase = "waiting") => structuredClone(fixtures[phase]);
const view = (v) => p.asArrivalView(v, fixtures.occurrence, 1);
test("Go PostgreSQL arrival snapshots preserve their exact occurrence, calendar, frozen manifest and ordinary collection binding", () => {
  for (const phase of ["waiting", "ready", "admitted", "captured"]) {
    const v = fresh(phase);
    assert.deepEqual(view(v), v);
  }
  assert.equal(view(fresh()).probe_due, true);
  assert.equal(view(fresh("captured")).collection.inputs.length, 1);
});
test("arrival metadata cannot substitute due times, calendar identity, source, hash, lease or counter history", () => {
  for (const mutate of [
    (v) => (v.arrival.occurrence_id = "00000055-1111-4111-8111-111111111111"),
    (v) => (v.arrival.definition.manifest_name = "yesterday.ready.json"),
    (v) => (v.arrival.definition.due_at = "2030-01-01T00:00:00Z"),
    (v) =>
      (v.schedule.definition.collection.source.manifest =
        "other-{due_utc}.ready.json"),
    (v) => v.arrival.probes++,
    (v) => (v.arrival.lease_owner = "00000055-1111-4111-8111-111111111111"),
    (v) => (v.arrival.manifest.files[0].sha256 = "f".repeat(64)),
    (v) => (v.arrival.arrival_deadline_at = "2030-01-01T00:00:00Z"),
    (v) => (v.arrival_timeliness = "not_observed"),
    (v) => (v.probe_due = true),
    (v) =>
      (v.collection.job.definition.schedule.occurrence_id =
        "00000055-1111-4111-8111-111111111111"),
    (v) => (v.collection.job.deadline_at = "2030-01-01T00:00:00Z"),
  ]) {
    const v = fresh("admitted");
    mutate(v);
    assert.throws(() => view(v));
  }
});
test("missing is an unobserved cutoff result and cannot claim producer absence or a frozen manifest", () => {
  const v = fresh();
  v.arrival.state = "missing";
  v.arrival.revision++;
  v.arrival.reason = "no_verified_ready_manifest_by_cutoff";
  v.observed_state = "missing";
  v.current_authority = false;
  v.probe_due = false;
  assert.equal(view(v).arrival_timeliness, "not_observed");
  for (const mutate of [
    (v) => (v.probe_due = true),
    (v) => (v.current_authority = true),
    (v) => (v.arrival_timeliness = "on_time"),
    (v) => (v.arrival.observed_at = v.arrival.definition.due_at),
    (v) => (v.arrival.producer_never_published = true),
  ]) {
    const w = structuredClone(v);
    mutate(w);
    assert.throws(() => view(w));
  }
});
test("historical original-key receipts stay tied to the reviewed occurrence and action", () => {
  const a = fresh("ready").arrival;
  const r = {
    resource: {
      kind: "workflow_schedule_arrival",
      occurrence_id: a.occurrence_id,
      definition_hash: a.definition_hash,
      state: "admitted",
      revision: a.revision + 1,
      collection_id: fresh("admitted").arrival.collection_id,
      manifest_hash: a.manifest_hash,
      external_contact: false,
    },
    replayed: true,
  };
  assert.deepEqual(p.asArrivalResult(r, a, "admit"), r);
  for (const mutate of [
    (r) => (r.resource.occurrence_id = "00000055-1111-4111-8111-111111111111"),
    (r) => (r.resource.definition_hash = "f".repeat(64)),
    (r) => (r.resource.external_contact = true),
    (r) => (r.resource.state = "waiting"),
    (r) => (r.resource.revision = 1),
  ]) {
    const w = structuredClone(r);
    mutate(w);
    assert.throws(() => p.asArrivalResult(w, a, "admit"));
  }
});

test("arrival timeliness preserves PostgreSQL precision at the exact late boundary", () => {
  const v = fresh("ready"),
    boundary = v.arrival.definition.late_after_at;
  v.arrival.observed_at = boundary.replace("Z", ".000001Z");
  v.arrival_timeliness = "late";
  assert.equal(view(v).arrival_timeliness, "late");
  v.arrival_timeliness = "on_time";
  assert.throws(() => view(v));
  v.arrival.observed_at = boundary.replace("Z", ".000000Z");
  assert.equal(view(v).arrival_timeliness, "on_time");
});
