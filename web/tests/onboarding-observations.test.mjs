import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";
const built = await build({
  entryPoints: ["src/onboarding-observations-types.ts"],
  absWorkingDir: new URL("..", import.meta.url).pathname,
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const {
  asObservationDefinition,
  asObservationPreview,
  asObservationReceipt,
  asObservationSummary,
  asObservationView,
  asObservationPage,
  observationHash,
} = await import(
  "data:text/javascript;base64," +
    Buffer.from(built.outputFiles[0].contents).toString("base64")
);
const fixture = JSON.parse(
    await readFile(
      new URL("fixtures/onboarding-observation.json", import.meta.url),
      "utf8",
    ),
  ),
  fresh = () => structuredClone(fixture),
  author = fixture.summary.author_id,
  other = "000000af-1111-4111-8111-111111111111";
test("read-only receipt observation shares Go hashes and exact original wire and rotated observer", () => {
  const f = fresh(),
    p = asObservationPreview(f.preview, f.selection, author, f.plan_id);
  assert.equal(observationHash(p.definition), p.definition_hash);
  assert.equal(p.resend_authorized, false);
  assert.notEqual(
    p.definition.source.dispatch.definition.effect.host_fingerprint,
    p.definition.effect.host_fingerprint,
  );
  for (const mutate of [
    (p) => (p.resend_authorized = true),
    (p) => (p.external_contact = true),
    (p) => (p.definition.source.dispatch.id = other),
    (p) => p.definition.authority_revision++,
    (p) => (p.definition.probe.id = other),
  ]) {
    const f = fresh();
    mutate(f.preview);
    assert.throws(() =>
      asObservationPreview(f.preview, f.selection, author, f.plan_id),
    );
  }
});
test("even rehashed observations cannot change bytes, final path, connection family or publication eligibility", () => {
  for (const mutate of [
    (d) => (d.source.state = "staging"),
    (d) => (d.source.state = "succeeded"),
    (d) => (d.source.attempts = 0),
    (d) => d.source.fence++,
    (d) => (d.effect.path += ".partial"),
    (d) => (d.effect.address = "other.invalid:22"),
    (d) => (d.effect.user = "other"),
    (d) => (d.observer.connection.id = other),
    (d) => (d.authorized_file.id = other),
    (d) => (d.authorized_file.sha256 = "f".repeat(64)),
    (d) => (d.wire.sha256 = "f".repeat(64)),
    (d) => d.wire.size_bytes++,
    (d) =>
      (d.wire.ciphertext = {
        object_id: other,
        sha256: d.wire.sha256,
        size_bytes: d.wire.size_bytes,
      }),
  ]) {
    const f = fresh(),
      d = f.preview.definition;
    mutate(d);
    d.probe.hash = observationHash(d.observer);
    assert.throws(() => asObservationDefinition(d, author, f.plan_id));
  }
});
test("receipt proposals and history cannot invent approval, success or another actor", () => {
  const f = fresh(),
    r = {
      replayed: false,
      resource: { kind: "onboarding_observation", observation: f.summary },
    },
    expected = {
      hash: f.preview.definition_hash,
      state: "proposed",
      source: f.selection.source_run_id,
    };
  assert.equal(asObservationReceipt(r, author, expected).id, f.summary.id);
  for (const mutate of [
    (r) => (r.resource.observation.state = "approved"),
    (r) => (r.resource.observation.author_id = other),
    (r) => (r.resource.observation.source_run_id = other),
    (r) => (r.resource.observation.result.integrity_confirmed = true),
    (r) => (r.resource.observation.result.business_acceptance = "accepted"),
  ]) {
    const x = structuredClone(r);
    mutate(x);
    assert.throws(() => asObservationReceipt(x, author, expected));
  }
  assert.equal(
    asObservationPage({ observations: [f.summary] }, author).observations
      .length,
    1,
  );
  assert.throws(() =>
    asObservationPage({ observations: [f.summary, f.summary] }, author),
  );
});
test("terminal integrity is exact wire evidence with no fsync, business acceptance or GET contact", () => {
  const f = fresh(),
    s = f.summary;
  Object.assign(s, {
    state: "succeeded",
    revision: 4,
    worker_key: "fixture-observation",
    lease_owner: other,
    started_at: "2026-10-30T01:00:00Z",
    lease_until: "2026-10-30T01:00:30Z",
    completed_at: "2026-10-30T01:00:20Z",
  });
  Object.assign(s.result, {
    code: "remote_file_integrity_observed",
    integrity_confirmed: true,
    reconciled: true,
    sha256: f.preview.definition.wire.sha256,
    size_bytes: f.preview.definition.wire.size_bytes,
  });
  const v = {
      observation: { ...s, definition: f.preview.definition },
      current_bindings: false,
      binding_reason: "succeeded",
      contact_attempted: false,
      resend_authorized: false,
      observed_at: "2026-10-30T01:00:21Z",
    },
    expected = { id: s.id, hash: s.definition_hash };
  assert.equal(
    asObservationView(v, author, f.plan_id, expected).observation.result
      .integrity_confirmed,
    true,
  );
  for (const mutate of [
    (v) => (v.resend_authorized = true),
    (v) => (v.current_bindings = true),
    (v) => (v.contact_attempted = true),
    (v) => (v.observation.result.sha256 = "f".repeat(64)),
    (v) => (v.observation.result.file_fsync_acknowledged = true),
    (v) => (v.observation.completed_at = "2026-10-30T01:00:31Z"),
  ]) {
    const x = structuredClone(v);
    mutate(x);
    assert.throws(() => asObservationView(x, author, f.plan_id, expected));
  }
  const work = structuredClone(v);
  work.contact_attempted = true;
  assert.equal(
    asObservationView(work, author, f.plan_id, expected, true)
      .contact_attempted,
    true,
  );
  work.observation.result.business_acceptance = "accepted";
  assert.throws(() => asObservationSummary(work.observation, author));
  const boundary = structuredClone(v);
  boundary.observation.started_at = "2026-10-30T01:00:00.123456Z";
  boundary.observation.lease_until = "2026-10-30T01:00:30.123456Z";
  boundary.observation.completed_at = "2026-10-30T01:00:30.123455Z";
  assert.equal(
    asObservationView(boundary, author, f.plan_id, expected).observation.result
      .integrity_confirmed,
    true,
  );
  boundary.observation.completed_at = boundary.observation.lease_until;
  assert.throws(() => asObservationView(boundary, author, f.plan_id, expected));
});
