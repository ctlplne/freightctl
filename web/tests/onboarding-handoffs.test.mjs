import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";
const built = await build({
  entryPoints: ["src/onboarding-handoffs-types.ts"],
  absWorkingDir: new URL("..", import.meta.url).pathname,
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const {
  asHandoffDefinition,
  asHandoffPreview,
  asHandoffResult,
  asHandoffView,
  asHandoffPage,
  handoffHash,
} = await import(
  "data:text/javascript;base64," +
    Buffer.from(built.outputFiles[0].contents).toString("base64")
);
const fixture = JSON.parse(
    await readFile(
      new URL("fixtures/onboarding-handoff.json", import.meta.url),
      "utf8",
    ),
  ),
  fresh = () => structuredClone(fixture),
  author = fixture.summary.author_id,
  other = "0000001b-1111-4111-8111-111111111111";
test("queued handoff shares Go hashes and freezes the exact source and target activation", () => {
  const f = fresh(),
    p = asHandoffPreview(f.preview, f.selection, author, f.plan_id);
  assert.equal(handoffHash(p.definition), p.definition_hash);
  for (const mutate of [
    (p) => (p.definition.source.dispatch.id = other),
    (p) => p.definition.source.run_revision++,
    (p) => p.definition.source.delivery.revision++,
    (p) => (p.definition.source.dispatch.author_id = other),
    (p) => p.definition.target.release.revision++,
    (p) => (p.external_contact = true),
  ]) {
    const f = fresh();
    mutate(f.preview);
    assert.throws(() =>
      asHandoffPreview(f.preview, f.selection, author, f.plan_id),
    );
  }
});
test("even rehashed handoff proposals cannot change business bytes or receiver meaning", () => {
  for (const mutate of [
    (d) => (d.source.attempts = 1),
    (d) => (d.source.fence = 1),
    (d) => (d.source.state = "ambiguous"),
    (d) => (d.target.file.sha256 = "9".repeat(64)),
    (d) => (d.target.effect.address = "other.invalid:22"),
    (d) => (d.target.effect.filename = "other.csv"),
    (d) => (d.target.workflow.id = other),
    (d) => (d.target.file.id = other),
    (d) => (d.source_recheck_id = other),
  ]) {
    const f = fresh(),
      d = f.preview.definition;
    mutate(d);
    d.target_hash = handoffHash(d.target);
    assert.throws(() => asHandoffDefinition(d, author, f.plan_id));
  }
  const f = fresh(),
    d = f.preview.definition;
  d.source.dispatch.definition.effect.encryption = {
    key: { id: other, version: 1, hash: "8".repeat(64) },
    profile: "seipd-v1-aes256",
  };
  d.source.dispatch.definition.effect.recipient_fingerprint = "7".repeat(40);
  d.source.dispatch.definition_hash = handoffHash(d.source.dispatch.definition);
  assert.throws(() => asHandoffDefinition(d, author, f.plan_id));
});
test("handoff receipts and private history cannot invent approval, successor or current execution", () => {
  const f = fresh(),
    expected = {
      hash: f.preview.definition_hash,
      state: "proposed",
      source: f.selection.source_run_id,
      target: f.selection.target_release,
    },
    r = {
      replayed: false,
      resource: { kind: "onboarding_handoff", handoff: f.summary },
    };
  assert.equal(asHandoffResult(r, author, expected).id, f.summary.id);
  for (const mutate of [
    (r) => (r.resource.handoff.state = "approved"),
    (r) => (r.resource.handoff.author_id = other),
    (r) => (r.resource.handoff.replacement_run_id = other),
    (r) => (r.resource.handoff.source_run_id = other),
    (r) => r.resource.handoff.target_release.revision++,
    (r) => (r.resource.kind = "onboarding_production"),
  ]) {
    const x = structuredClone(r);
    mutate(x);
    assert.throws(() => asHandoffResult(x, author, expected));
  }
  const value = {
    handoff: { ...f.summary, definition: f.preview.definition },
    current_bindings: true,
    binding_reason: "current",
    external_contact: false,
  };
  assert.equal(
    asHandoffView(value, author, f.plan_id, {
      id: f.summary.id,
      hash: f.summary.definition_hash,
    }).current_bindings,
    true,
  );
  value.handoff.state = "completed";
  value.handoff.revision = 3;
  value.handoff.replacement_run_id = other;
  assert.throws(() =>
    asHandoffView(value, author, f.plan_id, {
      id: f.summary.id,
      hash: f.summary.definition_hash,
    }),
  );
  value.current_bindings = false;
  value.binding_reason = "completed";
  assert.equal(
    asHandoffView(value, author, f.plan_id, {
      id: f.summary.id,
      hash: f.summary.definition_hash,
    }).handoff.replacement_run_id,
    other,
  );
  assert.equal(
    asHandoffPage({ handoffs: [f.summary] }, author).handoffs.length,
    1,
  );
  assert.throws(() =>
    asHandoffPage({ handoffs: [f.summary, f.summary] }, author),
  );
});
