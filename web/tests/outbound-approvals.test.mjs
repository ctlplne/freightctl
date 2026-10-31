import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";
const result = await build({
  entryPoints: ["src/outbound-approvals-types.ts"],
  absWorkingDir: new URL("..", import.meta.url).pathname,
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const {
  asDispatchPreview,
  asDispatchView,
  asDispatchReview,
  asDispatchDefinition,
  asDispatchPage,
  asDispatchResult,
  dispatchHash,
} = await import(
  "data:text/javascript;base64," +
    Buffer.from(result.outputFiles[0].contents).toString("base64")
);
const fixture = JSON.parse(
    await readFile(
      new URL("fixtures/outbound-dispatch.json", import.meta.url),
      "utf8",
    ),
  ),
  fresh = (name = "workflow") => structuredClone(fixture[name]),
  owner = fixture.direct.summary.author_id,
  reviewer = fixture.direct.summary.reviewer_id,
  other = "000000ff-1111-4111-8111-111111111111";
const preview = (f) =>
  asDispatchPreview(
    f.preview,
    owner,
    1,
    f.selection,
    asDispatchView(f.view, f.view.id),
  );
test("plain direct and encrypted workflow dispatch review hashes match exact Go canonical metadata", () => {
  for (const f of Object.values(fixture)) {
    const p = preview(f);
    assert.equal(dispatchHash(p.definition), p.definition_hash);
    assert.equal(p.external_contact, false);
    assert.equal(p.grants_file_access, false);
    assert.equal(
      asDispatchReview(f.review, reviewer, f.summary).definition.delivery_hash,
      f.selection.definition_hash,
    );
    assert.equal(JSON.stringify(p).includes('"key_reference"'), false);
  }
});
test("even rehashed metadata cannot invent self approval, more attempts, another final path or an author policy", () => {
  for (const mutate of [
    (d) => (d.reviewer_id = d.author_id),
    (d) => d.attempt_limit++,
    (d) => (d.namespace_root = "/other"),
    (d) => (d.effect.final_path += ".other"),
    (d) => (d.policy.mode = "author"),
  ]) {
    const f = fresh();
    mutate(f.preview.definition);
    f.preview.definition_hash = dispatchHash(f.preview.definition);
    assert.throws(() => preview(f));
  }
});
test("source, destination, key and workflow mutations cannot escape the owner-selected view even when rehashed", () => {
  for (const mutate of [
    (d) => (d.source.sha256 = "b".repeat(64)),
    (d) => (d.effect.address = "127.0.0.2:22"),
    (d) => (d.effect.key_reference_sha256 = "a".repeat(64)),
    (d) => (d.effect.workflow_binding.run_id = other),
    (d) => (d.effect.recipient_fingerprint = "c".repeat(40)),
    (d) => (d.delivery_hash = "d".repeat(64)),
  ]) {
    const f = fresh();
    mutate(f.preview.definition);
    f.preview.definition_hash = dispatchHash(f.preview.definition);
    assert.throws(() => preview(f));
  }
});
test("a stale policy cannot claim current approval or reviewability; attempted work cannot receive a fresh request", () => {
  for (const mutate of [
    (v) => {
      v.current_policy.revision++;
      v.current_approval = true;
    },
    (v) => {
      v.current_policy.revision++;
      v.reviewable = true;
    },
    (v) => v.attempts++,
    (v) => (v.state = "publishing"),
  ]) {
    const f = fresh();
    mutate(f.view);
    assert.throws(() => asDispatchView(f.view, f.view.id));
  }
});
test("dispatch history refuses unrelated actors, duplicate rows, wrong IDs and impossible terminal states", () => {
  const f = fresh();
  assert.equal(
    asDispatchPage({ reviews: [f.summary] }, reviewer).reviews.length,
    1,
  );
  assert.throws(() => asDispatchPage({ reviews: [f.summary] }, other));
  assert.throws(() =>
    asDispatchPage({ reviews: [f.summary, f.summary] }, owner),
  );
  assert.throws(() =>
    asDispatchReview(f.review, reviewer, { ...f.summary, id: other }),
  );
  assert.throws(() =>
    asDispatchPage(
      { reviews: [{ ...f.summary, state: "approved" }] },
      reviewer,
    ),
  );
});
test("exact original result recovery cannot substitute another delivery, review or transition", () => {
  const f = fresh(),
    r = { ...f.summary, state: "approved", revision: 2 },
    v = { resource: { kind: "outbound_dispatch_review", review: r } },
    x = {
      hash: r.definition_hash,
      id: r.id,
      delivery: r.delivery_id,
      state: "approved",
      revision: 2,
    };
  assert.equal(asDispatchResult(v, reviewer, x).state, "approved");
  for (const bad of [
    { ...x, delivery: other },
    { ...x, id: other },
    { ...x, state: "pending", revision: 1 },
  ])
    assert.throws(() => asDispatchResult(v, reviewer, bad));
});
test("key-reference values, unsafe counts and unsupported protocols are refused before rendering", () => {
  for (const mutate of [
    (d) => (d.effect.key_reference_sha256 = "/private/key"),
    (d) => (d.source.size_bytes = Number.MAX_SAFE_INTEGER + 1),
    (d) => (d.effect.protocol = "ftp"),
    (d) => (d.effect.workflow_binding.step_id = "../../outside"),
  ]) {
    const f = fresh();
    mutate(f.preview.definition);
    assert.throws(() => asDispatchDefinition(f.preview.definition));
  }
});
