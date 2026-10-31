import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";
const built = await build({
  entryPoints: ["src/onboarding-approvals-types.ts"],
  absWorkingDir: new URL("..", import.meta.url).pathname,
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const {
  asApprovalPreview,
  asApprovalReview,
  asApprovalPage,
  asApprovalSummary,
  asApprovalResult,
  asApprovalPolicy,
  approvalHash,
} = await import(
  "data:text/javascript;base64," +
    Buffer.from(built.outputFiles[0].contents).toString("base64")
);
const f = JSON.parse(
    await readFile(
      new URL("fixtures/onboarding-approval.json", import.meta.url),
      "utf8",
    ),
  ),
  fresh = () => structuredClone(f),
  owner = f.review.author_id,
  reviewer = f.review.reviewer_id,
  other = "000000f4-1111-4111-8111-111111111111";
test("independent review uses exact Go package and release hashes, without contact or file access", () => {
  const p = asApprovalPreview(f.preview, owner, f.selection);
  assert.equal(approvalHash(p.definition), p.definition_hash);
  assert.equal(p.external_contact, false);
  assert.equal(p.grants_file_access, false);
  assert.equal(
    asApprovalReview(f.review, reviewer).definition.release_hash,
    f.selection.definition_hash,
  );
});
test("even rehashed review packages cannot invent self approval, policy, release bytes or effect coverage", () => {
  for (const mutate of [
    (d) => (d.reviewer_id = d.author_id),
    (d) => d.policy.revision++,
    (d) => d.release_revision++,
    (d) => (d.release_hash = "a".repeat(64)),
    (d) => d.effects.push(structuredClone(d.effects[0])),
    (d) => (d.effects[0].requirement_id = other),
  ]) {
    const x = fresh();
    mutate(x.preview.definition);
    x.preview.definition_hash = approvalHash(x.preview.definition);
    assert.throws(() => asApprovalPreview(x.preview, owner, x.selection));
  }
});
test("unbound file/recipient/key mutations cannot reuse the original review hash or flags", () => {
  for (const mutate of [
    (p) => (p.definition.effects[0].file.sha256 = "b".repeat(64)),
    (p) => (p.definition.effects[0].effect.address = "untrusted.invalid:22"),
    (p) => p.definition.reviewer_authority_revision++,
    (p) => (p.external_contact = true),
    (p) => (p.grants_file_access = true),
  ]) {
    const x = fresh();
    mutate(x.preview);
    assert.throws(() => asApprovalPreview(x.preview, owner, x.selection));
  }
});
test("review history refuses other actors, duplicate rows and impossible terminal revisions", () => {
  assert.equal(
    asApprovalPage({ reviews: [f.summary] }, reviewer).reviews.length,
    1,
  );
  assert.throws(() => asApprovalSummary(f.summary, other));
  assert.throws(() =>
    asApprovalPage({ reviews: [f.summary, f.summary] }, reviewer),
  );
  for (const state of ["approved", "rejected", "withdrawn"]) {
    assert.throws(() => asApprovalSummary({ ...f.summary, state }, reviewer));
  }
});
test("review retry receipt must bind the exact operation result and reviewed revision", () => {
  const s = { ...f.summary, state: "approved", revision: 2 },
    v = { resource: { kind: "onboarding_approval", review: s } };
  assert.equal(
    asApprovalResult(v, reviewer, {
      hash: s.definition_hash,
      id: s.id,
      state: "approved",
      revision: 2,
    }).state,
    "approved",
  );
  for (const expected of [
    { hash: s.definition_hash, id: other, state: "approved", revision: 2 },
    { hash: s.definition_hash, id: s.id, state: "pending", revision: 1 },
  ])
    assert.throws(() => asApprovalResult(v, reviewer, expected));
});
test("default policy is author approval at revision zero; explicit policy is versioned", () => {
  assert.deepEqual(asApprovalPolicy({ revision: 0, mode: "author" }), {
    revision: 0,
    mode: "author",
  });
  assert.throws(() => asApprovalPolicy({ revision: 0, mode: "independent" }));
  assert.throws(() =>
    asApprovalPolicy({ revision: 1, mode: "independent", author_id: owner }),
  );
  assert.equal(
    asApprovalPolicy({
      revision: 1,
      mode: "independent",
      author_id: owner,
      event_id: other,
    }).mode,
    "independent",
  );
});
