import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";
import path from "node:path";
import { fileURLToPath } from "node:url";
const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const bundle = await build({
  absWorkingDir: web,
  entryPoints: ["src/onboarding-exchange-types.ts"],
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const { asExchangeReview, exchangeSnapshotHash } = await import(
  "data:text/javascript;base64," +
    Buffer.from(bundle.outputFiles[0].contents).toString("base64")
);
const fixture = JSON.parse(
  await readFile(
    path.join(web, "tests/fixtures/onboarding-exchange-review.json"),
    "utf8",
  ),
);
const fresh = () => structuredClone(fixture),
  expected = fixture.snapshot.selection;
test("onboarding review binds exact selected evidence and shares Go snapshot hash", () => {
  const v = asExchangeReview(fresh(), expected);
  assert.equal(exchangeSnapshotHash(v.snapshot), fixture.snapshot_hash);
  assert.equal(v.production_active, false);
  assert.equal(v.business_acceptance, "unknown");
  for (const field of [
    "probe_id",
    "run_id",
    "step_id",
    "requirement_id",
    "expected_authority_revision",
  ]) {
    const r = structuredClone(expected);
    r[field] = field === "expected_authority_revision" ? 8 : "changed";
    assert.throws(() => asExchangeReview(fresh(), r));
  }
});
test("onboarding review cannot invent business acceptance, activation, contact or completed evidence", () => {
  for (const mutate of [
    (v) => (v.business_acceptance = "accepted"),
    (v) => (v.production_active = true),
    (v) => (v.external_contact = true),
    (v) => (v.snapshot.file.sha256 = "a".repeat(64)),
    (v) => (v.snapshot.required_receipt = "business"),
    (v) => (v.snapshot.file_fsync_acknowledged = false),
    (v) => (v.snapshot.probe.id = fixture.snapshot.file.id),
    (v) => (v.snapshot.probe_completed_at = null),
  ]) {
    const v = fresh();
    mutate(v);
    assert.throws(() => asExchangeReview(v, expected));
  }
  const business = fresh();
  business.snapshot.required_receipt = "business";
  business.snapshot_hash = exchangeSnapshotHash(business.snapshot);
  business.ready_for_approval_review = false;
  business.reason = "business_receipt_missing";
  assert.equal(
    asExchangeReview(business, expected).ready_for_approval_review,
    false,
  );
  const unfinished = fresh();
  unfinished.snapshot.observed_receipt = "none";
  unfinished.snapshot.transfer_sha256 = "";
  unfinished.snapshot.transfer_bytes = 0;
  unfinished.snapshot.file_fsync_acknowledged = false;
  unfinished.snapshot.probe_completed_at = null;
  unfinished.ready_for_approval_review = false;
  unfinished.reason = "probe_not_succeeded";
  unfinished.snapshot_hash = exchangeSnapshotHash(unfinished.snapshot);
  assert.equal(
    asExchangeReview(unfinished, expected).snapshot.observed_receipt,
    "none",
  );
});
