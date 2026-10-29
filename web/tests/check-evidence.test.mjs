import assert from "node:assert/strict";
import { test } from "node:test";
import { build } from "esbuild";
import path from "node:path";
import { fileURLToPath } from "node:url";
const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const bundle = await build({
  absWorkingDir: web,
  entryPoints: ["src/types.ts"],
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const { asCheckView } = await import(
  "data:text/javascript;base64," +
    Buffer.from(bundle.outputFiles[0].contents).toString("base64")
);
const id = "11111111-1111-4111-8111-111111111111",
  objectID = "22222222-2222-4222-8222-222222222222",
  keyID = "33333333-3333-4333-8333-333333333333";
const source = "a".repeat(64),
  policy = "b".repeat(64),
  signature = "c".repeat(64),
  keyHash = "d".repeat(64),
  reportHash = "e".repeat(64);
function view() {
  const key = { id: keyID, version: 1, hash: keyHash };
  return {
    current: true,
    requirements: { signature_required: true, scanner_required: false },
    signature: {
      file_id: id,
      object_id: objectID,
      data_sha256: source,
      policy_hash: policy,
      sha256: signature,
      key,
    },
    check: {
      file_id: id,
      state: "passed",
      revision: 4,
      attempts: 1,
      code: "valid_csv",
      policy_hash: policy,
      report_hash: reportHash,
      binding: { file: { sha256: source }, target: { path: "/signed.csv" } },
      report: {
        engine: "freightctl-csv-v1",
        file_id: id,
        sha256: source,
        policy_hash: policy,
        rows: 2,
        bytes_read: 70,
        code: "valid_csv",
        signature: {
          key: { ...key },
          object_id: objectID,
          sha256: signature,
          verification: {
            primary_fingerprint: "f".repeat(40),
            signer_fingerprint: "0".repeat(40),
            signature_sha256: signature,
            hash_algorithm: "SHA-256",
            signature_version: 4,
            created_at: "2026-10-29T10:00:00Z",
            verified_at: "2026-10-29T10:00:01.123456Z",
            valid_until: "2026-10-29T11:00:00Z",
          },
        },
      },
    },
  };
}
function refuse(value) {
  assert.throws(
    () => asCheckView(value),
    (e) => e.code === "invalid_server_response" && e.status === 502,
  );
}
test("recorded signer proof stays bound to exact file, policy, attachment and key", () => {
  const v = asCheckView(view());
  assert.equal(v.signatureProof.primary, "f".repeat(40));
  assert.equal(v.signatureProof.signer, "0".repeat(40));
  assert.equal(v.signatureProof.keyID, keyID);
  assert.equal(v.validation.rows, 2);
  assert.equal(v.signatureProof.signatureSHA256, signature);
});
test("wrong file/policy/signature/key joins cannot become visible verification evidence", () => {
  const mutations = [
    (v) => (v.check.report.file_id = keyID),
    (v) => (v.check.report.sha256 = policy),
    (v) => (v.check.report.policy_hash = source),
    (v) => (v.signature.data_sha256 = policy),
    (v) => (v.signature.policy_hash = source),
    (v) => (v.check.report.signature.object_id = id),
    (v) => (v.check.report.signature.sha256 = source),
    (v) => (v.check.report.signature.verification.signature_sha256 = source),
    (v) => (v.check.report.signature.key.hash = source),
    (v) => (v.check.report.signature.key.version = 2),
    (v) => (v.check.report.signature.key.id = id),
  ];
  for (const mutate of mutations) {
    const v = view();
    mutate(v);
    refuse(v);
  }
});
test("malformed fingerprints, weak digest labels, format versions and impossible dates fail closed", () => {
  const mutations = [
    (p) => (p.primary_fingerprint = "<img src=x>"),
    (p) => (p.signer_fingerprint = "a".repeat(41)),
    (p) => (p.hash_algorithm = "SHA-1"),
    (p) => (p.signature_version = 3),
    (p) => (p.created_at = "2026-10-29T12:00:00Z"),
    (p) => (p.valid_until = "2026-10-29T09:00:00Z"),
    (p) => (p.verified_at = "2026-02-31T10:00:00Z"),
    (p) => (p.verified_at = "garbage"),
  ];
  for (const mutate of mutations) {
    const v = view();
    mutate(v.check.report.signature.verification);
    refuse(v);
  }
});
test("nanosecond ordering keeps a still-valid submillisecond proof and refuses expired equality", () => {
  const v = view(),
    p = v.check.report.signature.verification;
  p.verified_at = "2026-10-29T10:00:01.123456Z";
  p.valid_until = "2026-10-29T10:00:01.123457Z";
  assert.ok(asCheckView(v).signatureProof);
  p.valid_until = p.verified_at;
  refuse(v);
});
test("signed success requires both a stored attachment and a complete proof", () => {
  let v = view();
  delete v.check.report.signature;
  refuse(v);
  v = view();
  delete v.signature;
  refuse(v);
  v = view();
  v.check.report = null;
  refuse(v);
  v = view();
  v.check.report_hash = "";
  refuse(v);
});
test("unsigned, held, failed and historical views preserve their actual scope", () => {
  const v = view();
  delete v.signature;
  delete v.check.report.signature;
  v.requirements.signature_required = false;
  assert.equal(asCheckView(v).signatureProof, null);
  v.check.state = "held";
  v.check.report = {};
  v.check.report_hash = "";
  v.check.attempts = 0;
  assert.equal(asCheckView(v).validation, null);
  const failed = view();
  failed.check.state = "failed";
  failed.check.code = "invalid_csv";
  assert.ok(asCheckView(failed).signatureProof);
  const historical = view();
  historical.current = false;
  historical.check.state = "released";
  assert.equal(asCheckView(historical).current, false);
});
test("supported v6 and SHA3 report labels retain full 64-character fingerprints", () => {
  const v = view(),
    p = v.check.report.signature.verification;
  p.signature_version = 6;
  p.hash_algorithm = "SHA3-256";
  p.primary_fingerprint = "f".repeat(64);
  p.signer_fingerprint = "0".repeat(64);
  assert.equal(asCheckView(v).signatureProof.primary.length, 64);
});

function recovering() {
  const v = view();
  v.check.state = "running";
  v.check.revision = 2;
  v.check.attempts = 1;
  v.check.report = {};
  v.check.report_hash = "";
  delete v.signature;
  v.check.worker_id = objectID;
  v.check.lease_until = "2026-10-29T08:00:00.123456-04:00";
  v.recovery = {
    observed_at: "2026-10-29T12:00:00.123456Z",
    eligible: true,
    code: "ready",
    decision: {
      expected_revision: 2,
      expected_worker_id: objectID,
      expected_lease_until: "2026-10-29T12:00:00.123456Z",
      sha256: source,
      policy_hash: policy,
    },
  };
  return v;
}
test("recovery binds the exact reservation and uses server time across UTC offsets", () => {
  const v = asCheckView(recovering());
  assert.equal(v.recovery.eligible, true);
  assert.equal(v.recovery.decision.expected_worker_id, objectID);
});
test("recovery rejects mismatched worker/revision/source/policy/lease and forged eligibility", () => {
  const mutations = [
    (v) => v.recovery.decision.expected_revision++,
    (v) => (v.recovery.decision.expected_worker_id = keyID),
    (v) => (v.recovery.decision.sha256 = policy),
    (v) => (v.recovery.decision.policy_hash = source),
    (v) =>
      (v.recovery.decision.expected_lease_until =
        "2026-10-29T12:00:00.123457Z"),
    (v) => (v.recovery.observed_at = "2026-10-29T12:00:00.123455Z"),
    (v) => (v.check.attempts = 3),
    (v) => (v.current = false),
    (v) => (v.recovery.code = "lease_active"),
    (v) => (v.recovery.code = "unknown"),
    (v) => (v.check.state = "passed"),
  ];
  for (const mutate of mutations) {
    const v = recovering();
    mutate(v);
    refuse(v);
  }
});
test("active and exhausted leases remain non-executable without consulting the browser clock", () => {
  const live = recovering();
  live.recovery.observed_at = "2026-10-29T11:59:59Z";
  live.recovery.eligible = false;
  live.recovery.code = "lease_active";
  assert.equal(asCheckView(live).recovery.eligible, false);
  const exhausted = recovering();
  exhausted.check.attempts = 3;
  exhausted.recovery.eligible = false;
  exhausted.recovery.code = "attempt_budget_exhausted";
  assert.equal(asCheckView(exhausted).recovery.eligible, false);
});
