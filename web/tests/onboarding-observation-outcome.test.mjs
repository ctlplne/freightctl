import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";
const built = await build({
  entryPoints: ["src/onboarding-releases-types.ts"],
  absWorkingDir: new URL("..", import.meta.url).pathname,
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const { asRecoveredTransportReceipt } = await import(
  "data:text/javascript;base64," +
    Buffer.from(built.outputFiles[0].contents).toString("base64")
);
test("original production outcome accepts only exact historical wire evidence and preserves business uncertainty", async () => {
  const f = JSON.parse(
      await readFile(
        new URL("fixtures/onboarding-observation.json", import.meta.url),
        "utf8",
      ),
    ),
    s = f.summary,
    d = f.preview.definition;
  Object.assign(s, {
    state: "succeeded",
    revision: 4,
    worker_key: "fixture-observation",
    lease_owner: "000000af-1111-4111-8111-111111111111",
    started_at: "2026-10-30T01:00:00Z",
    lease_until: "2026-10-30T01:00:30Z",
    completed_at: "2026-10-30T01:00:20Z",
  });
  Object.assign(s.result, {
    code: "remote_file_integrity_observed",
    integrity_confirmed: true,
    reconciled: true,
    sha256: d.wire.sha256,
    size_bytes: d.wire.size_bytes,
  });
  const outcome = { state: "integrity_confirmed", observation: s },
    check = (o) =>
      asRecoveredTransportReceipt(
        o,
        s.author_id,
        s.source_run_id,
        d.wire.sha256,
        d.wire.size_bytes,
        false,
      );
  assert.equal(check(outcome).id, s.id);
  assert.equal(check({ state: "unresolved" }), undefined);
  for (const mutate of [
    (o) => (o.state = "unresolved"),
    (o) => delete o.observation,
    (o) =>
      (o.observation.source_run_id = "000000ae-1111-4111-8111-111111111111"),
    (o) => (o.observation.result.sha256 = "a".repeat(64)),
    (o) => o.observation.result.size_bytes++,
    (o) => (o.observation.result.business_acceptance = "accepted"),
    (o) => (o.observation.result.file_fsync_acknowledged = true),
  ]) {
    const x = structuredClone(outcome);
    mutate(x);
    assert.throws(() => check(x));
  }
  assert.equal(
    asRecoveredTransportReceipt(
      { state: "integrity_confirmed" },
      s.author_id,
      s.source_run_id,
      d.wire.sha256,
      d.wire.size_bytes,
      true,
    ),
    undefined,
  );
});
