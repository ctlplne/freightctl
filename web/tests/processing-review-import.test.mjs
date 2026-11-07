import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";
const modules = {};
for (const [key, name] of [
  ["importer", "processing-review-import.ts"],
  ["api", "processing-review-api.ts"],
]) {
  const built = await build({
    entryPoints: [new URL("../src/" + name, import.meta.url).pathname],
    bundle: true,
    write: false,
    format: "esm",
    target: "es2022",
  });
  modules[key] = await import(
    "data:text/javascript;base64," +
      Buffer.from(built.outputFiles[0].contents).toString("base64")
  );
}
const { importReviewRecoveryFile } = modules.importer,
  { reviewRecovery, reviewMutation } = modules.api,
  fixture = JSON.parse(
    await readFile(new URL("fixtures/processing-review.json", import.meta.url)),
  ),
  origin = "https://freightctl.test";
function context() {
  const session = {
      identity: {
        tenant_id: "11111111-1111-4111-8111-111111111111",
        partner_id: "22222222-2222-4222-8222-222222222222",
        actor_id: fixture.definition.author.actor_id,
        authority_revision: 7,
        root_policy_digest: fixture.definition.author.namespace_root_digest,
        permissions: ["workflow_manage", "workflow_execute"],
      },
      session: {
        id: "44444444-4444-4444-8444-444444444444",
        state: "active",
        expires_at: "2027-01-01T00:00:00Z",
      },
      csrf_token: "PRIVATE_REVIEW_CSRF",
      limits: {},
    },
    mutation = reviewMutation({
      kind: "request",
      body: {
        workflow: fixture.definition.workflow,
        expected_revision: 1,
        reviewer_id: fixture.definition.reviewer.actor_id,
        expires_at: fixture.definition.expires_at,
      },
      key: "original-review-request",
    }),
    recovery = reviewRecovery(mutation, session, origin),
    text = JSON.stringify(recovery),
    prepared = [];
  return {
    mutation,
    recovery,
    prepared,
    options: {
      session,
      origin,
      file: { size: Buffer.byteLength(text), text: async () => text },
      current: () => true,
      busy: () => false,
      prepare: async (m) => {
        prepared.push(m);
      },
    },
  };
}
test("foreign recovery is refused during background inspection instead of silently discarded", async () => {
  const c = context();
  c.recovery.server_origin = "https://unapproved.invalid";
  c.options.file.text = async () => JSON.stringify(c.recovery);
  c.options.busy = () => true;
  await assert.rejects(
    importReviewRecoveryFile(c.options),
    (e) => e.code === "invalid_processing_review",
  );
  assert.deepEqual(c.prepared, []);
});
test("valid recovery during inspection gets explicit retry refusal without preparing or changing its key", async () => {
  const c = context();
  c.options.busy = () => true;
  await assert.rejects(
    importReviewRecoveryFile(c.options),
    (e) => e.code === "review_inspection_busy",
  );
  assert.deepEqual(c.prepared, []);
  c.options.busy = () => false;
  await importReviewRecoveryFile(c.options);
  assert.deepEqual(c.prepared, [c.mutation]);
});
test("an inspection starting after file selection cannot silently consume the recovery", async () => {
  const c = context();
  let busy = false;
  const text = c.options.file.text;
  c.options.busy = () => busy;
  c.options.file.text = async () => {
    busy = true;
    return text();
  };
  await assert.rejects(
    importReviewRecoveryFile(c.options),
    (e) => e.code === "review_inspection_busy",
  );
  assert.deepEqual(c.prepared, []);
});
test("reading recovery cannot carry approval across an authority or session change", async () => {
  const c = context();
  let current = true;
  const text = c.options.file.text;
  c.options.file.text = async () => {
    current = false;
    return text();
  };
  c.options.current = () => current;
  await assert.rejects(
    importReviewRecoveryFile(c.options),
    (e) => e.code === "session_changed",
  );
  assert.deepEqual(c.prepared, []);
});
test("oversized recovery refuses before reading even when inspection is busy", async () => {
  const c = context();
  let reads = 0;
  c.options.file.size = 32769;
  c.options.file.text = async () => {
    reads++;
    return "";
  };
  c.options.busy = () => true;
  await assert.rejects(importReviewRecoveryFile(c.options));
  assert.equal(reads, 0);
  assert.deepEqual(c.prepared, []);
});
