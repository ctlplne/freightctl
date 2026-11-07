import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";
import { createHash } from "node:crypto";
const built = await build({
  entryPoints: [
    new URL("../src/processing-review-api.ts", import.meta.url).pathname,
  ],
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const p = await import(
  "data:text/javascript;base64," +
    Buffer.from(built.outputFiles[0].contents).toString("base64")
);
const fixture = JSON.parse(
  await readFile(
    new URL("fixtures/processing-review.json", import.meta.url),
    "utf8",
  ),
);
const session = () => ({
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
});
test("review browser reconstructs independent canonical meaning and refuses private or changed fields", () => {
  const row = p.processingReview(fixture);
  assert.equal(row.definition_hash, fixture.definition_hash);
  for (const mutate of [
    (r) => (r.definition.definition.processing.reason = "changed reason"),
    (r) => (r.definition.reviewer.actor_id = r.definition.author.actor_id),
    (r) => (r.definition.source_file_id = "hidden"),
    (r) => (r.approved = true),
    (r) => (r.adopted_revision = 3),
  ]) {
    const r = structuredClone(fixture);
    mutate(r);
    assert.throws(() => p.processingReview(r));
  }
});
test("review recovery binds exact meaning,key,origin and participant without credentials", () => {
  const s = session();
  const m = p.reviewMutation({
    kind: "adopt",
    id: fixture.id,
    body: { definition_hash: fixture.definition_hash, expected_revision: 2 },
    key: "original-adoption",
  });
  const recovery = p.reviewRecovery(m, s, "https://freightctl.test");
  const text = JSON.stringify(recovery);
  assert.equal(text.includes(s.csrf_token), false);
  assert.equal(text.includes(s.session.id), false);
  assert.deepEqual(
    p.parseReviewRecovery(text, s, "https://freightctl.test"),
    m,
  );
  for (const mutate of [
    (r) => (r.request.key = "other"),
    (r) => r.request.body.expected_revision++,
    (r) => (r.server_origin = "https://other.test"),
    (r) => r.participant.authority_revision++,
    (r) => (r.request.body.approved = true),
  ]) {
    const r = structuredClone(recovery);
    mutate(r);
    assert.throws(() =>
      p.parseReviewRecovery(JSON.stringify(r), s, "https://freightctl.test"),
    );
  }
});

const summary = (row = fixture) => ({
  id: row.id,
  author_id: row.definition.author.actor_id,
  reviewer_id: row.definition.reviewer.actor_id,
  workflow_id: row.definition.workflow.id,
  workflow_version: row.definition.workflow.version,
  definition_hash: row.definition_hash,
  state: row.state,
  revision: row.revision,
  adopted_revision: row.adopted_revision,
  expires_at: row.definition.expires_at,
});
const request = () =>
  p.reviewMutation({
    kind: "request",
    body: {
      workflow: fixture.definition.workflow,
      expected_revision: 1,
      reviewer_id: fixture.definition.reviewer.actor_id,
      expires_at: fixture.definition.expires_at,
    },
    key: "original-review-request",
  });
test("a lost review reply recovers one exact original command after a new browser session", async () => {
  const first = session(),
    m = request(),
    saved = JSON.stringify(
      p.reviewRecovery(m, first, "https://freightctl.test"),
    );
  const calls = [];
  let committed = 0;
  const api = {
    session: first,
    prefix:
      "/v1/tenants/" +
      first.identity.tenant_id +
      "/partners/" +
      first.identity.partner_id,
    request: async (path, options, decode) => {
      calls.push({
        path,
        body: options.body,
        key: options.headers["Idempotency-Key"],
      });
      if (calls.length === 1) {
        committed++;
        throw new Error("reply lost after commit");
      }
      return decode({ resource: summary(), replayed: true });
    },
  };
  await assert.rejects(new p.ProcessingReviewApi(api).mutate(m));
  api.session = structuredClone(first);
  api.session.session.id = "99999999-9999-4999-8999-999999999999";
  const recovered = p.parseReviewRecovery(
    saved,
    api.session,
    "https://freightctl.test",
  );
  const receipt = await new p.ProcessingReviewApi(api).mutate(recovered);
  assert.equal(committed, 1);
  assert.equal(receipt.replayed, true);
  assert.deepEqual(calls[0], calls[1]);
  assert.equal(calls[0].body.includes(first.csrf_token), false);
});
test("review client refuses revoked roles and in-flight scope changes outside the server", async () => {
  const s = session();
  let called = 0;
  const api = {
    session: s,
    prefix:
      "/v1/tenants/" +
      s.identity.tenant_id +
      "/partners/" +
      s.identity.partner_id,
    request: async () => {
      called++;
      throw new Error("must not contact");
    },
  };
  api.session.identity.permissions = ["workflow_execute"];
  assert.throws(() => new p.ProcessingReviewApi(api).mutate(request()));
  assert.equal(called, 0);
  for (const change of [
    (s) => s.identity.authority_revision++,
    (s) => (s.identity.root_policy_digest = "f".repeat(64)),
    (s) => (s.session.id = "99999999-9999-4999-8999-999999999999"),
  ]) {
    const s = session();
    let complete;
    const api = {
      session: s,
      prefix:
        "/v1/tenants/" +
        s.identity.tenant_id +
        "/partners/" +
        s.identity.partner_id,
      request: async (_path, _options, decode) =>
        new Promise((resolve, reject) => {
          complete = () => {
            try {
              resolve(decode(fixture));
            } catch (e) {
              reject(e);
            }
          };
        }),
    };
    const pending = new p.ProcessingReviewApi(api).get(fixture.id);
    change(api.session);
    complete();
    await assert.rejects(pending);
  }
});
test("original independent approval stays historical after current adoption and payload injection refuses", async () => {
  const s = session();
  s.identity.actor_id = fixture.definition.reviewer.actor_id;
  s.identity.authority_revision =
    fixture.definition.reviewer.authority_revision;
  s.identity.root_policy_digest =
    fixture.definition.reviewer.namespace_root_digest;
  s.identity.permissions = ["inspect", "workflow_approve"];
  const current = structuredClone(fixture);
  current.state = "adopted";
  current.revision = 3;
  current.adopted_revision = 3;
  let response = {
    resource: { ...summary(), state: "approved", revision: 2 },
    replayed: true,
  };
  const api = {
    session: s,
    prefix:
      "/v1/tenants/" +
      s.identity.tenant_id +
      "/partners/" +
      s.identity.partner_id,
    request: async (_p, _o, decode) => decode(response),
  };
  const client = new p.ProcessingReviewApi(api),
    m = p.reviewMutation({
      kind: "approve",
      id: fixture.id,
      body: { definition_hash: fixture.definition_hash, expected_revision: 1 },
      key: "old-approval",
    });
  const receipt = await client.mutate(m, p.processingReview(current));
  assert.equal(receipt.summary.state, "approved");
  assert.equal(current.state, "adopted");
  response.resource.definition = fixture.definition;
  await assert.rejects(client.mutate(m, p.processingReview(current)));
  s.identity.permissions = ["workflow_approve"];
  assert.throws(() => client.mutate(m, p.processingReview(current)));
});

test("review timestamps preserve microsecond meaning and refuse invalid calendar dates", () => {
  const r = structuredClone(fixture);
  r.definition.expires_at = "2026-11-06T00:00:00.000001Z";
  const wire = JSON.stringify(r.definition)
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e")
    .replaceAll("&", "\\u0026")
    .replaceAll("\u2028", "\\u2028")
    .replaceAll("\u2029", "\\u2029");
  r.definition_hash = createHash("sha256").update(wire).digest("hex");
  assert.equal(
    p.processingReview(r).definition.expires_at,
    r.definition.expires_at,
  );
  assert.equal(
    p.reviewTime("2026-11-06T01:02:03.120000Z"),
    "2026-11-06T01:02:03.12Z",
  );
  for (const value of [
    "2026-02-30T00:00:00Z",
    "2026-11-06T24:00:00Z",
    "2026-11-06T00:00:00.0000001Z",
    "2026-11-06T00:00:00Z;approve",
  ])
    assert.throws(() => p.reviewTime(value));
});
