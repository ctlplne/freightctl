import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";
const built = await build({
  entryPoints: [
    new URL("../src/processing-types.ts", import.meta.url).pathname,
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
    new URL("fixtures/processing-workflow.json", import.meta.url),
    "utf8",
  ),
);
test("typed browser definition reproduces independently recorded Go/Python canonical meaning", () => {
  assert.deepEqual(
    p.processingDefinition(fixture.definition),
    fixture.definition,
  );
  assert.equal(p.processingHash(fixture.definition), fixture.definition_hash);
  const c = p.processingContracts(fixture.contracts);
  const original = structuredClone(c);
  c.source_policy.definition.columns[0].name = "changed";
  assert.notDeepEqual(c, original);
  assert.equal(
    fixture.contracts.source_policy.definition.columns[0].name,
    "account",
  );
});
test("browser refuses hidden delivery,execution,changed schemas and unbounded processing meaning", () => {
  for (const mutate of [
    (d) => d.steps.push({ kind: "sftp.deliver" }),
    (d) => (d.approved = true),
    (d) => (d.processing.definition.engine = "shell"),
    (d) => (d.processing.output_policy.hash = ""),
    (d) => (d.processing.target_path = "/../outside"),
    (d) => (d.processing.definition.max_bytes = 0),
    (d) => (d.processing.definition.columns[0].conversion = "eval"),
  ]) {
    const d = structuredClone(fixture.definition);
    mutate(d);
    assert.throws(() => p.processingDefinition(d));
  }
  for (const mutate of [
    (c) => (c.source_policy.definition.columns[0].name = "changed"),
    (c) => (c.output_policy.reference.hash = "f".repeat(64)),
    (c) => (c.source.acceptance_policy = "integrity-only-v1"),
  ]) {
    const c = structuredClone(fixture.contracts);
    mutate(c);
    assert.throws(() => p.processingContracts(c));
  }
});

const apiBundle = await build({
  entryPoints: [new URL("../src/processing-api.ts", import.meta.url).pathname],
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const a = await import(
  "data:text/javascript;base64," +
    Buffer.from(apiBundle.outputFiles[0].contents).toString("base64")
);
const session = () => ({
  identity: {
    tenant_id: "11111111-1111-4111-8111-111111111111",
    partner_id: "22222222-2222-4222-8222-222222222222",
    actor_id: "33333333-3333-4333-8333-333333333333",
    authority_revision: 7,
    root_policy_digest: fixture.contracts.namespace_root_digest,
    permissions: [
      "read",
      "write",
      "check_run",
      "workflow_manage",
      "workflow_approve",
      "workflow_execute",
    ],
  },
  session: {
    id: "44444444-4444-4444-8444-444444444444",
    expires_at: "2027-01-01T00:00:00Z",
    state: "active",
  },
  csrf_token: "PRIVATE_CSRF_TOKEN",
  limits: {},
});
test("saved request recovery fixes its key and meaning,contains no credential,and refuses a different origin or authority", () => {
  const s = session(),
    request = a.processingMutation({
      kind: "draft",
      body: { expected_version: 0, definition: fixture.definition },
      key: "original-draft",
    }),
    saved = a.processingRecovery(request, s, "https://freightctl.test");
  assert.equal(JSON.stringify(saved).includes(s.csrf_token), false);
  assert.equal(JSON.stringify(saved).includes(s.session.id), false);
  assert.deepEqual(
    a.parseProcessingRecovery(
      JSON.stringify(saved),
      s,
      "https://freightctl.test",
    ),
    request,
  );
  const reordered = structuredClone(saved);
  reordered.participant = Object.fromEntries(
    Object.entries(reordered.participant).reverse(),
  );
  assert.deepEqual(
    a.parseProcessingRecovery(
      JSON.stringify(reordered),
      s,
      "https://freightctl.test",
    ),
    request,
  );
  for (const mutate of [
    (r) => (r.request.key = "different"),
    (r) =>
      (r.request.body.definition.processing.output_policy.hash = "f".repeat(
        64,
      )),
    (r) => (r.server_origin = "https://outside.test"),
    (r) => r.participant.authority_revision++,
    (r) => (r.participant.root_policy_digest = "f".repeat(64)),
    (r) => (r.request.body.approved = true),
  ]) {
    const r = structuredClone(saved);
    mutate(r);
    assert.throws(() =>
      a.parseProcessingRecovery(
        JSON.stringify(r),
        s,
        "https://freightctl.test",
      ),
    );
  }
});
test("lost reply recovery resends one exact draft and role changes refuse before transport", async () => {
  const s = session(),
    calls = [],
    request = a.processingMutation({
      kind: "draft",
      body: { expected_version: 0, definition: fixture.definition },
      key: "original-draft",
    });
  let lost = true;
  const reply = {
    resource: {
      id: "55555555-5555-4555-8555-555555555555",
      version: 1,
      definition: fixture.definition,
      definition_hash: fixture.definition_hash,
      state: "draft",
      revision: 1,
      approval_authority: 0,
    },
    replayed: true,
  };
  const api = {
    session: s,
    prefix: "/v1/tenants/t/partners/p",
    request: async (path, options, decode) => {
      calls.push({
        path,
        body: options.body,
        key: options.headers["Idempotency-Key"],
      });
      if (lost) {
        lost = false;
        throw new Error("synthetic committed response loss");
      }
      return decode(reply);
    },
  };
  const client = new a.ProcessingApi(api);
  await assert.rejects(client.mutate(request));
  const saved = a.processingRecovery(request, s, "https://freightctl.test"),
    recovered = a.parseProcessingRecovery(
      JSON.stringify(saved),
      s,
      "https://freightctl.test",
    );
  const result = await client.mutate(recovered);
  assert.equal(result.replayed, true);
  assert.deepEqual(calls[0], calls[1]);
  s.identity.permissions = [];
  await assert.rejects(client.mutate(request));
  assert.equal(calls.length, 2);
});
test("authority/root/session change during a metadata response cannot publish old scope data", async () => {
  const s = session();
  const api = {
    session: s,
    prefix: "/v1/tenants/t/partners/p",
    request: async (path, options, decode) => {
      s.identity.authority_revision++;
      return decode(fixture.contracts);
    },
  };
  const client = new a.ProcessingApi(api);
  await assert.rejects(
    client.contracts(fixture.contracts.source.file_revision_id),
  );
});
