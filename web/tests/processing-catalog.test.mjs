import assert from "node:assert/strict";
import { test } from "node:test";
import { build } from "esbuild";
const built = await build({
  entryPoints: [
    new URL("../src/processing-catalog-types.ts", import.meta.url).pathname,
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
const id = "11111111-1111-4111-8111-111111111111",
  hash = "a".repeat(64);
const fixture = () => ({
  profile: "processing-workflow-catalog-v1",
  authority_revision: 7,
  namespace_root_digest: hash,
  workflows: [
    {
      id,
      version: 2,
      hash,
      name: "Settlement processing",
      state: "draft",
      revision: 1,
      kind: "records.project",
      source_policy_hash: hash,
      output_kind: "json_records",
      column_count: 2,
      output_policy: { id, version: 2, hash },
      approval_current: false,
      output_policy_current: true,
    },
  ],
});
test("processing catalog preserves independent approval and policy facts without execution claims", () => {
  const page = p.processingCatalog(fixture());
  assert.equal(page.workflows[0].approval_current, false);
  assert.equal(page.workflows[0].output_policy_current, true);
  for (const mutate of [
    (p) => (p.workflows[0].approval_current = true),
    (p) => (p.workflows[0].definition = {}),
    (p) => (p.workflows[0].reason = "hidden"),
    (p) => (p.execution_ready = true),
    (p) => p.workflows.push(structuredClone(p.workflows[0])),
    (p) => (p.namespace_root_digest = "bad"),
  ]) {
    const value = fixture();
    mutate(value);
    assert.throws(() => p.processingCatalog(value));
  }
});

const clientBundle = await build({
  entryPoints: [new URL("../src/processing-api.ts", import.meta.url).pathname],
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const { ProcessingApi } = await import(
  "data:text/javascript;base64," +
    Buffer.from(clientBundle.outputFiles[0].contents).toString("base64")
);
const session = () => ({
  identity: {
    tenant_id: "22222222-2222-4222-8222-222222222222",
    partner_id: "33333333-3333-4333-8333-333333333333",
    actor_id: "44444444-4444-4444-8444-444444444444",
    authority_revision: 7,
    root_policy_digest: hash,
    permissions: ["workflow_manage"],
  },
  session: {
    id: "55555555-5555-4555-8555-555555555555",
    state: "active",
    expires_at: "2027-01-01T00:00:00Z",
  },
  csrf_token: "PRIVATE_CATALOG_CSRF",
  limits: {},
});
test("catalog metadata needs no file grant and cannot publish mismatched authority or namespace", async () => {
  const s = session();
  let calls = 0,
    value = fixture();
  const api = {
    session: s,
    prefix:
      "/v1/tenants/" +
      s.identity.tenant_id +
      "/partners/" +
      s.identity.partner_id,
    request: async (path, options, decode) => {
      calls++;
      assert.equal(options.method, undefined);
      assert.match(path, /processing-workflows\?limit=25$/);
      return decode(value);
    },
  };
  const client = new ProcessingApi(api);
  const catalog = await client.catalog();
  assert.equal(catalog.workflows[0].id, id);
  assert.deepEqual(s.identity.permissions, ["workflow_manage"]);
  await assert.rejects(client.status(id));
  assert.equal(calls, 1);
  value = { ...fixture(), authority_revision: 8 };
  await assert.rejects(client.catalog());
  value = { ...fixture(), namespace_root_digest: "b".repeat(64) };
  await assert.rejects(client.catalog());
});
