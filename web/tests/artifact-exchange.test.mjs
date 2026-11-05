import assert from "node:assert/strict";
import { test } from "node:test";
import { build } from "esbuild";
import { readFile } from "node:fs/promises";
const bundle = await build({
  entryPoints: ["src/artifact-exchanges-types.ts"],
  absWorkingDir: new URL("..", import.meta.url).pathname,
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const p = await import(
  "data:text/javascript;base64," +
    Buffer.from(bundle.outputFiles[0].contents).toString("base64")
);
const apiBundle = await build({
  entryPoints: ["src/artifact-exchanges-api.ts"],
  absWorkingDir: new URL("..", import.meta.url).pathname,
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const a = await import(
  "data:text/javascript;base64," +
    Buffer.from(apiBundle.outputFiles[0].contents).toString("base64")
);
const id = (n) =>
  n.toString(16).padStart(8, "0") + "-1111-4111-8111-111111111111";
const context = {
  tenant: id(1),
  partner: id(2),
  actor: id(3),
  endpoint: id(4),
  after: "",
  limit: 20,
};
function offered(n = 10) {
  const request = {
    schema_version: 1,
    artifact: {
      file_revision_id: id(5),
      size_bytes: 8,
      sha256: "a".repeat(64),
      acceptance_policy: "integrity-only-v1",
    },
    endpoint: { id: context.endpoint, revision: 1, hash: "b".repeat(64) },
    expires_at: "2026-11-05T20:00:00.000001Z",
    receipt: "availability-only-v1",
  };
  return {
    id: id(n),
    state: "offered",
    exchange: {
      id: id(n),
      sender_actor_id: id(6),
      recipient_actor_id: context.actor,
      request,
      request_hash: p.exchangeRequestHash(request),
      event_id: id(7),
    },
  };
}
test("receive metadata binds recipient, canonical request, exact endpoint and opaque held rows", () => {
  const row = offered();
  assert.deepEqual(
    p.asIncomingPage(
      { exchanges: [row, { id: id(11), state: "held" }] },
      context,
    ),
    { exchanges: [row, { id: id(11), state: "held" }], next: "" },
  );
  for (const mutate of [
    (r) => (r.exchange.recipient_actor_id = id(99)),
    (r) => (r.exchange.id = id(99)),
    (r) => (r.exchange.request_hash = "c".repeat(64)),
    (r) => (r.exchange.request.endpoint.id = id(99)),
    (r) => (r.exchange.storage_id = id(99)),
    (r) => (r.exchange.request.approved = true),
    (r) => (r.exchange.request.artifact.acceptance_policy = "clean"),
  ]) {
    const bad = structuredClone(row);
    mutate(bad);
    assert.throws(() => p.asIncomingPage({ exchanges: [bad] }, context));
  }
  assert.throws(() =>
    p.asIncomingPage(
      { exchanges: [{ id: id(10), state: "held", exchange: row.exchange }] },
      context,
    ),
  );
});
test("receive cursors cannot hide duplicate, reordered, foreign or skipped page identity", () => {
  for (const page of [
    { exchanges: [offered(), offered()] },
    { exchanges: [offered(11), offered(10)] },
    { exchanges: [offered()], next: id(99) },
    { exchanges: [], next: id(10) },
    { exchanges: [offered()], next: null },
  ])
    assert.throws(() => p.asIncomingPage(page, context));
  assert.throws(() =>
    p.asIncomingPage({ exchanges: [offered()] }, { ...context, after: id(10) }),
  );
  assert.throws(() =>
    p.asIncomingPage(
      { exchanges: Array.from({ length: 21 }, (_, i) => offered(10 + i)) },
      context,
    ),
  );
});
test("browser canonical bytes match the shared server fixture including exact microseconds", async () => {
  const fixture = JSON.parse(
    await readFile(
      new URL("fixtures/artifact-exchange.json", import.meta.url),
      "utf8",
    ),
  );
  assert.equal(
    new TextDecoder().decode(p.exchangeRequestBytes(fixture.request)),
    fixture.canonical,
  );
  assert.equal(p.exchangeRequestHash(fixture.request), fixture.sha256);
  const changed = offered();
  changed.exchange.request.endpoint.id = id(99);
  changed.exchange.request_hash = p.exchangeRequestHash(
    changed.exchange.request,
  );
  assert.throws(() => p.asIncomingPage({ exchanges: [changed] }, context));
});
test("receive adapter binds requests and navigation to current session without buffering bytes", async () => {
  const calls = [];
  let response = { exchanges: [offered()] };
  let during = () => {};
  const api = {
    session: {
      identity: {
        tenant_id: context.tenant,
        partner_id: context.partner,
        actor_id: context.actor,
        authority_revision: 1,
        root_policy_digest: "d".repeat(64),
      },
      session: { id: id(99) },
    },
    request: async (path, options, decode) => {
      calls.push({ path, options });
      await during();
      return decode(response);
    },
  };
  const client = new a.ExchangeReceiveApi(api);
  assert.equal(client.isCurrent(), true);
  assert.equal(
    (await client.incoming(context.endpoint)).exchanges[0].id,
    id(10),
  );
  assert.equal(
    calls[0].path,
    `/v1/tenants/${context.tenant}/partners/${context.partner}/exchange-endpoints/${context.endpoint}/incoming?limit=20&after=`,
  );
  assert.equal(calls[0].options.method, undefined);
  assert.equal(
    client.downloadPath(offered()),
    `/v1/tenants/${context.tenant}/partners/${context.partner}/exchanges/${id(10)}/file`,
  );
  assert.throws(() => client.downloadPath({ id: id(10), state: "held" }));
  await assert.rejects(() => client.incoming("https://unapproved.invalid"));
  assert.equal(calls.length, 1);
  response = offered();
  assert.equal((await client.inspect(id(10), context.endpoint)).id, id(10));
  during = () => {
    api.session.identity.authority_revision++;
  };
  await assert.rejects(
    () => client.inspect(id(10), context.endpoint),
    (e) => e.code === "context_changed",
  );
  assert.equal(client.isCurrent(), false);
  assert.throws(
    () => client.downloadPath(offered()),
    (e) => e.code === "context_changed",
  );
});
test("canonical receive times and numeric fields never silently lose request meaning", () => {
  for (const value of [
    "2026-11-05T20:00:00.0000000001Z",
    "2026-11-05T20:00:00.0000010Z",
    "2026-02-30T20:00:00Z",
    "2026-11-05T20:00:00+00:00",
  ]) {
    const row = offered();
    row.exchange.request.expires_at = value;
    assert.throws(() => p.asIncomingPage({ exchanges: [row] }, context));
  }
  for (const value of [-1, 0.5, Number.MAX_SAFE_INTEGER + 1, NaN, Infinity]) {
    const row = offered();
    row.exchange.request.artifact.size_bytes = value;
    assert.throws(() => p.asIncomingPage({ exchanges: [row] }, context));
  }
});
