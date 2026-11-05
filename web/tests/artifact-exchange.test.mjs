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

test("terminal receipts bind the exact offer, operation and canonical Go bytes", async () => {
  const fixture = JSON.parse(
    await readFile(
      new URL("fixtures/artifact-exchange.json", import.meta.url),
      "utf8",
    ),
  );
  assert.equal(
    new TextDecoder().decode(p.exchangeClosureBytes(fixture.closure)),
    fixture.closure_canonical,
  );
  const command = fixture.closure;
  const receipt = {
    exchange_id: command.exchange_id,
    state: "declined",
    command_hash: fixture.closure_sha256,
    event_id: id(15),
    replayed: false,
  };
  assert.deepEqual(p.asExchangeClosureResult(receipt, command), receipt);
  for (const patch of [
    { exchange_id: id(99) },
    { state: "canceled" },
    { command_hash: "e".repeat(64) },
    { event_id: "not-an-id" },
    { replayed: null },
    { artifact: { file_revision_id: id(99) } },
  ])
    assert.throws(() =>
      p.asExchangeClosureResult({ ...receipt, ...patch }, command),
    );
  assert.throws(() => p.exchangeClosureBytes({ ...command, approved: true }));
  assert.throws(() =>
    p.exchangeClosureBytes({ ...command, operation: "reopen" }),
  );
});

test("recipient decline preserves an exact retry and refuses stale session or opaque held metadata", async () => {
  const row = offered();
  const command = {
    schema_version: 1,
    exchange_id: row.id,
    request_hash: row.exchange.request_hash,
    operation: "decline",
  };
  const { createHash } = await import("node:crypto");
  const receipt = {
    exchange_id: row.id,
    state: "declined",
    command_hash: createHash("sha256")
      .update(p.exchangeClosureBytes(command))
      .digest("hex"),
    event_id: id(15),
    replayed: false,
  };
  const calls = [];
  let during = () => {};
  let response = receipt;
  const api = {
    session: {
      identity: {
        tenant_id: context.tenant,
        partner_id: context.partner,
        actor_id: context.actor,
        authority_revision: 1,
        root_policy_digest: "d".repeat(64),
        permissions: ["read", "list"],
      },
      session: { id: id(99) },
    },
    request: async (path, options, decode) => {
      calls.push({ path, options });
      during();
      return decode(response);
    },
  };
  const client = new a.ExchangeReceiveApi(api);
  assert.deepEqual(await client.decline(row, "fixed-key"), receipt);
  response = { ...receipt, replayed: true };
  assert.equal((await client.decline(row, "fixed-key")).replayed, true);
  assert.deepEqual(calls[0], calls[1]);
  assert.equal(
    calls[0].path,
    `/v1/tenants/${context.tenant}/partners/${context.partner}/exchange-closures`,
  );
  assert.equal(calls[0].options.method, "POST");
  assert.equal(calls[0].options.headers["Idempotency-Key"], "fixed-key");
  assert.deepEqual(JSON.parse(calls[0].options.body), command);
  await assert.rejects(() =>
    client.decline({ id: row.id, state: "held" }, "fixed-key"),
  );
  await assert.rejects(() => client.decline(row, "invalid key"));
  assert.equal(calls.length, 2);
  during = () => api.session.identity.authority_revision++;
  await assert.rejects(
    () => client.decline(row, "fixed-key"),
    (e) => e.code === "context_changed",
  );
  assert.equal(client.isCurrent(), false);
});
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
        permissions: ["read", "list"],
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

test("endpoint directory uses canonical scoped bindings and refuses stale participant visibility", async () => {
  const fixture = JSON.parse(
    await readFile(
      new URL("fixtures/artifact-exchange.json", import.meta.url),
      "utf8",
    ),
  );
  const who = {
    ...context,
    authority_revision: 1,
    root_policy_digest: "d".repeat(64),
    manager: false,
    can_receive: true,
    can_send: false,
  };
  const row = {
    id: context.endpoint,
    revision: 1,
    definition: fixture.endpoint,
    definition_hash: fixture.endpoint_sha256,
    state: "active",
    recorded_by: id(7),
    event_id: id(8),
  };
  assert.equal(
    p.endpointDefinitionHash(fixture.endpoint, context),
    fixture.endpoint_sha256,
  );
  assert.deepEqual(p.asEndpointPage({ endpoints: [row] }, who, "", 10), {
    endpoints: [row],
    next: "",
  });
  for (const mutate of [
    (e) => (e.definition.recipient.partner_id = id(99)),
    (e) => e.definition.recipient.authority_revision++,
    (e) => e.definition.senders.push({ ...e.definition.senders[0] }),
    (e) => (e.definition.url = "https://unapproved.invalid"),
    (e) => (e.definition_hash = "e".repeat(64)),
    (e) => (e.state = "approved-to-execute"),
  ]) {
    const bad = structuredClone(row);
    mutate(bad);
    assert.throws(() => p.asEndpointPage({ endpoints: [bad] }, who, "", 10));
  }
  const stale = structuredClone(row);
  stale.definition.recipient.authority_revision++;
  stale.definition_hash = p.endpointDefinitionHash(stale.definition, context);
  assert.throws(() => p.asEndpointPage({ endpoints: [stale] }, who, "", 10));
  assert.equal(
    p.asEndpointPage({ endpoints: [stale] }, { ...who, manager: true }, "", 10)
      .endpoints.length,
    1,
  );
  assert.throws(() =>
    p.asEndpointPage({ endpoints: [row], next: id(99) }, who, "", 1),
  );
});

test("directory adapter never turns a sender-only or stale manager record into a receive endpoint", async () => {
  const fixture = JSON.parse(
    await readFile(
      new URL("fixtures/artifact-exchange.json", import.meta.url),
      "utf8",
    ),
  );
  const row = {
    id: context.endpoint,
    revision: 1,
    definition: fixture.endpoint,
    definition_hash: fixture.endpoint_sha256,
    state: "active",
    recorded_by: id(7),
    event_id: id(8),
  };
  const calls = [];
  let response = { endpoints: [row] };
  const api = {
    session: {
      identity: {
        tenant_id: context.tenant,
        partner_id: context.partner,
        actor_id: context.actor,
        authority_revision: 1,
        root_policy_digest: "d".repeat(64),
        permissions: ["read", "list"],
      },
      session: { id: id(99) },
    },
    request: async (path, options, decode) => {
      calls.push(path);
      return decode(response);
    },
  };
  const client = new a.ExchangeReceiveApi(api);
  const page = await client.endpoints();
  assert.equal(page.endpoints.length, 1);
  assert.ok(client.isReceiveEndpoint(row));
  assert.match(calls[0], /exchange-endpoints\?limit=10&after=$/);
  response = row;
  assert.equal((await client.endpoint(context.endpoint)).id, context.endpoint);
  await assert.rejects(() => client.endpoint(id(99)));
  assert.equal(client.isReceiveEndpoint({ ...row, state: "revoked" }), false);
  api.session.identity.permissions = ["read", "deliver"];
  api.session.identity.actor_id = id(6);
  const sender = new a.ExchangeReceiveApi(api);
  assert.equal(sender.isReceiveEndpoint(row), false);
  api.session.identity.permissions = [
    "read",
    "list",
    "admin",
    "accounts_manage",
  ];
  api.session.identity.actor_id = context.actor;
  const manager = new a.ExchangeReceiveApi(api);
  const stale = structuredClone(row);
  stale.definition.recipient.authority_revision++;
  stale.definition_hash = p.endpointDefinitionHash(stale.definition, context);
  assert.equal(manager.isReceiveEndpoint(stale), false);
});

test("source review and offer receipts bind exact bytes,sender,recipient and original request", () => {
  const row = offered(),
    sender = { ...context, actor: row.exchange.sender_actor_id };
  const request = row.exchange.request;
  const result = { exchange: row.exchange, replayed: false };
  assert.deepEqual(
    p.asExchangeArtifact(request.artifact, request.artifact.file_revision_id),
    request.artifact,
  );
  assert.throws(() => p.asExchangeArtifact(request.artifact, id(99)));
  for (const patch of [
    { size_bytes: Number.MAX_SAFE_INTEGER + 1 },
    { acceptance_policy: "approved" },
    { sha256: "private" },
    { file_revision_id: "https://unapproved.invalid" },
    { storage_id: id(99) },
  ])
    assert.throws(() =>
      p.asExchangeArtifact({ ...request.artifact, ...patch }),
    );
  assert.deepEqual(
    p.asExchangeOfferResult(result, request, sender, context.actor),
    result,
  );
  for (const change of [
    (r) => (r.exchange.sender_actor_id = id(99)),
    (r) => (r.exchange.recipient_actor_id = id(99)),
    (r) => {
      r.exchange.request.artifact.sha256 = "e".repeat(64);
      r.exchange.request_hash = p.exchangeRequestHash(r.exchange.request);
    },
    (r) => (r.exchange.event_id = "not-an-id"),
    (r) => (r.replayed = null),
    (r) => (r.business_processed = true),
  ]) {
    const bad = structuredClone(result);
    change(bad);
    assert.throws(() =>
      p.asExchangeOfferResult(bad, request, sender, context.actor),
    );
  }
});

test("sender adapter reuses exact offer/cancel keys and rechecks current participant bindings", async () => {
  const fixture = JSON.parse(
    await readFile(
      new URL("fixtures/artifact-exchange.json", import.meta.url),
      "utf8",
    ),
  );
  const endpoint = {
    id: context.endpoint,
    revision: 1,
    definition: fixture.endpoint,
    definition_hash: fixture.endpoint_sha256,
    state: "active",
    recorded_by: id(7),
    event_id: id(8),
  };
  const row = offered();
  row.exchange.request.endpoint.hash = endpoint.definition_hash;
  row.exchange.request_hash = p.exchangeRequestHash(row.exchange.request);
  const request = row.exchange.request,
    source = request.artifact;
  const { createHash } = await import("node:crypto");
  const close = {
    schema_version: 1,
    exchange_id: row.id,
    request_hash: row.exchange.request_hash,
    operation: "cancel",
  };
  const terminal = {
    exchange_id: row.id,
    state: "canceled",
    command_hash: createHash("sha256")
      .update(p.exchangeClosureBytes(close))
      .digest("hex"),
    event_id: id(21),
    replayed: false,
  };
  let during = () => {},
    replayed = false;
  const calls = [];
  const api = {
    session: {
      identity: {
        tenant_id: context.tenant,
        partner_id: context.partner,
        actor_id: id(6),
        authority_revision: 1,
        root_policy_digest: "d".repeat(64),
        permissions: ["read", "deliver"],
      },
      session: { id: id(99) },
    },
    request: async (path, options, decode) => {
      calls.push({ path, options });
      during();
      return decode(
        path.includes("exchange-sources/")
          ? source
          : path.endsWith("exchange-closures")
            ? terminal
            : { exchange: row.exchange, replayed },
      );
    },
  };
  const client = new a.ExchangeReceiveApi(api);
  assert.equal(client.isSendEndpoint(endpoint), true);
  assert.equal(client.isReceiveEndpoint(endpoint), false);
  assert.deepEqual(await client.source(source.file_revision_id), source);
  assert.deepEqual(await client.offer(request, endpoint, "fixed-offer"), {
    exchange: row.exchange,
    replayed: false,
  });
  replayed = true;
  assert.equal(
    (await client.offer(request, endpoint, "fixed-offer")).replayed,
    true,
  );
  assert.deepEqual(calls[1], calls[2]);
  assert.deepEqual(JSON.parse(calls[1].options.body), request);
  assert.equal(calls[1].options.headers["Idempotency-Key"], "fixed-offer");
  assert.deepEqual(
    await client.cancelOffer(row.exchange, "fixed-cancel"),
    terminal,
  );
  assert.deepEqual(JSON.parse(calls[3].options.body), close);
  await assert.rejects(() =>
    client.offer(request, { ...endpoint, state: "revoked" }, "fixed-offer"),
  );
  await assert.rejects(() =>
    client.offer(
      { ...request, endpoint: { ...request.endpoint, revision: 2 } },
      endpoint,
      "fixed-offer",
    ),
  );
  await assert.rejects(() => client.source("not-a-revision"));
  assert.equal(calls.length, 4);
  during = () => api.session.identity.authority_revision++;
  await assert.rejects(
    () => client.offer(request, endpoint, "fixed-offer"),
    (e) => e.code === "context_changed",
  );
  assert.equal(client.isCurrent(), false);
});

function outgoing(n = 10) {
  return {
    tenant_id: context.tenant,
    partner_id: context.partner,
    exchange: offered(n).exchange,
    state: "offered",
    checked_at: "2026-11-05T20:00:00Z",
    retrieval: "unknown",
    receiver_persistence: "unknown",
    business_processing: "unknown",
  };
}
test("outgoing history keeps current scope,exact microsecond expiry and unknown receiver outcomes", () => {
  const row = outgoing(),
    who = { ...context, actor: row.exchange.sender_actor_id };
  assert.deepEqual(p.asOutgoingExchange(row, who, row.exchange.id), row);
  assert.equal(
    p.asOutgoingExchange(
      { ...row, state: "expired", checked_at: row.exchange.request.expires_at },
      who,
    ).state,
    "expired",
  );
  for (const patch of [
    { tenant_id: id(99) },
    { partner_id: id(99) },
    { retrieval: "verified" },
    { receiver_persistence: "durable" },
    { business_processing: "complete" },
    { state: "processed" },
    { state: "expired" },
    { checked_at: row.exchange.request.expires_at },
    { state: "canceled" },
    { closure_event_id: id(55) },
    { storage_id: id(99) },
  ])
    assert.throws(() => p.asOutgoingExchange({ ...row, ...patch }, who));
  const closed = { ...row, state: "declined", closure_event_id: id(55) };
  assert.deepEqual(p.asOutgoingExchange(closed, who), closed);
  const wrong = structuredClone(row);
  wrong.exchange.sender_actor_id = id(99);
  assert.throws(() => p.asOutgoingExchange(wrong, who));
});
test("outgoing history cursors cannot include duplicate,reordered,skipped or foreign records", () => {
  const who = { ...context, actor: id(6) };
  for (const page of [
    { exchanges: [outgoing(), outgoing()] },
    { exchanges: [outgoing(11), outgoing(10)] },
    { exchanges: [outgoing()], next: id(99) },
    { exchanges: [], next: id(10) },
    { exchanges: [{ ...outgoing(), partner_id: id(99) }] },
  ])
    assert.throws(() => p.asOutgoingPage(page, who, "", 20));
  assert.throws(() =>
    p.asOutgoingPage({ exchanges: [outgoing()] }, who, id(10), 20),
  );
  assert.deepEqual(
    p.asOutgoingPage({ exchanges: [outgoing()], next: id(10) }, who, "", 1),
    { exchanges: [outgoing()], next: id(10) },
  );
});
test("outgoing adapter uses scoped read-only routes and rejects context changes before disclosure", async () => {
  const row = outgoing(),
    calls = [];
  let during = () => {},
    response = { exchanges: [row] };
  const api = {
    session: {
      identity: {
        tenant_id: context.tenant,
        partner_id: context.partner,
        actor_id: id(6),
        authority_revision: 1,
        root_policy_digest: "d".repeat(64),
        permissions: ["read", "deliver", "list"],
      },
      session: { id: id(99) },
    },
    request: async (path, options, decode) => {
      calls.push({ path, options });
      during();
      return decode(response);
    },
  };
  const client = new a.ExchangeReceiveApi(api);
  assert.equal(
    (await client.outgoing()).exchanges[0].exchange.id,
    row.exchange.id,
  );
  assert.match(calls[0].path, /outgoing-exchanges\?limit=20&after=$/);
  assert.equal(calls[0].options.method, undefined);
  response = row;
  assert.equal(
    (await client.outgoingExchange(row.exchange.id)).state,
    "offered",
  );
  await assert.rejects(() => client.outgoing("not-a-cursor"));
  await assert.rejects(() => client.outgoingExchange("not-a-view"));
  assert.equal(calls.length, 2);
  during = () => api.session.identity.authority_revision++;
  await assert.rejects(
    () => client.outgoingExchange(row.exchange.id),
    (e) => e.code === "context_changed",
  );
  assert.equal(client.isCurrent(), false);
});

test("history discovery requires list while a known own receipt remains inspectable", async () => {
  const row = outgoing(),
    calls = [];
  const api = {
    session: {
      identity: {
        tenant_id: context.tenant,
        partner_id: context.partner,
        actor_id: id(6),
        authority_revision: 1,
        root_policy_digest: "d".repeat(64),
        permissions: ["read", "deliver"],
      },
      session: { id: id(99) },
    },
    request: async (path, options, decode) => {
      calls.push(path);
      return decode(path.includes("?") ? { exchanges: [row] } : row);
    },
  };
  const client = new a.ExchangeReceiveApi(api);
  await assert.rejects(
    () => client.outgoing(),
    (e) => e.code === "permission_denied",
  );
  assert.equal(calls.length, 0);
  assert.equal(
    (await client.outgoingExchange(row.exchange.id)).exchange.id,
    row.exchange.id,
  );
  assert.equal(calls.length, 1);
});
