import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";
const bundle = await build({
  entryPoints: ["src/artifact-exchanges-api.ts"],
  absWorkingDir: new URL("..", import.meta.url).pathname,
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const apiModule = await import(
  "data:text/javascript;base64," +
    Buffer.from(bundle.outputFiles[0].contents).toString("base64")
);
const fixture = JSON.parse(
  await readFile(
    new URL("fixtures/artifact-exchange.json", import.meta.url),
    "utf8",
  ),
);
const id = (n) =>
  n.toString(16).padStart(8, "0") + "-1111-4111-8111-111111111111";
const origin = "https://freightctl.invalid";
function setup() {
  const session = {
    identity: {
      tenant_id: id(1),
      partner_id: id(2),
      actor_id: id(6),
      authority_revision: 1,
      root_policy_digest: "d".repeat(64),
      permissions: ["read", "deliver"],
    },
    session: { id: id(99) },
  };
  let requests = 0;
  const api = {
    session,
    request: async () => {
      requests++;
      throw Error("recovery review must not contact a server");
    },
  };
  const endpoint = {
    id: id(4),
    revision: 1,
    definition: fixture.endpoint,
    definition_hash: fixture.endpoint_sha256,
    state: "active",
    recorded_by: id(7),
    event_id: id(8),
  };
  const request = structuredClone(fixture.request);
  request.endpoint = {
    id: endpoint.id,
    revision: 1,
    hash: endpoint.definition_hash,
  };
  const review = { request, endpoint, key: "original-offer-operation" };
  return {
    api,
    review,
    requests: () => requests,
    client: new apiModule.ExchangeReceiveApi(api),
  };
}
test("saved offer review survives a recreated client without sending or trusting file outcomes", () => {
  const f = setup();
  const bytes = f.client.recoveryBytes(origin, f.review);
  const fresh = new apiModule.ExchangeReceiveApi(f.api);
  const saved = fresh.readRecovery(origin, new TextDecoder().decode(bytes));
  assert.equal(saved.request_key, f.review.key);
  assert.deepEqual(saved.request, f.review.request);
  assert.deepEqual(saved.endpoint, f.review.endpoint);
  assert.equal(saved.participant.actor_id, id(6));
  assert.equal(saved.server_origin, origin);
  assert.equal(Object.hasOwn(saved, "replayed"), false);
  assert.equal(Object.hasOwn(saved, "business_processed"), false);
  assert.equal(f.requests(), 0);
});

test("recovery preserves withdrawal identity and refuses invented outcome or changed request meaning", () => {
  const f = setup();
  const bytes = f.client.recoveryBytes(origin, {
    ...f.review,
    expected_exchange_id: id(30),
    withdrawal_key: "original-withdrawal",
  });
  const text = new TextDecoder().decode(bytes),
    saved = f.client.readRecovery(origin, text);
  assert.equal(saved.expected_exchange_id, id(30));
  assert.equal(saved.withdrawal_key, "original-withdrawal");
  for (const mutate of [
    (v) => (v.server_origin = "https://unapproved.invalid"),
    (v) => (v.participant.actor_id = id(77)),
    (v) => v.participant.authority_revision++,
    (v) => (v.participant.root_policy_digest = "e".repeat(64)),
    (v) => (v.request.artifact.sha256 = "e".repeat(64)),
    (v) => (v.endpoint.state = "revoked"),
    (v) => v.endpoint.definition.senders[0].authority_revision++,
    (v) => (v.business_processed = true),
    (v) => (v.credential = "must-never-be-imported"),
    (v) => delete v.expected_exchange_id,
    (v) => (v.request_key = "invalid key"),
  ]) {
    const bad = JSON.parse(text);
    mutate(bad);
    assert.throws(
      () => f.client.readRecovery(origin, JSON.stringify(bad)),
      (e) => e.code === "invalid_exchange_recovery",
    );
  }
  assert.equal(f.requests(), 0);
});

test("recovery refuses duplicated,aliased,null,rounded,trailing or oversized control JSON", () => {
  const f = setup(),
    text = new TextDecoder().decode(f.client.recoveryBytes(origin, f.review));
  for (const bad of [
    text.replace('"schema_version":1', '"schema_version":1,"schema_version":1'),
    text.replace('"schema_version":1', '"schema_version":1,"SCHEMA_VERSION":1'),
    text.replace('"schema_version":1', '"schema_version":1e0'),
    text.replace('"schema_version":1', '"schema_version":1.0'),
    text.replace('"schema_version":1', '"schema_version":null'),
    text.replace('"size_bytes":8', '"size_bytes":9007199254740993'),
    text.replace(
      '"request_key":"original-offer-operation"',
      '"request_key":"original-offer-operation","\\u0072equest_key":"different"',
    ),
    text + " {}",
    " ".repeat(24577),
    '{"nested":' + "[".repeat(12) + "0" + "]".repeat(12) + "}",
  ])
    assert.throws(
      () => f.client.readRecovery(origin, bad),
      (e) => e.code === "invalid_exchange_recovery",
    );
  assert.equal(f.requests(), 0);
});

test("changed authority,scope,origin or manager visibility cannot adopt an old send review", () => {
  const original = setup(),
    text = new TextDecoder().decode(
      original.client.recoveryBytes(origin, original.review),
    );
  for (const mutate of [
    (i) => (i.tenant_id = id(77)),
    (i) => (i.partner_id = id(77)),
    (i) => (i.actor_id = id(77)),
    (i) => i.authority_revision++,
    (i) => (i.root_policy_digest = "e".repeat(64)),
    (i) => (i.permissions = ["read", "admin", "accounts_manage"]),
  ]) {
    const f = setup();
    mutate(f.api.session.identity);
    const fresh = new apiModule.ExchangeReceiveApi(f.api);
    assert.throws(
      () => fresh.readRecovery(origin, text),
      (e) => e.code === "invalid_exchange_recovery",
    );
    assert.equal(f.requests(), 0);
  }
  assert.throws(() =>
    original.client.readRecovery("https://other.invalid", text),
  );
  original.api.session.identity.authority_revision++;
  assert.throws(
    () => original.client.readRecovery(origin, text),
    (e) => e.code === "context_changed",
  );
});
