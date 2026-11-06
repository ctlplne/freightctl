import assert from "node:assert/strict";
import { test } from "node:test";
import { build } from "esbuild";
const bundle = await build({
  entryPoints: ["src/artifact-exchanges-api.ts"],
  absWorkingDir: new URL("..", import.meta.url).pathname,
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const { ExchangeReceiveApi } = await import(
  "data:text/javascript;base64," +
    Buffer.from(bundle.outputFiles[0].contents).toString("base64")
);
const id = (n) =>
  n.toString(16).padStart(8, "0") + "-1111-4111-8111-111111111111";
const request = () => ({
  exchange_id: id(4),
  request_hash: "a".repeat(64),
  artifact: {
    file_revision_id: id(5),
    size_bytes: 8,
    sha256: "b".repeat(64),
    acceptance_policy: "integrity-only-v1",
  },
  virtual_path: "/new-owned.dat",
});
const response = () => ({
  profile: "received-artifact-copy-v1",
  source: ((r) => ({
    exchange_id: r.exchange_id,
    request_hash: r.request_hash,
    artifact: r.artifact,
  }))(request()),
  artifact: { ...request().artifact, file_revision_id: id(6) },
  event_id: id(7),
  acceptance: "durable-local-integrity-only",
  replayed: false,
  observation: "original-command-receipt",
  current_state: "not-checked",
  receiver_persistence: "unknown",
  business_processing: "unknown",
});
function transport(permissions = ["read", "list", "write"]) {
  let during = () => {},
    result = response();
  const calls = [];
  const api = {
    session: {
      identity: {
        tenant_id: id(1),
        partner_id: id(2),
        actor_id: id(3),
        authority_revision: 1,
        root_policy_digest: "c".repeat(64),
        permissions,
      },
      session: { id: id(8) },
    },
    request: async (path, options, decode) => {
      calls.push({ path, options });
      during();
      return decode(result);
    },
  };
  return {
    api,
    calls,
    client: new ExchangeReceiveApi(api),
    during: (fn) => (during = fn),
    result: (v) => (result = v),
  };
}
test("received copy sends only pinned exact source and new path under independent write authority", async () => {
  const t = transport(),
    r = request();
  t.during(() => {
    r.artifact.size_bytes++;
    r.virtual_path = "/tampered.dat";
  });
  const actual = await t.client.copyReceived(r, "original-copy");
  assert.equal(actual.artifact.file_revision_id, id(6));
  assert.equal(
    t.calls[0].path,
    `/v1/tenants/${id(1)}/partners/${id(2)}/exchange-copies`,
  );
  assert.deepEqual(JSON.parse(t.calls[0].options.body), request());
  assert.equal(t.calls[0].options.method, "POST");
  assert.equal(t.calls[0].options.headers["Idempotency-Key"], "original-copy");
  const ro = transport(["read", "list"]);
  await assert.rejects(() =>
    ro.client.copyReceived(request(), "original-copy"),
  );
  assert.equal(ro.calls.length, 0);
});
test("copy rejects changed identity,authority,root,session or permissions before exposing a response", async () => {
  for (const mutate of [
    (a) => (a.session.identity.tenant_id = id(9)),
    (a) => (a.session.identity.partner_id = id(9)),
    (a) => (a.session.identity.actor_id = id(9)),
    (a) => a.session.identity.authority_revision++,
    (a) => (a.session.identity.root_policy_digest = "d".repeat(64)),
    (a) => (a.session.session.id = id(9)),
    (a) => a.session.identity.permissions.pop(),
  ]) {
    const t = transport();
    t.during(() => mutate(t.api));
    await assert.rejects(() =>
      t.client.copyReceived(request(), "original-copy"),
    );
  }
});
test("copy refuses mixed source,changed accepted bytes,private fields and stronger receipt claims", async () => {
  for (const mutate of [
    (v) => (v.source.exchange_id = id(9)),
    (v) => (v.source.request_hash = "d".repeat(64)),
    (v) => v.source.artifact.size_bytes++,
    (v) => v.artifact.size_bytes++,
    (v) => (v.artifact.sha256 = "d".repeat(64)),
    (v) => (v.artifact.file_revision_id = id(5)),
    (v) => (v.artifact.acceptance_policy = "intake-csv-v1:" + "d".repeat(64)),
    (v) => (v.receiver_persistence = "confirmed"),
    (v) => (v.business_processing = "complete"),
    (v) => (v.current_state = "available"),
    (v) => (v.storage_id = id(9)),
    (v) => (v.event_id = "not-an-id"),
  ]) {
    const t = transport(),
      v = response();
    mutate(v);
    t.result(v);
    await assert.rejects(() =>
      t.client.copyReceived(request(), "original-copy"),
    );
  }
});
test("private recovery hints bind origin,actor,authority and root and reject ambiguous controls without contacting server", () => {
  const t = transport(),
    saved = {
      request: request(),
      request_key: "original-copy",
      expected_artifact_id: id(6),
    },
    origin = "https://freightctl.example";
  const encoded = t.client.copyRecovery(saved, origin);
  assert.deepEqual(
    t.client.readCopyRecovery(JSON.stringify(encoded), origin),
    saved,
  );
  assert.equal(t.calls.length, 0);
  for (const mutate of [
    (v) => (v.server_origin = "https://foreign.example"),
    (v) => (v.participant.actor_id = id(9)),
    (v) => v.participant.authority_revision++,
    (v) => (v.participant.root_policy_digest = "d".repeat(64)),
    (v) => (v.request.overwrite = true),
    (v) => (v.request.virtual_path = "/../escape"),
    (v) => (v.request.virtual_path = "/.freightctl/secret"),
    (v) => (v.request.virtual_path = "/a\ud800"),
    (v) => (v.request_key = "bad key"),
    (v) => (v.expected_artifact_id = ""),
    (v) => (v.credentials = "not-a-grant"),
  ]) {
    const v = structuredClone(encoded);
    mutate(v);
    assert.throws(() => t.client.readCopyRecovery(JSON.stringify(v), origin));
  }
  const text = JSON.stringify(encoded);
  assert.throws(() =>
    t.client.readCopyRecovery(
      text.slice(0, -1) + ',"request_key":"changed"}',
      origin,
    ),
  );
  assert.throws(() =>
    t.client.readCopyRecovery(text, "http://freightctl.example"),
  );
  const ro = transport(["read", "list"]);
  assert.throws(() => ro.client.readCopyRecovery(text, origin));
  assert.equal(ro.calls.length, 0);
});
test("an uncertain response preserves original meaning and known result identity for an explicit retry", async () => {
  const t = transport(),
    r = request();
  t.during(() => {
    throw new Error("response lost");
  });
  await assert.rejects(() => t.client.copyReceived(r, "original-copy"));
  assert.equal(t.calls.length, 1);
  t.during(() => {});
  const v = response();
  v.replayed = true;
  t.result(v);
  const replay = await t.client.copyReceived(
    r,
    "original-copy",
    undefined,
    id(6),
  );
  assert.equal(replay.replayed, true);
  assert.deepEqual(t.calls[0].options, t.calls[1].options);
  v.artifact.file_revision_id = id(9);
  await assert.rejects(() =>
    t.client.copyReceived(r, "original-copy", undefined, id(6)),
  );
});
