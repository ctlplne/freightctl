import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash } from "node:crypto";
import { build } from "esbuild";
const bundle = await build({
  entryPoints: [
    "src/artifact-exchanges-api.ts",
    "src/artifact-evidence-types.ts",
  ],
  absWorkingDir: new URL("..", import.meta.url).pathname,
  bundle: true,
  write: false,
  outdir: "out",
  format: "esm",
  target: "es2022",
});
const modules = await Promise.all(
  bundle.outputFiles.map(async (f) => [
    f.path.split("/").at(-1),
    await import(
      "data:text/javascript;base64," +
        Buffer.from(f.contents).toString("base64")
    ),
  ]),
);
const a = modules.find(([n]) => n === "artifact-exchanges-api.js")[1],
  p = modules.find(([n]) => n === "artifact-evidence-types.js")[1];
const id = (n) =>
    n.toString(16).padStart(8, "0") + "-1111-4111-8111-111111111111",
  scope = { tenant: id(1), partner: id(2) };
const artifact = () => ({
  file_revision_id: id(5),
  size_bytes: 8,
  sha256: "a".repeat(64),
  acceptance_policy: "integrity-only-v1",
});
const expected = () => ({
  request_hash: "b".repeat(64),
  artifact: artifact(),
  expires_at: "2026-11-06T00:00:00.000001Z",
});
const response = () => ({
  profile: "authorized-exchange-evidence-v1",
  tenant_id: scope.tenant,
  partner_id: scope.partner,
  exchange_id: id(4),
  direction: "incoming",
  current_metadata_state: "offered",
  checked_at: "2026-11-05T00:00:00Z",
  details: "authorized-records",
  request_hash: expected().request_hash,
  artifact: artifact(),
  recorded_events: [
    {
      kind: "custody-acceptance",
      event_id: id(6),
      resource_id: id(5),
      recorded_at: "2026-11-04T00:00:00.000001Z",
    },
    {
      kind: "availability-offer",
      event_id: id(7),
      resource_id: id(4),
      recorded_at: "2026-11-04T00:00:01Z",
    },
  ],
  storage_verification: "not-checked",
  retrieval: "unknown",
  receiver_persistence: "unknown",
  business_processing: "unknown",
});
test("recorded evidence preserves exact bindings and causal sequence without claiming byte or receiver outcomes", () => {
  const v = response();
  v.recorded_events[0].recorded_at = "2026-11-04T00:00:02Z";
  const actual = p.asExchangeEvidence(v, scope, id(4), "incoming", expected());
  assert.equal(actual.artifact.sha256, artifact().sha256);
  assert.equal(actual.retrieval, "unknown");
  assert.equal(actual.recorded_events.length, 2);
  const held = response();
  held.current_metadata_state = "held";
  held.details = "opaque";
  held.recorded_events = [];
  delete held.artifact;
  delete held.request_hash;
  const opaque = p.asExchangeEvidence(
    held,
    scope,
    id(4),
    "incoming",
    expected(),
  );
  assert.equal(opaque.artifact, undefined);
  assert.deepEqual(opaque.recorded_events, []);
  for (const change of [
    (v) => (v.artifact = artifact()),
    (v) => (v.request_hash = expected().request_hash),
    (v) => (v.reply_reference_only = id(8)),
    (v) => (v.recorded_events = response().recorded_events),
  ]) {
    const dirty = structuredClone(held);
    change(dirty);
    assert.throws(() =>
      p.asExchangeEvidence(dirty, scope, id(4), "incoming", expected()),
    );
  }
});
test("evidence rejects mixed scope/artifact/event identity,raw payloads and invented stronger receipts", () => {
  for (const change of [
    (v) => (v.tenant_id = id(9)),
    (v) => (v.partner_id = id(9)),
    (v) => (v.exchange_id = id(9)),
    (v) => (v.direction = "outgoing"),
    (v) => (v.request_hash = "c".repeat(64)),
    (v) => v.artifact.size_bytes++,
    (v) => (v.recorded_events[0].resource_id = id(9)),
    (v) => (v.recorded_events[1].event_id = v.recorded_events[0].event_id),
    (v) => (v.recorded_events[0].payload = { secret: "hidden" }),
    (v) => (v.recorded_events[0].recorded_at = "2026-02-30T00:00:00Z"),
    (v) => v.recorded_events.reverse(),
    (v) => (v.receiver_persistence = "confirmed"),
    (v) => (v.business_processing = "complete"),
    (v) => (v.storage_verification = "verified"),
    (v) => (v.raw_events = []),
  ]) {
    const v = response();
    change(v);
    assert.throws(() =>
      p.asExchangeEvidence(v, scope, id(4), "incoming", expected()),
    );
  }
});
test("metadata expiry comparisons retain the exact microsecond and terminal decisions", () => {
  const v = response();
  v.checked_at = "2026-11-06T00:00:00Z";
  p.asExchangeEvidence(v, scope, id(4), "incoming", expected());
  v.checked_at = expected().expires_at;
  assert.throws(() =>
    p.asExchangeEvidence(v, scope, id(4), "incoming", expected()),
  );
  v.direction = "outgoing";
  v.current_metadata_state = "expired";
  p.asExchangeEvidence(v, scope, id(4), "outgoing", expected());
  v.current_metadata_state = "held";
  assert.throws(() =>
    p.asExchangeEvidence(v, scope, id(4), "outgoing", expected()),
  );
  v.current_metadata_state = "canceled";
  v.recorded_events.push({
    kind: "view-canceled",
    event_id: id(8),
    resource_id: id(4),
    recorded_at: "2026-11-05T00:00:00Z",
  });
  p.asExchangeEvidence(v, scope, id(4), "outgoing", expected());
});
function transport(permissions = ["read", "list", "deliver"]) {
  let during = () => {};
  const calls = [],
    api = {
      session: {
        identity: {
          tenant_id: scope.tenant,
          partner_id: scope.partner,
          actor_id: id(3),
          authority_revision: 1,
          root_policy_digest: createHash("sha256").update("/").digest("hex"),
          permissions,
        },
        session: { id: id(10) },
      },
      request: async (path, options, decode) => {
        calls.push({ path, options });
        during();
        return decode(response());
      },
    };
  return {
    api,
    calls,
    client: new a.ExchangeReceiveApi(api),
    during: (fn) => (during = fn),
  };
}
test("evidence client pins its expected snapshot and refuses a changed identity or unauthorized direction", async () => {
  let t = transport(),
    e = expected();
  t.during(() => {
    e.artifact.size_bytes++;
    e.expires_at = "2026-01-01T00:00:00Z";
  });
  await t.client.evidence(id(4), "incoming", e);
  assert.deepEqual(JSON.parse(t.calls[0].options.body), {
    exchange_id: id(4),
    direction: "incoming",
  });
  assert.equal(t.calls[0].options.method, "POST");
  assert.equal(
    t.calls[0].path,
    `/v1/tenants/${scope.tenant}/partners/${scope.partner}/exchange-traces/previews`,
  );
  t = transport();
  t.during(() => t.api.session.identity.authority_revision++);
  await assert.rejects(() => t.client.evidence(id(4), "incoming", expected()));
  t = transport(["read", "list"]);
  await assert.rejects(() => t.client.evidence(id(4), "outgoing", expected()));
  assert.equal(t.calls.length, 0);
  t = transport(["read", "deliver"]);
  await assert.rejects(() => t.client.evidence(id(4), "incoming", expected()));
  assert.equal(t.calls.length, 0);
});
