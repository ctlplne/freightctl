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
const integrityReport = () => ({
  profile: "recipient-sha256-report-v1",
  exchange_id: id(4),
  request_hash: expected().request_hash,
  read_authorization_event_id: id(8),
  artifact: artifact(),
  observation: "recipient-reported-sha256-and-length-match",
  event_id: id(9),
  recorded_at: "2026-11-05T00:00:00.000001Z",
  receiver_persistence: "unknown",
  business_processing: "unknown",
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
test("v4 binds an outgoing copy to a distinct source with equal bytes", () => {
  const receivedCopy = {
    source: {
      exchange_id: id(12),
      request_hash: "c".repeat(64),
      artifact: { ...artifact(), file_revision_id: id(13) },
    },
    source_accepted_event_id: id(14),
    source_offer_event_id: id(15),
  };
  const original = {
    ...response(),
    profile: p.evidenceV4,
    direction: "outgoing",
    received_copy: receivedCopy,
  };
  const parse = (wire, direction = "outgoing", profile = p.evidenceV4) =>
    p.asExchangeEvidence(wire, scope, id(4), direction, expected(), profile);
  assert.deepEqual(parse(original).received_copy, receivedCopy);
  assert.throws(() => parse({ ...original, direction: "incoming" }, "incoming"));
  assert.throws(() =>
    parse({ ...original, profile: p.evidenceV3 }, "outgoing", p.evidenceV3),
  );
  const bad = [
    { ...receivedCopy, source_accepted_event_id: id(6) },
    { ...receivedCopy, source_offer_event_id: id(14) },
    { ...receivedCopy, source: { ...receivedCopy.source, exchange_id: id(4) } },
    { ...receivedCopy, source: { ...receivedCopy.source, artifact: artifact() } },
    ...[{ size_bytes: 9 }, { sha256: "e".repeat(64) }].map((change) => ({
      ...receivedCopy,
      source: {
        ...receivedCopy.source,
        artifact: { ...receivedCopy.source.artifact, ...change },
      },
    })),
    { ...receivedCopy, virtual_path: "/private" },
  ];
  for (const copy of bad)
    assert.throws(() => parse({ ...original, received_copy: copy }));
});
test("integrity commands and receipts stay bound to the exact offer and reported outcomes", () => {
  const pinned = expected();
  const command = {
    schema_version: 1,
    exchange_id: id(4),
    request_hash: pinned.request_hash,
    read_authorization_event_id: id(8),
    file_revision_id: pinned.artifact.file_revision_id,
    size_bytes: pinned.artifact.size_bytes,
    sha256: pinned.artifact.sha256,
  };
  const receipt = integrityReport();
  assert.deepEqual(p.asExchangeIntegrityCommand(command, id(4), pinned), command);
  assert.deepEqual(p.asExchangeIntegrityReport(receipt, id(4), pinned, id(8)), {
    event: id(9),
    recordedAt: receipt.recorded_at,
  });
  for (const altered of [
    { exchange_id: id(3) },
    { request_hash: "c".repeat(64) },
    { file_revision_id: id(3) },
    { size_bytes: 9 },
    { sha256: "c".repeat(64) },
    { read_authorization_event_id: "invented" },
    { receiver_persistence: "durable" },
  ])
    assert.throws(() =>
      p.asExchangeIntegrityCommand({ ...command, ...altered }, id(4), pinned),
    );
  for (const altered of [
    { artifact: { ...artifact(), size_bytes: 9 } },
    { observation: "server-verified-possession" },
    { read_authorization_event_id: id(9) },
    { recorded_at: "2026-11-31T00:00:00Z" },
    { receiver_persistence: "durable" },
    { business_processing: "complete" },
    { payload: "raw bytes" },
  ])
    assert.throws(() =>
      p.asExchangeIntegrityReport({ ...receipt, ...altered }, id(4), pinned, id(8)),
    );
});
test("v3 groups the exact report with authorized records and keeps held evidence opaque", () => {
  const result = {
    ...response(),
    profile: p.evidenceV3,
    integrity_report: integrityReport(),
  };
  const decode = (wire) =>
    p.asExchangeEvidence(wire, scope, id(4), "incoming", expected(), p.evidenceV3);
  assert.deepEqual(decode(result).integrity_report, {
    event: id(9),
    recordedAt: result.integrity_report.recorded_at,
  });
  assert.throws(() =>
    p.asExchangeEvidence(
      { ...result, profile: p.evidenceV2 },
      scope,
      id(4),
      "incoming",
      expected(),
      p.evidenceV2,
    ),
  );
  const { artifact: _a, request_hash: _r, ...opaque } = result;
  const held = {
    ...opaque,
    current_metadata_state: "held",
    details: "opaque",
    recorded_events: [],
  };
  assert.throws(() => decode(held));
  delete held.integrity_report;
  assert.equal(decode(held).details, "opaque");
  for (const change of [
    { request_hash: "a".repeat(64) },
    { exchange_id: id(3) },
    { event_id: id(7) },
    { business_processing: "complete" },
  ])
    assert.throws(() =>
      decode({ ...result, integrity_report: { ...integrityReport(), ...change } }),
    );
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
const projection = () => ({
  projection_id: id(10),
  definition_hash: "d".repeat(64),
  source_artifact: { ...artifact(), file_revision_id: id(11) },
  source_accepted_event_id: id(12),
  completed_event_id: id(13),
  completed_at: "2026-11-04T00:00:01.123456Z",
});
test("v2 lineage is accepted only on an exact outgoing trace", () => {
  const v = {
    ...response(),
    profile: p.evidenceV2,
    direction: "outgoing",
    record_projection: projection(),
  };
  const read = (wire) =>
    p.asExchangeEvidence(
      wire,
      scope,
      id(4),
      wire.direction,
      expected(),
      wire.profile,
    );
  assert.deepEqual(read(v).record_projection, projection());
  for (const change of [
    (v) => (v.direction = "incoming"),
    (v) => (v.profile = p.evidenceV1),
    (v) => (v.record_projection = null),
    (v) => (v.record_projection.report = {}),
    (v) => (v.record_projection.definition_hash = "unverified"),
    (v) => (v.record_projection.source_artifact = v.artifact),
    (v) =>
      (v.record_projection.source_accepted_event_id =
        v.recorded_events[0].event_id),
    (v) =>
      (v.record_projection.completed_event_id =
        v.record_projection.source_accepted_event_id),
    (v) => (v.record_projection.completed_at = "unverified"),
  ]) {
    const dirty = structuredClone(v);
    change(dirty);
    assert.throws(() => read(dirty));
  }
});
function transport(
  permissions = ["read", "list", "deliver"],
  respond = response,
) {
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
        return decode(respond());
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
test("outgoing browser evidence requests v2 and pins the response profile", async () => {
  const t = transport(undefined, () => ({
    ...response(),
    direction: "outgoing",
    profile: p.evidenceV2,
    record_projection: projection(),
  }));
  const result = await t.client.evidence(id(4), "outgoing", expected());
  assert.deepEqual(result.record_projection, projection());
  assert.deepEqual(JSON.parse(t.calls[0].options.body), {
    exchange_id: id(4),
    direction: "outgoing",
    profile: p.evidenceV2,
  });
  const legacy = transport(undefined, () => ({
    ...response(),
    direction: "outgoing",
  }));
  await assert.rejects(() =>
    legacy.client.evidence(id(4), "outgoing", expected()),
  );
});
