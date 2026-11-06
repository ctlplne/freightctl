import assert from "node:assert/strict";
import { test } from "node:test";
import { build } from "esbuild";
import { readFile } from "node:fs/promises";
const bundle = await build({
  entryPoints: ["src/api.ts"],
  absWorkingDir: new URL("..", import.meta.url).pathname,
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const { Api } = await import(
  "data:text/javascript;base64," +
    Buffer.from(bundle.outputFiles[0].contents).toString("base64")
);
const id = (n) =>
  n.toString(16).padStart(8, "0") + "-1111-4111-8111-111111111111";
const fixture = JSON.parse(
  await readFile(
    new URL("./fixtures/audit-history.json", import.meta.url),
    "utf8",
  ),
);
function transport() {
  const api = new Api();
  api.session = {
    identity: structuredClone(fixture.reader),
    session: { id: id(4) },
  };
  let during = () => {},
    result = {
      profile: "event-metadata-history-v1",
      tenant_id: id(1),
      partner_id: id(2),
      reader_actor_id: id(3),
      observed_at: "2026-11-05T00:00:00.100002Z",
      observation: "independent-page-observation",
      payloads: "omitted",
      events: [
        {
          event_id: id(5),
          actor_id: id(6),
          kind: "FileAccepted",
          resource_id: id(7),
          recorded_at: "2026-11-05T00:00:00.100001Z",
        },
      ],
      next: fixture.cursor,
    };
  const calls = [];
  api.request = async (path, options, decode) => {
    calls.push({ path, options });
    during();
    return decode(result);
  };
  return {
    api,
    calls,
    during: (fn) => (during = fn),
    result: (v) => (result = v),
    response: () => structuredClone(result),
  };
}
test("operator history uses explicit root audit permission and metadata-only scoped search", async () => {
  const api = new Api();
  let called = 0;
  api.session = {
    identity: {
      tenant_id: id(1),
      partner_id: id(2),
      actor_id: id(3),
      authority_revision: 1,
      root_policy_digest:
        "8a5edab282632443219e051e4ade2d1d5bbc671c781051bf1437897cbdfea0f1",
      permissions: ["read", "list", "audit_read"],
    },
    session: { id: id(4) },
  };
  api.request = async (path, options, decode) => {
    called++;
    assert.equal(
      path,
      `/v1/tenants/${id(1)}/partners/${id(2)}/audit/history/search`,
    );
    assert.equal(options.method, "POST");
    return decode({
      profile: "event-metadata-history-v1",
      tenant_id: id(1),
      partner_id: id(2),
      reader_actor_id: id(3),
      observed_at: "2026-11-05T00:00:00.000002Z",
      observation: "independent-page-observation",
      payloads: "omitted",
      events: [
        {
          event_id: id(5),
          actor_id: id(6),
          kind: "FileAccepted",
          resource_id: id(7),
          recorded_at: "2026-11-05T00:00:00.000001Z",
        },
      ],
    });
  };
  const page = await api.auditHistory({ limit: 1, kinds: ["FileAccepted"] });
  assert.equal(page.events[0].resource_id, id(7));
  assert.equal(called, 1);
});
test("browser and Go share canonical filter/cursor binding and pin input before await", async () => {
  const t = transport(),
    input = structuredClone(fixture.request);
  t.during(() => {
    input.kinds[0] = "Changed";
    input.resource_id = id(9);
  });
  const first = await t.api.auditHistory(input);
  assert.equal(first.next, fixture.cursor);
  assert.deepEqual(JSON.parse(t.calls[0].options.body), fixture.normalized);
  const next = t.response();
  next.events[0].event_id = id(8);
  delete next.next;
  t.result(next);
  t.during(() => {});
  const second = await t.api.auditHistory({
    ...fixture.normalized,
    limit: 3,
    after: first.next,
  });
  assert.equal(second.events[0].event_id, id(8));
  const before = t.calls.length;
  await assert.rejects(() =>
    t.api.auditHistory({
      ...fixture.normalized,
      actor_id: id(9),
      after: fixture.cursor,
    }),
  );
  assert.equal(t.calls.length, before);
});
test("audit metadata refuses changed actor,authority,root,permissions and session", async () => {
  for (const mutate of [
    (a) => (a.session.identity.tenant_id = id(9)),
    (a) => (a.session.identity.partner_id = id(9)),
    (a) => (a.session.identity.actor_id = id(9)),
    (a) => a.session.identity.authority_revision++,
    (a) => (a.session.identity.root_policy_digest = "d".repeat(64)),
    (a) => a.session.identity.permissions.pop(),
    (a) => (a.session.session.id = id(9)),
  ]) {
    const t = transport();
    t.during(() => mutate(t.api));
    await assert.rejects(() => t.api.auditHistory(fixture.normalized));
  }
  for (const mutate of [
    (a) => (a.session.identity.permissions = ["admin", "read", "list"]),
    (a) => (a.session.identity.root_policy_digest = "d".repeat(64)),
  ]) {
    const t = transport();
    mutate(t.api);
    await assert.rejects(() => t.api.auditHistory(fixture.normalized));
    assert.equal(t.calls.length, 0);
  }
});
test("history rejects mixed scope,filter,raw payload,stronger outcome or forged next metadata", async () => {
  for (const mutate of [
    (v) => (v.tenant_id = id(9)),
    (v) => (v.partner_id = id(9)),
    (v) => (v.reader_actor_id = id(9)),
    (v) => (v.events[0].actor_id = id(9)),
    (v) => (v.events[0].resource_id = id(9)),
    (v) => (v.events[0].kind = "Unexpected"),
    (v) => (v.events[0].payload = { credential: "untrusted" }),
    (v) => (v.events[0].recorded_at = "2026-11-05T00:00:00.000001Z"),
    (v) => (v.events[0].recorded_at = "2026-11-05T00:00:00.1000001Z"),
    (v) => v.events.push(v.events[0]),
    (v) => (v.payloads = "included"),
    (v) => (v.receiver_persistence = "confirmed"),
    (v) => (v.next = fixture.cursor + "\n"),
    (v) => (v.next = fixture.cursor + "="),
    (v) => (v.observed_at = "2026-02-30T00:00:00Z"),
  ]) {
    const t = transport(),
      v = t.response();
    mutate(v);
    t.result(v);
    await assert.rejects(
      () => t.api.auditHistory(fixture.normalized),
      (e) => e.status === 502,
    );
  }
});
test("history preserves microsecond filter boundaries and rejects untrusted control widening", async () => {
  const t = transport(),
    v = t.response();
  delete v.next;
  t.result(v);
  await t.api.auditHistory({
    ...fixture.normalized,
    from: "2026-11-05T00:00:00.100001Z",
  });
  await assert.rejects(() =>
    t.api.auditHistory({
      ...fixture.normalized,
      until: "2026-11-05T00:00:00.100001Z",
    }),
  );
  for (const input of [
    { limit: 0 },
    { limit: 101 },
    { limit: 1, include_payload: true },
    { limit: 1, actor_id: "invalid" },
    { limit: 1, from: "2026-11-05T00:00:00.0000001Z" },
    { limit: 1, kinds: Array(17).fill("FileAccepted") },
    { limit: 1, after: "bad" },
  ]) {
    const blocked = transport();
    await assert.rejects(() => blocked.api.auditHistory(input));
    assert.equal(blocked.calls.length, 0);
  }
});
