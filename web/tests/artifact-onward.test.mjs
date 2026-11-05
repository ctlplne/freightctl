import assert from "node:assert/strict";
import { test } from "node:test";
import { build } from "esbuild";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
const modules = await Promise.all(
  ["artifact-onward-types", "artifact-onward-api"].map(async (name) => {
    const built = await build({
      entryPoints: [`src/${name}.ts`],
      absWorkingDir: new URL("..", import.meta.url).pathname,
      bundle: true,
      write: false,
      format: "esm",
      target: "es2022",
    });
    return import(
      "data:text/javascript;base64," +
        Buffer.from(built.outputFiles[0].contents).toString("base64")
    );
  }),
);
const [p, a] = modules;
const fixture = JSON.parse(
  await readFile(
    new URL("fixtures/artifact-onward.json", import.meta.url),
    "utf8",
  ),
);
const id = (n) =>
  n.toString(16).padStart(8, "0") + "-1111-4111-8111-111111111111";
const session = () => ({
  identity: {
    tenant_id: id(1),
    partner_id: id(2),
    actor_id: id(3),
    authority_revision: 2,
    root_policy_digest: fixture.binding.root_policy_digest,
    permissions: ["workflow_execute", "read", "deliver"],
  },
  session: { id: id(10) },
});
const original = () => ({
  request: structuredClone(fixture.review.request),
  review_hash: fixture.review.review_hash,
});
function transport() {
  const calls = [];
  let response = structuredClone(fixture.result),
    during = () => {};
  const api = {
    session: session(),
    request: async (path, options, decode) => {
      calls.push({ path, options });
      during();
      return decode(response);
    },
  };
  return {
    api,
    calls,
    response: (v) => (response = v),
    during: (v) => (during = v),
  };
}
function recovery() {
  return {
    schema_version: 1,
    profile: "freightctl-onward-recovery-v1",
    server_origin: "https://freightctl.invalid",
    participant: {
      tenant_id: id(1),
      partner_id: id(2),
      actor_id: id(3),
      authority_revision: 2,
      root_policy_digest: fixture.binding.root_policy_digest,
    },
    review: structuredClone(fixture.review),
    request_key: id(11),
    expected_run_id: id(8),
    work_key: id(12),
  };
}
function observation() {
  return {
    run_id: id(8),
    workflow: structuredClone(fixture.review.request.workflow),
    artifact: structuredClone(fixture.review.request.artifact),
    observed_state: "attention",
    reason_sha256: "c".repeat(64),
    receiver_persistence: "unknown",
    business_processing: "unknown",
    steps: [
      {
        ordinal: 1,
        delivery_id: id(13),
        state: "ambiguous",
        observation_sha256: "d".repeat(64),
      },
    ],
  };
}

test("browser verifies actual Go receipt fingerprint without converting historical acceptance to present success", () => {
  assert.equal(
    createHash("sha256").update(JSON.stringify(fixture.binding)).digest("hex"),
    fixture.review.review_hash,
  );
  assert.deepEqual(
    p.asOnwardAcceptance(fixture.result, original(), session()),
    {
      run_id: id(8),
      accepted_run_state: "queued",
      current_state: "not-checked",
      replayed: false,
    },
  );
  for (const mutate of [
    (r) => (r.id = id(99)),
    (r) => (r.file_id = id(99)),
    (r) => r.source.size_bytes++,
    (r) => r.workflow_version++,
    (r) => r.authority_revision++,
    (r) => (r.namespace_root = "/other"),
    (r) => (r.storage_id = id(99)),
    (r) => r.onward_workflow_revision++,
    (r) => (r.onward_profile = "automatic-forward"),
    (r) => (r.onward_review_hash = "f".repeat(64)),
    (r) => (r.state = "succeeded"),
    (r) => (r.execution_plan = { execute: true }),
  ]) {
    const value = structuredClone(fixture.result);
    mutate(value.resource);
    assert.throws(() =>
      p.asOnwardAcceptance(value, original(), session(), id(8)),
    );
  }
  const other = session();
  other.identity.actor_id = id(99);
  assert.throws(() => p.asOnwardAcceptance(fixture.result, original(), other));
});
test("review cannot change source, workflow, destination type or claim remote acceptance", () => {
  assert.deepEqual(
    p.asOnwardReview(fixture.review, fixture.review.request),
    fixture.review,
  );
  for (const mutate of [
    (v) => (v.request.artifact.sha256 = "f".repeat(64)),
    (v) => v.request.workflow.version++,
    (v) => (v.external_contact = true),
    (v) => (v.receiver_persistence = "stored"),
    (v) => (v.effects[0].protocol = "http"),
    (v) => (v.effects[0].connection.address = "https://unapproved.invalid"),
    (v) => (v.effects[0].ordinal = 2),
    (v) => v.effects.push(v.effects[0]),
  ]) {
    const value = structuredClone(fixture.review);
    mutate(value);
    assert.throws(() => p.asOnwardReview(value, fixture.review.request));
  }
});
test("lost start and same-key retry preserve exact meaning; lookup alone never calls start or work", async () => {
  const t = transport(),
    client = new a.ArtifactOnwardApi(t.api),
    start = original();
  let first = true;
  t.during(() => {
    if (first) {
      first = false;
      throw new Error("lost response after possible commit");
    }
  });
  await assert.rejects(() => client.start(start, id(11)));
  t.response({ ...fixture.result, replayed: true });
  assert.equal((await client.start(start, id(11))).run_id, id(8));
  assert.deepEqual(t.calls[0], t.calls[1]);
  await client.receipt(start, id(11), id(8));
  assert.ok(t.calls[2].path.endsWith("/onward/receipts"));
  assert.equal(t.calls[2].options.headers["Idempotency-Key"], undefined);
  assert.deepEqual(JSON.parse(t.calls[2].options.body), {
    start,
    receipt_key: id(11),
  });
  await assert.rejects(() => client.start(start, id(11), id(99)));
});
test("in-flight caller mutation cannot change sent body or expected receipt, and credential rotation rejects the response", async () => {
  const t = transport(),
    client = new a.ArtifactOnwardApi(t.api),
    start = original();
  t.during(() => start.request.artifact.size_bytes++);
  assert.equal((await client.start(start, id(11))).run_id, id(8));
  assert.equal(
    JSON.parse(t.calls[0].options.body).request.artifact.size_bytes,
    3,
  );
  t.during(() => t.api.session.identity.authority_revision++);
  await assert.rejects(
    () => client.start(original(), id(11)),
    (e) => e.code === "context_changed",
  );
  await assert.rejects(
    () => client.start(original(), id(11)),
    (e) => e.code === "context_changed",
  );
  assert.equal(t.calls.length, 2);
  const receiveOnly = transport();
  receiveOnly.api.session.identity.permissions = ["read", "list"];
  assert.throws(
    () => new a.ArtifactOnwardApi(receiveOnly.api),
    (e) => e.code === "permission_denied",
  );
});
test("status and each stable work retry require the original receipt/run; ambiguity remains explicit", async () => {
  const t = transport(),
    client = new a.ArtifactOnwardApi(t.api),
    status = observation();
  t.response(status);
  assert.equal(
    (await client.observe(original(), id(11), id(8))).steps[0].state,
    "ambiguous",
  );
  t.response({ ...status, replayed: false, selected_delivery_id: id(13) });
  await client.work(original(), id(11), id(8), id(12));
  t.response({ ...status, replayed: true, selected_delivery_id: id(13) });
  await client.work(original(), id(11), id(8), id(12));
  assert.deepEqual(t.calls[1], t.calls[2]);
  assert.deepEqual(JSON.parse(t.calls[1].options.body), {
    start: original(),
    receipt_key: id(11),
    run_id: id(8),
  });
  for (const mutate of [
    (v) => (v.run_id = id(99)),
    (v) => (v.receiver_persistence = "accepted"),
    (v) => v.artifact.size_bytes++,
    (v) => (v.steps[0].ordinal = 2),
    (v) => v.steps.push(v.steps[0]),
    (v) => (v.selected_delivery_id = id(99)),
    (v) => (v.raw_observation = { password: "secret" }),
  ]) {
    const value = {
      ...structuredClone(status),
      replayed: false,
      selected_delivery_id: id(13),
    };
    mutate(value);
    assert.throws(() => p.asOnwardObservation(value, original(), id(8), true));
  }
});
test("saved onward recovery binds origin, actor, authority and original keys; import contacts nothing and proves no receipt", () => {
  const t = transport(),
    client = new a.ArtifactOnwardApi(t.api),
    saved = recovery(),
    text = JSON.stringify(saved);
  assert.deepEqual(client.readRecovery(text, saved.server_origin), saved);
  assert.equal(t.calls.length, 0);
  for (const mutate of [
    (v) => (v.server_origin = "https://other.invalid"),
    (v) => (v.participant.actor_id = id(99)),
    (v) => v.participant.authority_revision++,
    (v) => (v.participant.root_policy_digest = "f".repeat(64)),
    (v) => (v.request_key = "../new"),
    (v) => (v.expected_run_id = undefined),
    (v) => (v.received = true),
    (v) => (v.review.effects[0].connection.url = "https://other.invalid"),
  ]) {
    const value = structuredClone(saved);
    mutate(value);
    assert.throws(() =>
      client.readRecovery(JSON.stringify(value), saved.server_origin),
    );
  }
  for (const raw of [
    text.replace(
      '"request_key":',
      '"request_key":"' + id(99) + '","request_key":',
    ),
    text.replace(
      '"request_key":',
      '"REQUEST_KEY":"' + id(99) + '","request_key":',
    ),
    text + "{}",
    text.replace('"size_bytes":3', '"size_bytes":9007199254740993'),
    text.replace('"size_bytes":3', '"size_bytes":null'),
    "[".repeat(10) + text + "]".repeat(10),
  ])
    assert.throws(() => client.readRecovery(raw, saved.server_origin));
});

test("untrusted saved destination hints are replaced by current server review, while a changed fingerprint refuses", async () => {
  const t = transport(),
    client = new a.ArtifactOnwardApi(t.api),
    saved = recovery();
  saved.review.effects[0].connection.id = id(99);
  t.response(fixture.review);
  const verified = await client.refresh(saved.review);
  assert.deepEqual(verified.effects, fixture.review.effects);
  assert.notDeepEqual(verified.effects, saved.review.effects);
  assert.ok(t.calls[0].path.endsWith("/onward/previews"));
  t.response({ ...fixture.review, review_hash: "f".repeat(64) });
  await assert.rejects(() => client.refresh(saved.review));
  assert.ok(t.calls.every((call) => call.path.endsWith("/onward/previews")));
});
