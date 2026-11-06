import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { build } from "esbuild";
const [p, a] = await Promise.all(
  ["collection-exchange-source-types", "artifact-exchanges-api"].map(
    async (name) => {
      const b = await build({
        entryPoints: [`src/${name}.ts`],
        absWorkingDir: new URL("..", import.meta.url).pathname,
        bundle: true,
        write: false,
        format: "esm",
        target: "es2022",
      });
      return import(
        "data:text/javascript;base64," +
          Buffer.from(b.outputFiles[0].contents).toString("base64")
      );
    },
  ),
);
const fixture = JSON.parse(
  await readFile(new URL("fixtures/collections.json", import.meta.url), "utf8"),
).local;
const view = () => structuredClone(fixture.view),
  id = (n) => n.toString(16).padStart(8, "0") + "-1111-4111-8111-111111111111";
const expected = () =>
  p.collectedSourceExpectation(view(), fixture.view.inputs[0].id, 3);
const response = () => ({
  profile: "governed-collection-exchange-source-v1",
  artifact: { ...expected().artifact, acceptance_policy: "integrity-only-v1" },
  origin: expected().origin,
  state: "source-review-only",
  storage_verification: "not-checked",
});
function transport() {
  let reply = response(),
    during = () => {};
  const calls = [];
  const api = {
    session: {
      identity: {
        tenant_id: id(1),
        partner_id: id(2),
        actor_id: id(3),
        authority_revision: 3,
        root_policy_digest: createHash("sha256").update("/").digest("hex"),
        permissions: ["read", "deliver", "workflow_execute"],
      },
      session: { id: id(4) },
    },
    request: async (path, options, decode) => {
      calls.push({ path, options });
      during();
      return decode(reply);
    },
  };
  return { api, calls, reply: (v) => (reply = v), during: (f) => (during = f) };
}
test("only complete published collected inputs provide exact source hints; stopping old collection does not recall ordinary bytes", () => {
  const e = expected();
  assert.equal(e.artifact.file_revision_id, fixture.view.inputs[0].file_id);
  assert.equal(e.artifact.sha256, fixture.view.inputs[0].sha256);
  assert.equal(e.origin.manifest_sha256, fixture.view.job.manifest_hash);
  for (const state of ["held_or_unavailable", "unpublished_or_removed"]) {
    const v = view();
    v.local_states[0].state = state;
    assert.equal(p.collectedSourceExpectation(v, v.inputs[0].id, 3), null);
  }
  const unfinished = view();
  unfinished.job.captured = false;
  unfinished.job.state = "retry";
  unfinished.observed_state = "retry";
  unfinished.local_states[0].state = "awaiting_batch_capture";
  assert.equal(
    p.collectedSourceExpectation(unfinished, unfinished.inputs[0].id, 3),
    null,
  );
  const stopped = view();
  stopped.job.state = "cancelled";
  stopped.current_authority = false;
  stopped.observed_state = "cancelled";
  assert.deepEqual(
    p.collectedSourceExpectation(stopped, stopped.inputs[0].id, 3),
    e,
  );
  assert.equal(p.collectedSourceExpectation(view(), id(99), 3), null);
  const changed = view();
  changed.inputs[0].size_bytes++;
  assert.throws(() =>
    p.collectedSourceExpectation(changed, changed.inputs[0].id, 3),
  );
});
test("source response pins current exact bytes and manifest/input lineage without transport paths or stronger claims", () => {
  assert.deepEqual(
    p.asCollectedExchangeSource(response(), expected()),
    response(),
  );
  for (const mutate of [
    (r) => (r.artifact.file_revision_id = id(99)),
    (r) => r.artifact.size_bytes++,
    (r) => (r.artifact.sha256 = "f".repeat(64)),
    (r) => (r.origin.input_id = id(99)),
    (r) => (r.origin.first_collection_id = id(99)),
    (r) => (r.origin.manifest_sha256 = "f".repeat(64)),
    (r) => r.origin.workflow.version++,
    (r) => (r.origin.namespace_root = "/private"),
    (r) => (r.storage_verification = "verified"),
    (r) => (r.received = true),
  ]) {
    const value = response();
    mutate(value);
    assert.throws(() => p.asCollectedExchangeSource(value, expected()));
  }
  assert.equal(JSON.stringify(response()).includes("target_path"), false);
  assert.equal(JSON.stringify(response()).includes("source_connection"), false);
});
test("collection bridge uses one current-context read and never queues collection,offer or workflow work", async () => {
  const t = transport(),
    client = new a.ExchangeReceiveApi(t.api),
    e = expected();
  await client.collectedSource(e);
  assert.deepEqual(t.calls, [
    {
      path: `/v1/tenants/${id(1)}/partners/${id(2)}/workflow-collections/${e.origin.collection_id}/inputs/${e.origin.input_id}/exchange-source`,
      options: {},
    },
  ]);
  const invalid = structuredClone(e);
  invalid.origin.input_id = "https://unapproved.invalid/input";
  await assert.rejects(() => client.collectedSource(invalid));
  assert.equal(t.calls.length, 1);
  t.during(() => t.api.session.identity.authority_revision++);
  await assert.rejects(
    () => client.collectedSource(e),
    (error) => error.code === "context_changed",
  );
  await assert.rejects(
    () => client.collectedSource(e),
    (error) => error.code === "context_changed",
  );
  assert.equal(t.calls.length, 2);
  const receiver = transport();
  receiver.api.session.identity.permissions = ["read", "list"];
  await assert.rejects(
    () => new a.ExchangeReceiveApi(receiver.api).collectedSource(e),
    (error) => error.code === "permission_denied",
  );
  assert.equal(receiver.calls.length, 0);
});
test("in-flight caller mutation cannot replace expected accepted bytes or original lineage", async () => {
  const t = transport(),
    client = new a.ExchangeReceiveApi(t.api),
    e = expected();
  t.during(() => {
    e.artifact.size_bytes++;
    e.origin.input_identity = "f".repeat(64);
  });
  const result = await client.collectedSource(e);
  assert.equal(result.artifact.size_bytes, fixture.view.inputs[0].size_bytes);
  assert.equal(
    result.origin.input_identity,
    fixture.view.inputs[0].input_identity,
  );
});
