import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";
const built = await build({
  entryPoints: [
    new URL("../src/processing-types.ts", import.meta.url).pathname,
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
const fixture = JSON.parse(
  await readFile(
    new URL("fixtures/processing-workflow.json", import.meta.url),
    "utf8",
  ),
);
const session = {
  identity: {
    tenant_id: "11111111-1111-4111-8111-111111111111",
    partner_id: "22222222-2222-4222-8222-222222222222",
    actor_id: "33333333-3333-4333-8333-333333333333",
    authority_revision: fixture.contracts.authority_revision,
    root_policy_digest: fixture.contracts.namespace_root_digest,
  },
};
const ref = fixture.contracts.output_policy.reference;
const selected = structuredClone(fixture.contracts);
selected.profile = "record-processing-contracts-v2";
selected.output_policy.state = "output_active";
selected.output_binding = {
  profile: "producer-processing-output-policy-v1",
  policy_id: ref.id,
  policy_version: ref.version,
  policy_hash: ref.hash,
  publisher_id: "44444444-4444-4444-8444-444444444444",
  producer: session.identity,
};
test("selected browser contracts preserve exact producer and independent source metadata", () => {
  const actual = p.processingContracts(selected, session);
  assert.deepEqual(actual.output_binding, selected.output_binding);
  assert.deepEqual(actual.source, fixture.contracts.source);
  assert.deepEqual(actual.output_policy.reference, ref);
  for (const change of [
    (x) => (x.profile = "record-processing-contracts-v1"),
    (x) => delete x.output_binding,
    (x) =>
      (x.output_binding.producer.actor_id =
        "55555555-5555-4555-8555-555555555555"),
    (x) => x.output_binding.producer.authority_revision++,
    (x) => (x.output_binding.producer.root_policy_digest = "f".repeat(64)),
    (x) => x.output_binding.policy_version++,
    (x) => (x.output_binding.policy_hash = "f".repeat(64)),
    (x) => (x.output_binding.producer.permissions = ["admin"]),
    (x) => (x.output_policy.state = "active"),
  ]) {
    const bad = structuredClone(selected);
    change(bad);
    assert.throws(() => p.processingContracts(bad, session));
  }
  assert.throws(() => p.processingContracts(selected));
});

const apiBuilt = await build({
  entryPoints: [new URL("../src/processing-api.ts", import.meta.url).pathname],
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const a = await import(
  "data:text/javascript;base64," +
    Buffer.from(apiBuilt.outputFiles[0].contents).toString("base64")
);
test("selected metadata transport binds the complete reference and rejects changed session or a substituted default", async () => {
  const current = {
    identity: {
      ...session.identity,
      permissions: [
        "read",
        "write",
        "check_run",
        "workflow_manage",
        "workflow_approve",
        "workflow_execute",
      ],
    },
    session: {
      id: "66666666-6666-4666-8666-666666666666",
      state: "active",
      expires_at: "2027-01-01T00:00:00Z",
    },
    csrf_token: "stand-in",
    limits: {},
  };
  const calls = [];
  let mode = "selected";
  const api = {
    session: current,
    prefix: "/v1/tenants/t/partners/p",
    async request(path, options, decode) {
      calls.push({ path, options });
      if (mode === "changed")
        api.session = {
          ...current,
          identity: {
            ...current.identity,
            authority_revision: current.identity.authority_revision + 1,
          },
        };
      return decode(mode === "default" ? fixture.contracts : selected);
    },
  };
  const client = new a.ProcessingApi(api);
  const result = await client.contracts(
    fixture.contracts.source.file_revision_id,
    ref,
  );
  assert.equal(result.profile, "record-processing-contracts-v2");
  assert.equal(calls.length, 1);
  assert.ok(
    calls[0].path.endsWith(
      `?output_policy_id=${ref.id}&output_policy_version=${ref.version}&output_policy_hash=${ref.hash}`,
    ),
  );
  assert.deepEqual(calls[0].options, {});
  mode = "default";
  await assert.rejects(() =>
    client.contracts(fixture.contracts.source.file_revision_id, ref),
  );
  mode = "changed";
  await assert.rejects(() =>
    client.contracts(fixture.contracts.source.file_revision_id, ref),
  );
  const count = calls.length;
  await assert.rejects(() =>
    client.contracts(fixture.contracts.source.file_revision_id, ref),
  );
  assert.equal(calls.length, count);
});
