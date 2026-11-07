import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { build } from "esbuild";
const built = await build({
  entryPoints: [
    new URL("../src/output-policy-api.ts", import.meta.url).pathname,
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
    authority_revision: 1,
    root_policy_digest: createHash("sha256").update("/").digest("hex"),
    permissions: ["admin", "intake_manage"],
  },
  session: {
    id: "44444444-4444-4444-8444-444444444444",
    state: "active",
    expires_at: "2027-01-01T00:00:00Z",
  },
  csrf_token: "stand-in-secret",
  limits: {},
};
const command = {
  kind: "register",
  key: "original-output-register",
  body: {
    expected_version: 0,
    producer_id: "55555555-5555-4555-8555-555555555555",
    definition: fixture.contracts.output_policy.definition,
  },
};
test("output policy publication recovery binds the whole command and root publisher without workflow or byte grants", () => {
  assert.equal(p.outputPolicyAllowed(session), true);
  const request = p.outputPolicyMutation(command);
  const saved = p.outputPolicyRecovery(
    request,
    session,
    "https://freightctl.test",
  );
  assert.equal(JSON.stringify(saved).includes(session.csrf_token), false);
  assert.equal(JSON.stringify(saved).includes(session.session.id), false);
  assert.deepEqual(
    p.parseOutputPolicyRecovery(
      JSON.stringify(saved),
      session,
      "https://freightctl.test",
    ),
    request,
  );
  const reordered = structuredClone(saved);
  reordered.participant = Object.fromEntries(
    Object.entries(reordered.participant).reverse(),
  );
  assert.deepEqual(
    p.parseOutputPolicyRecovery(
      JSON.stringify(reordered),
      session,
      "https://freightctl.test",
    ),
    request,
  );
  for (const mutate of [
    (x) => (x.request.key = "different"),
    (x) => (x.request.body.producer_id = session.identity.actor_id),
    (x) => x.request.body.definition.max_rows++,
    (x) => (x.server_origin = "https://outside.test"),
    (x) => x.participant.authority_revision++,
    (x) => (x.participant.root_policy_digest = "f".repeat(64)),
    (x) => (x.request.body.approved = true),
  ]) {
    const bad = structuredClone(saved);
    mutate(bad);
    assert.throws(() =>
      p.parseOutputPolicyRecovery(
        JSON.stringify(bad),
        session,
        "https://freightctl.test",
      ),
    );
  }
  const worker = structuredClone(session);
  worker.identity.permissions = ["read", "write", "workflow_execute"];
  assert.equal(p.outputPolicyAllowed(worker), false);
});

test("an uncertain administrator registration retries the same body and key and keeps current inspection separate", async () => {
  const ref = {
    id: "66666666-6666-4666-8666-666666666666",
    version: 1,
    hash: fixture.contracts.output_policy.reference.hash,
  };
  const record = {
    profile: "producer-processing-output-policy-v1",
    policy: {
      id: ref.id,
      version: ref.version,
      definition: fixture.contracts.output_policy.definition,
      definition_hash: ref.hash,
      state: "output_active",
      revision: 1,
      approval_authority: 0,
    },
    binding: {
      profile: "producer-processing-output-policy-v1",
      policy_id: ref.id,
      policy_version: ref.version,
      policy_hash: ref.hash,
      publisher_id: session.identity.actor_id,
      producer: {
        tenant_id: session.identity.tenant_id,
        partner_id: session.identity.partner_id,
        actor_id: command.body.producer_id,
        authority_revision: 7,
        root_policy_digest: createHash("sha256")
          .update("/worker")
          .digest("hex"),
      },
    },
    observation: "original-command-receipt;current-state-not-checked",
    ingress_changed: false,
    usage: "producer-workflow-output-contract",
  };
  const calls = [];
  let mode = "lost";
  const api = {
    session: structuredClone(session),
    prefix: "/v1/tenants/t/partners/p",
    async request(path, options, decode) {
      calls.push({ path, options });
      if (mode === "lost") {
        mode = "receipt";
        throw new Error("lost after commit");
      }
      if (mode === "changed")
        api.session = {
          ...api.session,
          identity: {
            ...api.session.identity,
            authority_revision: api.session.identity.authority_revision + 1,
          },
        };
      if (mode === "current")
        return decode({
          ...record,
          policy: { ...record.policy, state: "output_revoked", revision: 2 },
          observation: "current-contract-metadata-only",
          producer_binding_current_at_observation: true,
        });
      return decode({ resource: record, replayed: true });
    },
  };
  const client = new p.OutputPolicyApi(api);
  await assert.rejects(() => client.mutate(command));
  const receipt = await client.mutate(command);
  assert.equal(receipt.replayed, true);
  assert.equal(receipt.resource.policy.state, "output_active");
  assert.deepEqual(calls[0], calls[1]);
  assert.equal(calls[0].options.headers["Idempotency-Key"], command.key);
  assert.equal(calls[0].path, api.prefix + "/processing-output-policies");
  mode = "current";
  const current = await client.get(ref);
  assert.equal(current.policy.state, "output_revoked");
  assert.equal(receipt.resource.policy.state, "output_active");
  mode = "changed";
  await assert.rejects(() => client.mutate(command));
  const count = calls.length;
  await assert.rejects(() => client.mutate(command));
  assert.equal(calls.length, count);
});

test("root publication refuses receipts that change ingress, producer, scope or full rule meaning", async () => {
  const ref = {
    id: "66666666-6666-4666-8666-666666666666",
    version: 1,
    hash: fixture.contracts.output_policy.reference.hash,
  };
  const record = {
    profile: "producer-processing-output-policy-v1",
    policy: {
      id: ref.id,
      version: ref.version,
      definition: fixture.contracts.output_policy.definition,
      definition_hash: ref.hash,
      state: "output_active",
      revision: 1,
      approval_authority: 0,
    },
    binding: {
      profile: "producer-processing-output-policy-v1",
      policy_id: ref.id,
      policy_version: ref.version,
      policy_hash: ref.hash,
      publisher_id: session.identity.actor_id,
      producer: {
        tenant_id: session.identity.tenant_id,
        partner_id: session.identity.partner_id,
        actor_id: command.body.producer_id,
        authority_revision: 7,
        root_policy_digest: createHash("sha256")
          .update("/worker")
          .digest("hex"),
      },
    },
    observation: "original-command-receipt;current-state-not-checked",
    ingress_changed: false,
    usage: "producer-workflow-output-contract",
  };
  for (const change of [
    (r) => (r.ingress_changed = true),
    (r) => r.policy.definition.max_rows++,
    (r) => r.policy.version++,
    (r) => (r.binding.producer.actor_id = session.identity.actor_id),
    (r) =>
      (r.binding.producer.tenant_id = "77777777-7777-4777-8777-777777777777"),
    (r) => (r.binding.producer.permissions = ["admin"]),
    (r) => (r.binding.publisher_id = command.body.producer_id),
  ]) {
    const bad = structuredClone(record);
    change(bad);
    const api = {
      session: structuredClone(session),
      prefix: "/v1/tenants/t/partners/p",
      async request(path, options, decode) {
        return decode({ resource: bad, replayed: false });
      },
    };
    const client = new p.OutputPolicyApi(api);
    await assert.rejects(() => client.mutate(command));
  }
});
