import assert from "node:assert/strict";
import { test } from "node:test";
import { build } from "esbuild";
import path from "node:path";
import { fileURLToPath } from "node:url";
const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const bundle = await build({
  absWorkingDir: web,
  entryPoints: ["src/onboarding-probes-types.ts"],
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const {
  probeDefinition,
  probeFingerprint,
  asProbeStart,
  asProbeView,
  asProbePage,
} = await import(
  "data:text/javascript;base64," +
    Buffer.from(bundle.outputFiles[0].contents).toString("base64")
);
const plan = "11111111-1111-4111-8111-111111111111",
  requirement = "22222222-2222-4222-8222-222222222222",
  connection = "33333333-3333-4333-8333-333333333333",
  author = "44444444-4444-4444-8444-444444444444",
  id = "55555555-5555-4555-8555-555555555555",
  owner = "66666666-6666-4666-8666-666666666666";
const request = () => ({
  plan: { id: plan, version: 3, hash: "a".repeat(64) },
  requirement_id: requirement,
  connection: { id: connection, version: 2, hash: "b".repeat(64) },
  expected_authority_revision: 7,
});
const probe = () => ({
  id,
  author_id: author,
  definition: probeDefinition(request()),
  definition_hash: probeFingerprint(probeDefinition(request())),
  state: "queued",
  revision: 1,
  worker_key: "",
  lease_owner: "",
  lease_until: null,
  started_at: null,
  completed_at: null,
  created_at: "2026-10-29T12:00:00Z",
  observation: {
    code: "awaiting_worker",
    ssh_identity_and_authentication: false,
    sftp_negotiated: false,
    required_extensions: false,
    directory_traversable: false,
  },
});
const view = () => {
  const p = probe();
  p.state = "succeeded";
  p.revision = 3;
  p.worker_key = "original-work";
  p.lease_owner = owner;
  p.started_at = "2026-10-29T12:00:01Z";
  p.lease_until = "2026-10-29T12:00:21Z";
  p.completed_at = "2026-10-29T12:00:02Z";
  p.observation = {
    code: "connectivity_verified",
    ssh_identity_and_authentication: true,
    sftp_negotiated: true,
    required_extensions: true,
    directory_traversable: true,
  };
  return {
    probe: p,
    connection: {
      id: connection,
      version: 2,
      definition_hash: "b".repeat(64),
      state: "active",
      revision: 1,
      address: "127.0.0.1:2022",
      user: "receiver",
      directory: "/inbox",
      host_fingerprint: "SHA256:synthetic-host",
      key_fingerprint: "SHA256:synthetic-client",
    },
    current_bindings: true,
    binding_reason: "current",
    evidence_strength: "connectivity_only",
    file_exchange_performed: false,
    production_active: false,
  };
};
test("probe canonical definition matches independent Go and Python golden", () => {
  assert.equal(
    probeFingerprint(probeDefinition(request())),
    "0588ff43f2acdc0b70ed2956670581b8650df0b5db024cb797639fe33e5b299e",
  );
  const dirty = {
    ...request(),
    endpoint: "https://untrusted.invalid",
    approved: true,
  };
  assert.deepEqual(probeDefinition(dirty), probeDefinition(request()));
  assert.equal(
    asProbeStart({ resource: probe(), replayed: true }, author, request()).id,
    id,
  );
});
test("probe receipts bind exact actor, plan, requirement and registered connection", () => {
  for (const mutate of [
    (p) => (p.author_id = owner),
    (p) => (p.definition.requirement_id = owner),
    (p) => (p.definition.connection.version = 99),
    (p) => (p.definition.plan.hash = "f".repeat(64)),
    (p) => (p.definition.authority_revision = 8),
    (p) => (p.definition_hash = "f".repeat(64)),
  ]) {
    const p = probe();
    mutate(p);
    assert.throws(() =>
      asProbeStart({ resource: p, replayed: false }, author, request()),
    );
  }
  assert.throws(() =>
    asProbeStart({ resource: probe(), replayed: "yes" }, author, request()),
  );
});
test("connectivity observations cannot claim exchange or activation and preserve changed bindings", () => {
  const good = view();
  assert.equal(
    asProbeView(good, author, { id, hash: good.probe.definition_hash }).probe
      .state,
    "succeeded",
  );
  for (const mutate of [
    (v) => (v.production_active = true),
    (v) => (v.file_exchange_performed = true),
    (v) => (v.evidence_strength = "business_acceptance"),
    (v) => (v.probe.observation.directory_traversable = false),
    (v) => (v.connection.id = owner),
    (v) => (v.connection.definition_hash = "f".repeat(64)),
    (v) => (v.current_bindings = "true"),
    (v) => (v.probe.author_id = owner),
  ]) {
    const v = view();
    mutate(v);
    assert.throws(() =>
      asProbeView(v, author, { id, hash: good.probe.definition_hash }),
    );
  }
  const stale = view();
  stale.current_bindings = false;
  stale.binding_reason = "binding_changed";
  delete stale.connection;
  assert.equal(asProbeView(stale, author).current_bindings, false);
  const pending = probe();
  pending.observation.ssh_identity_and_authentication = true;
  assert.throws(() =>
    asProbeStart({ resource: pending, replayed: false }, author, request()),
  );
});
test("probe history remains bounded and actor/plan scoped", () => {
  assert.equal(
    asProbePage({ probes: [probe()] }, author, plan).probes.length,
    1,
  );
  assert.throws(() =>
    asProbePage({ probes: Array(101).fill(probe()) }, author, plan),
  );
  assert.throws(() =>
    asProbePage({ probes: [probe(), probe()] }, author, plan),
  );
  assert.throws(() => asProbePage({ probes: [probe()] }, owner, plan));
  assert.throws(() => asProbePage({ probes: [probe()] }, author, owner));
});
