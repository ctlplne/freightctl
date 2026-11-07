import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";
const built = await build({
  entryPoints: [
    new URL("../src/processing-proposal-api.ts", import.meta.url).pathname,
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
    new URL("fixtures/processing-proposal.json", import.meta.url),
    "utf8",
  ),
);
const row = fixture.proposal;
const session = (executor = false) => ({
  identity: {
    ...(executor ? row.definition.executor : row.definition.author),
    permissions: executor
      ? ["workflow_manage", "read", "write", "check_run", "workflow_execute"]
      : ["workflow_manage"],
  },
  session: {
    id: "99999999-9999-4999-8999-999999999999",
    state: "active",
    expires_at: "2027-01-01T00:00:00Z",
  },
  csrf_token: "PRIVATE_PROPOSAL_CSRF",
  limits: {},
});
const summary = () => ({
  id: row.id,
  author_id: row.definition.author.actor_id,
  executor_id: row.definition.executor.actor_id,
  definition_hash: row.definition_hash,
  state: "pending",
  revision: 1,
  expires_at: row.definition.expires_at,
});
const submit = () =>
  p.proposalMutation({
    kind: "submit",
    key: "original-proposal",
    body: {
      executor_id: row.definition.executor.actor_id,
      definition: row.definition.definition,
      expires_at: row.definition.expires_at,
    },
  });
test("proposal browser validates the complete canonical rules,participants and expiry", () => {
  assert.equal(
    p.processingProposal(fixture).proposal.definition_hash,
    row.definition_hash,
  );
  for (const change of [
    (v) => (v.proposal.definition.definition.processing.reason = "changed"),
    (v) => v.proposal.definition.executor.authority_revision++,
    (v) =>
      (v.proposal.definition.executor.tenant_id =
        "00000000-0000-4000-8000-000000000001"),
    (v) => (v.proposal.definition.approved = true),
    (v) => (v.proposal.state = "approved"),
    (v) => (v.proposal.revision = 2),
    (v) => (v.proposal.definition.expires_at = v.proposal.created_at),
  ]) {
    const v = structuredClone(fixture);
    change(v);
    assert.throws(() => p.processingProposal(v));
  }
});
test("definition management gives authors no executor or approval action", () => {
  const v = p.processingProposal(fixture);
  assert.equal(p.proposalAllowed(session(), "submit"), true);
  assert.equal(p.proposalAllowed(session(), "withdraw", v), true);
  assert.equal(p.proposalAllowed(session(), "adopt", v), false);
  assert.equal(p.proposalAllowed(session(true), "adopt", v), true);
  assert.equal(p.proposalAllowed(session(true), "approve", v), false);
  const s = session(true);
  s.identity.permissions = ["workflow_manage"];
  assert.equal(p.proposalAllowed(s, "adopt", v), false);
});
test("saved proposal recovery binds whole request,origin and authority without browser secrets", () => {
  const s = session(),
    m = submit(),
    r = p.proposalRecovery(m, s, "https://freightctl.test"),
    text = JSON.stringify(r);
  assert.ok(!text.includes(s.csrf_token) && !text.includes(s.session.id));
  assert.deepEqual(
    p.parseProposalRecovery(text, s, "https://freightctl.test"),
    m,
  );
  for (const change of [
    (r) => (r.request.key = "replacement"),
    (r) => (r.request.body.definition.processing.reason = "changed"),
    (r) => (r.request.body.approved = true),
    (r) => r.participant.authority_revision++,
    (r) => (r.server_origin = "https://other.test"),
  ]) {
    const v = structuredClone(r);
    change(v);
    assert.throws(() =>
      p.parseProposalRecovery(JSON.stringify(v), s, "https://freightctl.test"),
    );
  }
});
test("lost committed proposal reply recovers the same request after a new browser session", async () => {
  const s = session(),
    m = submit(),
    saved = JSON.stringify(p.proposalRecovery(m, s, "https://freightctl.test")),
    calls = [];
  let committed = 0;
  const api = {
    session: s,
    prefix: "/test",
    request: async (path, options, decode) => {
      calls.push({
        path,
        body: options.body,
        key: options.headers["Idempotency-Key"],
      });
      if (calls.length === 1) {
        committed++;
        throw Error("committed reply lost");
      }
      return decode({
        resource: {
          profile: "processing-workflow-proposal-v1",
          observation: "original-command-receipt",
          proposal: summary(),
        },
        replayed: true,
      });
    },
  };
  await assert.rejects(new p.ProcessingProposalApi(api).mutate(m));
  api.session = structuredClone(s);
  api.session.session.id = "88888888-8888-4888-8888-888888888888";
  const recovered = p.parseProposalRecovery(
      saved,
      api.session,
      "https://freightctl.test",
    ),
    receipt = await new p.ProcessingProposalApi(api).mutate(recovered);
  assert.equal(receipt.replayed, true);
  assert.equal(committed, 1);
  assert.deepEqual(calls[0], calls[1]);
});
test("adoption receipt is an exact unapproved draft and cannot assert approval or execution", async () => {
  const view = p.processingProposal(fixture),
    s = session(true),
    ref = {
      id: "77777777-7777-4777-8777-777777777777",
      version: 1,
      hash: row.definition.workflow_definition_hash,
    };
  const resource = {
    profile: "processing-workflow-proposal-v1",
    observation: "original-command-receipt",
    proposal: {
      ...summary(),
      state: "adopted",
      revision: 2,
      adopted_workflow: ref,
    },
    adopted_workflow: {
      id: ref.id,
      version: 1,
      definition_hash: ref.hash,
      state: "draft",
      revision: 1,
      approval_authority: 0,
    },
  };
  let wire = resource;
  const api = {
    session: s,
    prefix: "/test",
    request: async (_, options, decode) =>
      decode({ resource: wire, replayed: true }),
  };
  const m = p.proposalMutation({
    kind: "adopt",
    id: row.id,
    key: "original-adoption",
    body: { definition_hash: row.definition_hash, expected_revision: 1 },
  });
  assert.equal(
    (await new p.ProcessingProposalApi(api).mutate(m, view)).summary.state,
    "adopted",
  );
  for (const change of [
    (v) => (v.adopted_workflow.state = "approved"),
    (v) => (v.adopted_workflow.approval_authority = 7),
    (v) => (v.proposal.executor_id = row.definition.author.actor_id),
    (v) => (v.proposal.definition_hash = "f".repeat(64)),
    (v) => delete v.adopted_workflow,
  ]) {
    wire = structuredClone(resource);
    change(wire);
    await assert.rejects(new p.ProcessingProposalApi(api).mutate(m, view));
  }
});
test("responses after scope changes and unrelated private rows are refused", async () => {
  const s = session();
  let complete;
  const api = {
    session: s,
    prefix: "/test",
    request: (_, __, decode) =>
      new Promise((resolve) => {
        complete = () => {
          try {
            resolve(decode(fixture));
          } catch (e) {
            resolve(Promise.reject(e));
          }
        };
      }),
  };
  const request = new p.ProcessingProposalApi(api).get(row.id);
  s.identity.authority_revision++;
  complete();
  await assert.rejects(request);
  api.session = session();
  api.session.identity.actor_id = "55555555-5555-4555-8555-555555555555";
  const other = new p.ProcessingProposalApi(api).get(row.id);
  complete();
  await assert.rejects(other);
});
