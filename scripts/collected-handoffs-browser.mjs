import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { wireResponse } from "./browser-wire.mjs";

// All intercepted calls still reach the certificate-checked real service. Only
// the committed response is dropped; recovery reads the original saved receipt.
export async function qualifyCollectedHandoffs(page, c, audit, record, actual) {
  const prefix = c.url + `/v1/tenants/${c.tenant}/partners/${c.partner}`;
  const region = () =>
    page.getByRole("region", { name: "Collection workflows", exact: true });
  const selected = () =>
    page.getByRole("region", { name: "Selected collection", exact: true });
  const panel = () =>
    selected().getByRole("region", {
      name: "Collected run handoffs",
      exact: true,
    });
  const base = "/workflow-collections/" + c.job.id + "/handoffs";
  let observation = 0;
  const response = (path, action) =>
    wireResponse(
      page,
      prefix + path,
      action,
      actual,
      "handoff-response-" + observation++,
    );
  const confirm = () =>
    page
      .getByRole("button", { name: "Confirm exact decision", exact: true })
      .click();
  const inspectJob = () =>
    response("/workflow-collections/" + c.job.id, () =>
      region()
        .getByRole("button", {
          name: "Inspect collection " + c.job.id,
          exact: true,
        })
        .click(),
    );
  const inspectHandoff = (id) =>
    response(base + "/" + id, () =>
      panel()
        .getByRole("button", { name: "Inspect handoff " + id, exact: true })
        .click(),
    );
  const contacts = () =>
    Promise.all(
      c.peer_logs.map(
        async (p) =>
          (await readFile(p, "utf8")).split("Accepted publickey for ").length -
          1,
      ),
    );
  const review = () =>
    panel()
      .getByRole("checkbox", {
        name: "I reviewed both workflows, exact file facts, old intents, selected recipients and key identities for this fingerprint.",
        exact: true,
      })
      .check();
  const before = await contacts();
  const original = await inspectJob(),
    input = original.inputs.find((i) => i.id === c.handoff_input_id);
  assert.ok(input?.run_id);
  assert.equal(original.replacements, undefined);
  async function prepare() {
    await panel()
      .getByLabel("Collected input to replace", { exact: true })
      .selectOption(input.id);
    await panel()
      .getByLabel("Replacement workflow version", { exact: true })
      .fill(String(c.handoff_target.version));
    const preview = await response(base + "/preview", () =>
      panel()
        .getByRole("button", {
          name: "Preview collected run handoff",
          exact: true,
        })
        .click(),
    );
    assert.equal(preview.external_contact, false);
    assert.equal(preview.approval_required, true);
    assert.equal(preview.definition.source_run.id, input.run_id);
    assert.equal(
      preview.definition.workflow.hash,
      c.handoff_target.definition_hash,
    );
    assert.deepEqual(preview.source_plan.facts, preview.definition.plan.facts);
    assert.notEqual(
      preview.source_effects[0].recipient_fingerprint,
      preview.effects[0].recipient_fingerprint,
    );
    assert.equal(preview.definition.plan.facts.source.name, input.source_name);
    assert.equal(
      preview.definition.plan.facts.source.manifest_hash,
      original.job.manifest_hash,
    );
    await review();
    await audit("collected-handoff-two-plans-and-public-identities");
    return preview;
  }
  async function lostResponseAndReload(operation, recordID) {
    const path =
      operation === "propose"
        ? base + "/proposals"
        : base + "/" + recordID + "/" + operation;
    const seen = [];
    await page.route(prefix + path, async (route) => {
      const r = await actual(
        route,
        "handoff-lost-" + operation + "-" + seen.length,
        prefix + path,
      );
      seen.push(r);
      await route.abort("failed");
    });
    await confirm();
    await page.getByText(/^The result was not confirmed\./).waitFor();
    assert.equal(seen.length, 1);
    assert.ok(seen[0].idempotency_key);
    const first = JSON.parse(seen[0].body);
    assert.equal(first.replayed, false);
    const h = first.resource.handoff;
    await page.reload();
    await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
    await page
      .getByRole("button", { name: "Collections", exact: true })
      .click();
    await inspectJob();
    await inspectHandoff(h.id);
    const receipt = await response(
      base + "/receipts/" + seen[0].idempotency_key + "/result",
      () =>
        panel()
          .getByRole("button", {
            name: "Look up saved " + operation + " handoff receipt",
            exact: true,
          })
          .click(),
    );
    assert.equal(receipt.replayed, true);
    assert.deepEqual(receipt.resource, first.resource);
    assert.equal(seen.length, 1, "receipt lookup must not retry a mutation");
    await page.unroute(prefix + path);
    await audit("collected-handoff-" + operation + "-receipt-after-reload");
    record(
      "collected-handoff-" + operation + "-read-only-original-key-recovery",
    );
    return h;
  }
  const preview = await prepare();
  await panel()
    .getByRole("button", {
      name: "Review proposing collected handoff",
      exact: true,
    })
    .click();
  let h = await lostResponseAndReload("propose");
  // Withdrawal changes no run. A fresh proposal for the same reviewed meaning
  // can then be approved, preserving the cancelled record in bounded history.
  await panel()
    .getByRole("button", {
      name: "Review withdrawing collected handoff",
      exact: true,
    })
    .click();
  const cancelled = await response(base + "/" + h.id + "/cancel", confirm);
  assert.equal(cancelled.resource.handoff.state, "cancelled");
  await panel()
    .getByText(/^Decision cancelled;/)
    .waitFor();
  await prepare();
  await panel()
    .getByRole("button", {
      name: "Review proposing collected handoff",
      exact: true,
    })
    .click();
  const proposed = await response(base + "/proposals", confirm);
  h = proposed.resource.handoff;
  assert.notEqual(h.id, cancelled.resource.handoff.id);
  await panel()
    .getByText(/^Decision proposed;/)
    .waitFor();
  await review();
  await panel()
    .getByRole("button", {
      name: "Review approving collected handoff",
      exact: true,
    })
    .click();
  h = await lostResponseAndReload("approve", h.id);
  assert.equal(h.state, "approved");
  await review();
  await panel()
    .getByRole("button", {
      name: "Review executing collected handoff",
      exact: true,
    })
    .click();
  h = await lostResponseAndReload("execute", h.id);
  assert.equal(h.state, "completed");
  const next = await response("/workflow-runs/" + h.planned_run_id, () =>
    panel()
      .getByRole("button", {
        name: "Inspect current replacement run",
        exact: true,
      })
      .click(),
  );
  assert.equal(next.run.id, h.planned_run_id);
  assert.deepEqual(next.run.execution_plan, preview.definition.plan);
  assert.equal(next.run.routing_authorization_id, undefined);
  assert.equal(next.steps[0].attempts, 0);
  const old = await response("/workflow-runs/" + input.run_id, () =>
    selected()
      .getByRole("button", {
        name: "Inspect original run for " + input.source_name,
        exact: true,
      })
      .click(),
  );
  assert.equal(old.observed_state, "cancelled");
  assert.ok(
    old.steps.every((s) => s.state === "cancelled" && s.attempts === 0),
  );
  const current = await response("/workflow-runs/" + h.planned_run_id, () =>
    selected()
      .getByRole("button", {
        name: "Inspect downstream run for " + input.source_name,
        exact: true,
      })
      .click(),
  );
  assert.deepEqual(current, next);
  const final = await response("/workflow-collections/" + c.job.id, () =>
    selected()
      .getByRole("button", { name: "Refresh selected collection", exact: true })
      .click(),
  );
  assert.deepEqual(final.job, original.job);
  assert.deepEqual(final.inputs, original.inputs);
  assert.equal(final.replacements.length, 1);
  assert.equal(final.replacements[0].original_run_id, input.run_id);
  assert.equal(final.replacements[0].current_run_id, h.planned_run_id);
  assert.deepEqual(await contacts(), before);
  await audit("collected-handoff-original-and-successor-navigation");
  record("collected-handoff-browser-governance-no-peer-contact");
  return {
    handoff: h,
    view: final,
    runs: [next],
    withdrawn_handoff: cancelled.resource.handoff,
  };
}
