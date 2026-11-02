import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { probe as qualifyCapturedRouting } from "./captured-routing-browser.mjs";
import { wireResponse } from "./browser-wire.mjs";
import { qualifyCollectedHandoffs } from "./collected-handoffs-browser.mjs";

// Every operation reaches the real HTTPS service through certificate-checked
// response capture. Explicit loss cases drop the first committed response and
// require retries to retain their original command key.
export async function qualifyRouting(page, c, audit, record, actual) {
  const prefix = c.url + `/v1/tenants/${c.tenant}/partners/${c.partner}`;
  const region = page.getByRole("region", {
    name: "Collection workflows",
    exact: true,
  });
  const selected = page.getByRole("region", {
    name: "Selected collection",
    exact: true,
  });
  const responses = [];
  const confirm = () =>
    page
      .getByRole("button", { name: "Confirm exact decision", exact: true })
      .click();
  const contacts = () =>
    Promise.all(
      c.peer_logs.map(
        async (p) =>
          (await readFile(p, "utf8")).split("Accepted publickey for ").length -
          1,
      ),
    );
  const open = async () => {
    await page
      .getByRole("button", { name: "Collections", exact: true })
      .click();
    await region
      .getByRole("heading", { name: "Collection workflows", exact: true })
      .waitFor();
  };
  let observation = 0;
  const response = (route, action) =>
    wireResponse(
      page,
      prefix + route,
      action,
      actual,
      `routing-${c.routing_phase}-response-${observation++}`,
    );
  async function inspect(id) {
    return response("/workflow-collections/" + id, () =>
      region
        .getByRole("button", { name: "Inspect collection " + id, exact: true })
        .click(),
    );
  }
  async function loss(route, key) {
    const target = prefix + route,
      label = "routing-" + c.routing_phase + "-" + key,
      seen = [];
    await page.route(target, async (route) => {
      const r = await actual(route, label + "-" + seen.length, target);
      seen.push(r);
      if (seen.length === 1) await route.abort("failed");
      else
        await route.fulfill({
          status: r.status,
          contentType: "application/json",
          body: r.body,
        });
    });
    await confirm();
    await page.getByText(/^The result was not confirmed\./).waitFor();
    await confirm();
    await page.locator("dialog[open]").waitFor({ state: "hidden" });
    await page.unroute(target);
    assert.equal(seen.length, 2);
    assert.ok(seen[0].idempotency_key);
    assert.equal(seen[0].idempotency_key, seen[1].idempotency_key);
    assert.deepEqual(seen[0].selection, seen[1].selection);
    const first = JSON.parse(seen[0].body),
      second = JSON.parse(seen[1].body);
    assert.equal(first.replayed, false);
    assert.equal(second.replayed, true);
    if (first.resource !== undefined)
      assert.deepEqual(first.resource, second.resource);
    else {
      assert.deepEqual(first.dispatch, second.dispatch);
      assert.deepEqual(first.status, second.status);
    }
    responses.push(...seen);
    record(label + "-original-key-after-lost-response");
    return second.resource ?? second;
  }
  async function condition(group, pattern) {
    const own = group.getByRole("group", { name: "Condition", exact: true });
    await own
      .getByLabel("Fact to compare", { exact: true })
      .selectOption("source.name");
    await own.getByLabel("Comparison", { exact: true }).selectOption("glob");
    await own
      .getByLabel("Comparison text (case-sensitive)", { exact: true })
      .fill(pattern);
  }
  await open();
  let result = {};
  if (c.routing_phase === "handoff-govern") {
    result = await qualifyCollectedHandoffs(page, c, audit, record, actual);
  } else if (c.routing_phase === "create") {
    const before = await contacts();
    for (const [label, value] of Object.entries({
      "Collection workflow name": "Operator settlement routing",
      "Ready manifest filename": "browser.ready.json",
      "Virtual local target folder": "/browser-routing",
      "Maximum files per batch": "4",
      "Maximum bytes per file": "1048576",
      "Maximum bytes per batch": "2097152",
    }))
      await region.getByLabel(label, { exact: true }).fill(value);
    await region
      .getByLabel("Registered source connection", { exact: true })
      .selectOption(c.source.id + ":" + c.source.version);
    for (const [i, id] of ["north", "south", "audit"].entries()) {
      await region
        .getByRole("button", { name: "Add transfer step", exact: true })
        .click();
      await region.getByLabel(`Step ${i + 1} ID`, { exact: true }).fill(id);
      const connection = id === "north" ? c.destination : c.audit_destination;
      await region
        .getByLabel(`Step ${i + 1} receiver`, { exact: true })
        .selectOption(connection.id + ":" + connection.version);
      await region
        .getByLabel(`Step ${i + 1} filename`, { exact: true })
        .fill("browser-" + id + ".csv");
    }
    await region
      .getByLabel("Route each file with approved conditions and finite loops", {
        exact: true,
      })
      .check();
    const root = region.getByRole("group", { name: "Program", exact: true });
    await root
      .getByRole("button", { name: "Remove program step 1", exact: true })
      .click();
    await root
      .getByRole("button", { name: "Add conditional branch", exact: true })
      .click();
    const branch = root.getByRole("group", {
      name: "Program step 1: if",
      exact: true,
    });
    // The first condition belongs to this branch; nested groups are edited only
    // after that comparison has been completed.
    await condition(branch, "north-*.csv");
    const matched = branch.getByRole("group", {
      name: "Program 1 when matched",
      exact: true,
    });
    await matched
      .getByRole("button", { name: "Remove program step 1", exact: true })
      .click();
    await matched
      .getByRole("button", { name: "Add finite recipient loop", exact: true })
      .click();
    const loop = matched.getByRole("group", {
      name: "Program 1 when matched step 1: for each",
      exact: true,
    });
    await loop.getByLabel("south", { exact: true }).uncheck();
    const otherwise = branch.getByRole("group", {
      name: "Program 1 otherwise",
      exact: true,
    });
    await otherwise
      .getByRole("button", { name: "Remove program step 1", exact: true })
      .click();
    await otherwise
      .getByRole("button", { name: "Add conditional branch", exact: true })
      .click();
    const south = otherwise.getByRole("group", {
      name: "Program 1 otherwise step 1: if",
      exact: true,
    });
    await condition(south, "south-*.csv");
    const southMatched = south.getByRole("group", {
      name: "Program 1 otherwise 1 when matched",
      exact: true,
    });
    await southMatched
      .getByRole("button", { name: "Remove program step 1", exact: true })
      .click();
    await southMatched
      .getByRole("button", { name: "Add approved delivery", exact: true })
      .click();
    await southMatched
      .getByLabel("Approved delivery step or loop item", { exact: true })
      .selectOption("south");
    await audit("routing-structured-branch-loop-editor");
    const preview = await response("/workflows/validate", () =>
      region
        .getByRole("button", {
          name: "Preview workflow definition",
          exact: true,
        })
        .click(),
    );
    assert.equal(preview.definition.schema_version, 2);
    assert.deepEqual(preview.definition.program, c.expected_program);
    assert.equal(preview.external_contact, false);
    await region
      .getByRole("button", {
        name: "Review saving workflow draft",
        exact: true,
      })
      .click();
    await audit("routing-draft-rule-review");
    let workflow = await loss("/workflows/drafts", "save-draft");
    await page.reload();
    await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
    await open();
    await region
      .getByLabel("Saved collection workflow", { exact: true })
      .selectOption(workflow.id + ":" + workflow.version);
    await region
      .getByRole("heading", {
        name: workflow.definition.name + ": draft",
        exact: true,
      })
      .waitFor();
    await region
      .getByRole("button", { name: "Review workflow approval", exact: true })
      .click();
    await audit("routing-approval-rule-review");
    workflow = await loss(
      "/workflows/" + workflow.id + "/1/approve",
      "approve",
    );
    await region
      .getByLabel("Collection and sending cutoff from queue time (seconds)", {
        exact: true,
      })
      .fill("300");
    const previewJob = await response("/workflow-collections/preview", () =>
      region
        .getByRole("button", { name: "Preview collection job", exact: true })
        .click(),
    );
    assert.equal(previewJob.external_contact, false);
    await region
      .getByRole("button", { name: "Review queueing collection", exact: true })
      .click();
    await audit("routing-collection-rule-review");
    const job = await loss("/workflow-collections", "queue");
    assert.deepEqual(await contacts(), before);
    result = { workflow, job };
  } else if (c.routing_phase === "route") {
    const before = await contacts();
    let view = await inspect(c.job.id);
    assert.ok(view.job.captured);
    assert.ok(view.inputs.every((i) => !i.run_id));
    const routingAuthorization = c.captured_routing
      ? await qualifyCapturedRouting(
          page,
          c,
          selected,
          view,
          audit,
          record,
          actual,
        )
      : undefined;
    const previews = [];
    for (const input of view.inputs) {
      const p = await response("/workflow-runs/preview", () =>
        selected
          .getByRole("button", {
            name: "Preview routing for " + input.source_name,
            exact: true,
          })
          .click(),
      );
      assert.equal(p.external_contact, false);
      assert.equal(p.execution_plan.facts.source.collection_id, c.job.id);
      assert.deepEqual(
        p.execution_plan.selected_steps,
        c.expected[input.source_name],
      );
      previews.push(p);
    }
    await audit("routing-exact-input-preview");
    await selected
      .getByRole("button", {
        name: "Review recording routing outcomes",
        exact: true,
      })
      .click();
    await audit("routing-outcome-review");
    await loss("/workflow-collections/" + c.job.id + "/refresh", "admit");
    view = await response("/workflow-collections/" + c.job.id, () =>
      selected
        .getByRole("button", {
          name: "Refresh selected collection",
          exact: true,
        })
        .click(),
    );
    assert.ok(view.inputs.every((i) => i.run_id));
    const runs = [];
    for (const input of view.inputs) {
      const r = await response("/workflow-runs/" + input.run_id, () =>
        selected
          .getByRole("button", {
            name: "Inspect downstream run for " + input.source_name,
            exact: true,
          })
          .click(),
      );
      assert.deepEqual(
        r.run.execution_plan,
        previews.find((p) => p.source.id === input.file_id).execution_plan,
      );
      if (routingAuthorization) {
        assert.equal(r.run.routing_authorization_id, routingAuthorization.id);
        assert.equal(r.run.workflow_version, c.routing_target.version);
        assert.equal(r.run.workflow_hash, c.routing_target.definition_hash);
      }
      runs.push(r);
      if (r.observed_state === "kept_local") {
        await audit("routing-local-outcome");
        assert.equal(
          await region
            .getByRole("button", {
              name: "Review working next transfer step",
              exact: true,
            })
            .count(),
          0,
        );
      }
    }
    await page.reload();
    await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
    await open();
    await inspect(c.job.id);
    const input = view.inputs[0],
      reloaded = await response("/workflow-runs/" + input.run_id, () =>
        selected
          .getByRole("button", {
            name: "Inspect downstream run for " + input.source_name,
            exact: true,
          })
          .click(),
      );
    assert.deepEqual(reloaded.run.execution_plan, runs[0].run.execution_plan);
    assert.deepEqual(await contacts(), before);
    result = { view, runs, previews, routingAuthorization };
    record("routing-original-manifest-plan-after-browser-reload");
  } else if (c.routing_phase.startsWith("send-")) {
    const view = await inspect(c.job.id),
      input = view.inputs.find((i) => i.file_id === c.target_file_id);
    assert.ok(input, "the independently reviewed input must still exist");
    const runID =
      view.replacements?.find((r) => r.input_id === input.id)?.current_run_id ??
      input.run_id;
    let status = await response("/workflow-runs/" + runID, () =>
      selected
        .getByRole("button", {
          name: "Inspect downstream run for " + input.source_name,
          exact: true,
        })
        .click(),
    );
    const index = status.steps.findIndex((s) => s.id === c.target_step);
    assert.ok(index >= 0);
    assert.ok(
      status.steps.slice(0, index).every((s) => s.state === "succeeded"),
    );
    await region
      .getByRole("button", {
        name: "Review working next transfer step",
        exact: true,
      })
      .click();
    if (c.audit_send) await audit("routing-selected-send-review");
    const sent = await loss("/workflow-runs/" + runID + "/work", "send");
    status = sent.status;
    assert.equal(sent.dispatch.step_id, c.target_step);
    assert.equal(status.steps[index].state, "succeeded");
    assert.equal(
      status.observed_state,
      index === status.steps.length - 1 ? "succeeded" : "running",
    );
    assert.equal(new Set(responses.map((r) => r.idempotency_key)).size, 1);
    result = { view, runs: [status] };
    record("routing-independently-approved-ordinary-browser-send");
  } else throw new Error("unsupported routing phase");
  await writeFile(
    c.raw + "/routing-browser-result.json",
    JSON.stringify({ state: "passed", ...result, responses }, null, 2) + "\n",
  );
}
