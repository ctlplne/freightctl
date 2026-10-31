import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";

// This driver uses real HTTPS and stock SSH peers. Response interception only
// drops the first real committed response; the retry reaches the server again.
export async function qualifyCollections(page, c, audit, record, actual) {
  const prefix = c.url + `/v1/tenants/${c.tenant}/partners/${c.partner}`;
  const region = page.getByRole("region", {
    name: "Collection workflows",
    exact: true,
  });
  const selected = page.getByRole("region", {
    name: "Selected collection",
    exact: true,
  });
  const confirm = () =>
    page
      .getByRole("button", { name: "Confirm exact decision", exact: true })
      .click();
  const contacts = async () =>
    Promise.all(
      [c.source_log, c.receiver_log].map(
        async (p) =>
          (await readFile(p, "utf8")).split("Accepted publickey for ").length -
          1,
      ),
    );
  const responses = [];
  async function open() {
    await page
      .getByRole("button", { name: "Collections", exact: true })
      .click();
    await region
      .getByRole("heading", {
        name: "Collection workflows",
        level: 2,
        exact: true,
      })
      .waitFor();
  }
  async function response(route, action) {
    const [body] = await Promise.all([
      page
        .waitForResponse(
          (r) => r.url() === prefix + route && r.status() === 200,
        )
        .then((r) => r.json()),
      action(),
    ]);
    return body;
  }
  async function inspect(id) {
    return response("/workflow-collections/" + id, () =>
      region
        .getByRole("button", { name: "Inspect collection " + id, exact: true })
        .click(),
    );
  }
  async function loss(route, label) {
    const target = prefix + route,
      seen = [];
    await page.route(target, async (intercepted) => {
      const r = await actual(intercepted, label + "-" + seen.length, target);
      seen.push(r);
      if (seen.length === 1) await intercepted.abort("failed");
      else
        await intercepted.fulfill({
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
    record(label + "-lost-response-original-key-replay");
    return second.resource ?? second;
  }
  await open();
  let result = {};
  if (c.collection_phase === "create" || c.collection_phase === "revise") {
    const before = await contacts(),
      revising = c.collection_phase === "revise";
    if (revising) {
      await region
        .getByLabel("Saved collection workflow", { exact: true })
        .selectOption(c.workflow.id + ":" + c.workflow.version);
      await region
        .getByRole("heading", {
          name: c.workflow.definition.name + ": approved",
          exact: true,
        })
        .waitFor();
      await region
        .getByRole("button", {
          name: "Prepare next workflow revision",
          exact: true,
        })
        .click();
    }
    const fields = {
      "Collection workflow name": revising
        ? "Reviewed browser collection v2"
        : "Reviewed browser collection",
      "Ready manifest filename": "browser.ready.json",
      "Virtual local target folder": "/browser-incoming",
      "Maximum files per batch": "4",
      "Maximum bytes per file": "1048576",
      "Maximum bytes per batch": "2097152",
    };
    for (const [label, value] of Object.entries(fields))
      await region.getByLabel(label, { exact: true }).fill(value);
    await region
      .getByLabel("Registered source connection", { exact: true })
      .selectOption(c.source.id + ":" + c.source.version);
    if (!revising)
      for (let i = 0; i < 2; i++) {
        await region
          .getByRole("button", { name: "Add transfer step", exact: true })
          .click();
        await region
          .getByLabel(`Step ${i + 1} ID`, { exact: true })
          .fill("browser_" + (i + 1));
        await region
          .getByLabel(`Step ${i + 1} receiver`, { exact: true })
          .selectOption(c.destination.id + ":" + c.destination.version);
        await region
          .getByLabel(`Step ${i + 1} filename`, { exact: true })
          .fill("browser-" + (i + 1) + ".csv");
      }
    if (revising)
      await region
        .getByLabel("Step 2 filename", { exact: true })
        .fill("browser-v2.csv");
    await audit("collection-" + c.collection_phase + "-form");
    const preview = await response("/workflows/validate", () =>
      region
        .getByRole("button", {
          name: "Preview workflow definition",
          exact: true,
        })
        .click(),
    );
    assert.equal(preview.external_contact, false);
    assert.equal(preview.effects.length, 2);
    assert.equal(preview.definition.source.connection.id, c.source.id);
    await region
      .getByRole("button", {
        name: "Review saving workflow draft",
        exact: true,
      })
      .click();
    await audit("collection-" + c.collection_phase + "-draft-review");
    let workflow = await loss(
      "/workflows/drafts",
      "collection-" + c.collection_phase + "-draft",
    );
    assert.equal(workflow.version, revising ? 2 : 1);
    // A saved draft must be recoverable after the browser loses its local state.
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
    await audit("collection-" + c.collection_phase + "-approval-review");
    workflow = await loss(
      "/workflows/" + workflow.id + "/" + workflow.version + "/approve",
      "collection-" + c.collection_phase + "-approve",
    );
    await region
      .getByLabel("Collection and sending cutoff from queue time (seconds)", {
        exact: true,
      })
      .fill("300");
    const jobPreview = await response("/workflow-collections/preview", () =>
      region
        .getByRole("button", { name: "Preview collection job", exact: true })
        .click(),
    );
    assert.equal(jobPreview.external_contact, false);
    await region
      .getByRole("button", { name: "Review queueing collection", exact: true })
      .click();
    await audit("collection-" + c.collection_phase + "-queue-review");
    const job = await loss(
      "/workflow-collections",
      "collection-" + c.collection_phase + "-queue",
    );
    assert.equal(job.state, "queued");
    assert.deepEqual(await contacts(), before);
    result = { workflow, job };
    record(
      "collection-" + c.collection_phase + "-metadata-only-no-peer-contact",
    );
  } else if (c.collection_phase === "work" || c.collection_phase === "dedupe") {
    const before = await contacts(),
      dedupe = c.collection_phase === "dedupe";
    await inspect(c.job.id);
    await selected
      .getByRole("button", { name: "Review reading source batch", exact: true })
      .click();
    await audit("collection-" + c.collection_phase + "-input-review");
    const work = await loss(
      "/workflow-collections/" + c.job.id + "/work",
      "collection-" + c.collection_phase + "-input",
    );
    assert.equal(work.state, "captured");
    let view = await response("/workflow-collections/" + c.job.id, () =>
      selected
        .getByRole("button", {
          name: "Refresh selected collection",
          exact: true,
        })
        .click(),
    );
    assert.ok(view.job.captured);
    assert.equal(view.inputs.length, 2);
    assert.ok(view.local_states.every((s) => s.state === "published"));
    assert.deepEqual(await contacts(), [before[0] + 1, before[1]]);
    await selected
      .getByRole("button", {
        name: "Review queueing downstream work",
        exact: true,
      })
      .click();
    await audit("collection-" + c.collection_phase + "-downstream-review");
    await loss(
      "/workflow-collections/" + c.job.id + "/refresh",
      "collection-" + c.collection_phase + "-admit",
    );
    view = await response("/workflow-collections/" + c.job.id, () =>
      selected
        .getByRole("button", {
          name: "Refresh selected collection",
          exact: true,
        })
        .click(),
    );
    assert.deepEqual(await contacts(), [before[0] + 1, before[1]]);
    assert.ok(view.inputs.every((i) => i.run_id));
    const runs = [];
    for (const [index, input] of view.inputs.entries()) {
      const run = await response("/workflow-runs/" + input.run_id, () =>
        selected
          .getByRole("button", {
            name: "Inspect downstream run for " + input.source_name,
            exact: true,
          })
          .click(),
      );
      if (dedupe) {
        assert.equal(run.observed_state, "succeeded");
        assert.notEqual(input.first_job_id, c.job.id);
        runs.push(run);
        continue;
      }
      const runRegion = page.getByRole("region", {
        name: "Collected input downstream run",
        exact: true,
      });
      for (let step = 0; step < 2; step++) {
        await runRegion
          .getByRole("button", {
            name: "Review working next transfer step",
            exact: true,
          })
          .click();
        if (index === 0 && step === 0) await audit("collection-send-review");
        await loss(
          "/workflow-runs/" + input.run_id + "/work",
          `collection-input-${index}-step-${step}`,
        );
      }
      const done = await response("/workflow-runs/" + input.run_id, () =>
        runRegion
          .getByRole("button", { name: "Refresh downstream run", exact: true })
          .click(),
      );
      assert.equal(done.observed_state, "succeeded");
      assert.ok(done.steps.every((s) => s.state === "succeeded"));
      runs.push(done);
    }
    await audit("collection-" + c.collection_phase + "-receipts");
    if (dedupe) {
      assert.deepEqual(await contacts(), [before[0] + 1, before[1]]);
      await selected
        .getByRole("button", {
          name: "Review stopping collection job",
          exact: true,
        })
        .click();
      await loss(
        "/workflow-collections/" + c.job.id + "/cancel",
        "collection-stop",
      );
      view = await response("/workflow-collections/" + c.job.id, () =>
        selected
          .getByRole("button", {
            name: "Refresh selected collection",
            exact: true,
          })
          .click(),
      );
      assert.equal(view.job.state, "cancelled");
      assert.ok(view.job.captured);
      assert.ok(view.local_states.every((s) => s.state === "published"));
      record(
        "new-workflow-version-and-producer-batch-do-not-rebind-or-resend-prior-inputs",
      );
    }
    result = { view, runs };
  } else throw new Error("unknown collection browser phase");
  await writeFile(
    c.raw + "/collection-browser-result.json",
    JSON.stringify({ ...result, responses }, null, 2) + "\n",
  );
}
