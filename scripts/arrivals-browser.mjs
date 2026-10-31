import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
export async function qualifyArrivals(page, c, audit, record, actual) {
  const prefix = c.url + `/v1/tenants/${c.tenant}/partners/${c.partner}`;
  const region = page.getByRole("region", {
    name: "Workflow schedules",
    exact: true,
  });
  const contacts = async () =>
    Promise.all(
      [c.source_log, c.receiver_log].map(
        async (p) =>
          (await readFile(p, "utf8")).split("Accepted publickey for ").length -
          1,
      ),
    );
  const before = await contacts(),
    responses = [];
  const confirm = () =>
    page
      .getByRole("button", { name: "Confirm exact decision", exact: true })
      .click();
  async function loss(route, label, failure) {
    const target = prefix + route,
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
    await page.getByText(failure).waitFor();
    await confirm();
    await page.locator("dialog[open]").waitFor({ state: "hidden" });
    assert.equal(seen.length, 2);
    assert.ok(seen[0].idempotency_key);
    assert.equal(seen[0].idempotency_key, seen[1].idempotency_key);
    assert.deepEqual(seen[0].selection, seen[1].selection);
    assert.deepEqual(
      JSON.parse(seen[0].body).resource,
      JSON.parse(seen[1].body).resource,
    );
    assert.equal(JSON.parse(seen[1].body).replayed, true);
    responses.push(...seen);
    await page.unroute(target);
    return JSON.parse(seen[1].body).resource;
  }
  async function open() {
    await page.getByRole("button", { name: "Schedules", exact: true }).click();
    await region
      .getByRole("heading", { name: "Workflow schedules", exact: true })
      .waitFor();
  }
  await open();
  await region
    .getByLabel("Schedule name", { exact: true })
    .fill("Browser arrival review");
  await region
    .getByLabel("Approved workflow", { exact: true })
    .selectOption(c.workflow.id + ":" + c.workflow.version);
  assert.equal(
    await region
      .getByLabel("Approved collection target folder", { exact: true })
      .inputValue(),
    c.source.target_directory,
  );
  assert.equal(
    await region.getByLabel("Filename pattern", { exact: true }).inputValue(),
    c.source.manifest,
  );
  assert.equal(
    await region
      .getByLabel("Filename pattern", { exact: true })
      .getAttribute("readonly"),
    "",
  );
  await region
    .getByLabel("Late after due time (seconds)", { exact: true })
    .fill("2");
  await region
    .getByLabel("Arrival cutoff after due time (seconds)", { exact: true })
    .fill("30");
  await region
    .getByLabel("Minimum time between source probes (seconds)", { exact: true })
    .fill("1");
  await region
    .getByLabel("Execution cutoff after due time (seconds)", { exact: true })
    .fill("120");
  await region
    .getByRole("button", { name: "Preview schedule", exact: true })
    .click();
  await region
    .getByRole("heading", { name: "Review schedule preview", exact: true })
    .waitFor();
  await audit("arrival-calendar-preview");
  await region
    .getByRole("button", { name: "Review saving schedule draft", exact: true })
    .click();
  await audit("arrival-calendar-draft-review");
  await loss(
    "/workflow-schedules/drafts",
    "browser-arrival-calendar-draft",
    /^Schedule decision not confirmed/,
  );
  assert.deepEqual(await contacts(), before);
  record(
    "scheduled-source-calendar-review-and-original-key-draft-replay-no-source-contact",
  );
  async function inspect() {
    await region
      .getByRole("button", {
        name: `Inspect schedule ${c.schedule.name} version ${c.schedule.version}`,
        exact: true,
      })
      .click();
    await region
      .getByRole("button", {
        name: "Inspect occurrence " + c.occurrence.id.slice(0, 8),
        exact: true,
      })
      .click();
    await page
      .getByRole("heading", { name: "Expected arrival: ready", exact: true })
      .waitFor();
  }
  await inspect();
  await audit("arrival-ready-frozen");
  const arrival = page.getByRole("region", {
    name: "Expected scheduled arrival",
    exact: true,
  });
  await arrival
    .getByRole("button", { name: "Review collection admission", exact: true })
    .click();
  await audit("arrival-admission-review");
  const admitted = await loss(
    "/workflow-schedule-arrivals/" + c.occurrence.id + "/admit",
    "browser-arrival-admit",
    /^Decision not confirmed/,
  );
  assert.equal(admitted.state, "admitted");
  assert.deepEqual(await contacts(), before);
  record(
    "frozen-ready-browser-admission-response-loss-uses-original-operation-key-without-source-contact",
  );
  const selected = page.getByRole("region", {
    name: "Selected collection",
    exact: true,
  });
  await selected
    .getByRole("heading", { name: "Collection: queued", exact: true })
    .waitFor();
  await selected
    .getByRole("button", { name: "Review reading source batch", exact: true })
    .click();
  await audit("arrival-ordinary-collection-review");
  const captured = await loss(
    "/workflow-collections/" + admitted.collection_id + "/work",
    "browser-arrival-collect",
    /^The result was not confirmed/,
  );
  assert.equal(captured.state, "captured");
  await selected
    .getByRole("heading", { name: "Collection: captured", exact: true })
    .waitFor();
  await audit("arrival-ordinary-captured");
  const after = await contacts();
  assert.equal(after[0], before[0] + 1);
  assert.equal(after[1], before[1]);
  record(
    "ordinary-browser-collection-captures-frozen-snapshot-after-producer-manifest-removal-and-original-key-replay",
  );
  await page.reload();
  await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
  await open();
  await region
    .getByRole("button", {
      name: `Inspect schedule ${c.schedule.name} version ${c.schedule.version}`,
      exact: true,
    })
    .click();
  await region
    .getByRole("button", {
      name: "Inspect occurrence " + c.occurrence.id.slice(0, 8),
      exact: true,
    })
    .click();
  await selected
    .getByRole("heading", { name: "Collection: captured", exact: true })
    .waitFor();
  assert.deepEqual(await contacts(), after);
  record(
    "browser-reload-keeps-scheduled-arrival-and-ordinary-custody-without-source-contact",
  );
  await writeFile(
    c.raw + "/arrival-browser-responses.json",
    JSON.stringify(responses, null, 2) + "\n",
  );
}
