import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
export async function qualifyProductionReleases(
  page,
  c,
  audit,
  record,
  actual,
  openPlan,
) {
  const section = page.getByRole("region", {
      name: "Onboarding production releases",
    }),
    prefix = c.url + `/v1/tenants/${c.tenant}/partners/${c.partner}`,
    responses = [];
  const button = (name) => section.getByRole("button", { name, exact: true });
  const state = async (value) => {
    const h = section.getByRole("heading", {
      name: "Onboarding release: " + value,
      exact: true,
    });
    await h.waitFor();
    assert.equal(await h.evaluate((el) => el === document.activeElement), true);
  };
  async function loss(target, label, action) {
    const seen = [];
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
    await action();
    await page.getByText(/The saved result is not confirmed/).waitFor();
    await action();
    await page.locator("dialog[open]").waitFor({ state: "hidden" });
    assert.equal(seen.length, 2);
    assert.ok(seen[0].idempotency_key);
    assert.equal(seen[0].idempotency_key, seen[1].idempotency_key);
    assert.deepEqual(seen[0].selection, seen[1].selection);
    assert.equal(JSON.parse(seen[0].body).replayed, false);
    assert.equal(JSON.parse(seen[1].body).replayed, true);
    assert.deepEqual(
      JSON.parse(seen[0].body).resource,
      JSON.parse(seen[1].body).resource,
    );
    await page.unroute(target);
    responses.push(...seen);
    return JSON.parse(seen[1].body).resource;
  }
  await section
    .getByLabel("Completed pre-contact test UUIDs", { exact: true })
    .fill(c.release_selection.test_ids.join("\n"));
  await button("Preview release proposal").click();
  const title = page.getByRole("heading", {
    name: "Review release proposal",
    exact: true,
  });
  await title.waitFor();
  assert.equal(
    await title.evaluate((el) => el === document.activeElement),
    true,
  );
  await audit("release-proposal-review");
  const proposed = await loss(
    prefix + "/onboarding-releases",
    "browser-release-propose",
    () =>
      page
        .getByRole("button", { name: "Save release proposal", exact: true })
        .click(),
  );
  await state("proposed");
  const release = proposed.release;
  assert.equal(await button("Activate release").isDisabled(), true);
  record("proposal-response-loss-recovers-one-immutable-release");
  await button("Approve release").click();
  await page
    .getByRole("heading", { name: "Review approve release", exact: true })
    .waitFor();
  await audit("release-approval-review");
  await loss(
    prefix + "/onboarding-releases/" + release.id + "/approve",
    "browser-release-approve",
    () =>
      page
        .getByRole("button", { name: "Confirm approve release", exact: true })
        .click(),
  );
  await state("approved");
  assert.equal(
    await section
      .getByRole("heading", {
        name: "Prepare a production dispatch",
        exact: true,
      })
      .count(),
    0,
  );
  record("approval-response-loss-preserves-exact-revision-without-activation");
  async function decide(action, next) {
    await button(
      action.charAt(0).toUpperCase() + action.slice(1) + " release",
    ).click();
    await page
      .getByRole("heading", {
        name: "Review " + action + " release",
        exact: true,
      })
      .waitFor();
    await page
      .getByRole("button", {
        name: "Confirm " + action + " release",
        exact: true,
      })
      .click();
    await state(next);
  }
  await decide("activate", "active");
  await audit("release-active");
  async function prepare() {
    await section
      .getByLabel("Active release requirement", { exact: true })
      .selectOption(c.plan.definition.requirements[0].id);
    await section
      .getByLabel("Accepted production file UUID", { exact: true })
      .fill(c.production_file);
    await button("Preview production dispatch").click();
    await page
      .getByRole("heading", { name: "Review production dispatch", exact: true })
      .waitFor();
  }
  await prepare();
  await audit("production-dispatch-review");
  const queued = await loss(
    prefix + "/onboarding-production",
    "browser-production-queue",
    () =>
      page
        .getByRole("button", {
          name: "Queue reviewed production run",
          exact: true,
        })
        .click(),
  );
  const stale = queued.dispatch;
  await section
    .getByRole("heading", { name: "Production run: queued", exact: true })
    .waitFor();
  record("production-save-response-loss-preserves-one-precontact-run");
  await decide("suspend", "suspended");
  await button("Inspect current production run").click();
  await section
    .getByRole("heading", { name: "Production run: attention", exact: true })
    .waitFor();
  assert.equal(await button("Execute production run").isDisabled(), true);
  await audit("release-suspended");
  await decide("activate", "active");
  await button("Inspect current production run").click();
  await section
    .getByRole("heading", { name: "Production run: attention", exact: true })
    .waitFor();
  assert.equal(await button("Execute production run").isDisabled(), true);
  record("suspension-and-new-activation-do-not-revive-old-queued-epoch");
  await prepare();
  let created;
  const productionTarget = prefix + "/onboarding-production";
  await page.route(productionTarget, async (route) => {
    const response = await actual(
      route,
      "browser-production-fresh-epoch",
      productionTarget,
    );
    created = JSON.parse(response.body);
    await route.fulfill({
      status: response.status,
      contentType: "application/json",
      body: response.body,
    });
  });
  await page
    .getByRole("button", { name: "Queue reviewed production run", exact: true })
    .click();
  await section
    .getByRole("heading", { name: "Production run: queued", exact: true })
    .waitFor();
  assert.ok(created?.resource?.dispatch);
  const production = created.resource.dispatch;
  await page.unroute(productionTarget);
  await page.reload();
  await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
  await openPlan();
  await button("Inspect release " + release.id.slice(0, 8)).click();
  await state("active");
  await button("Inspect production " + production.id.slice(0, 8)).click();
  await section
    .getByRole("heading", { name: "Production run: queued", exact: true })
    .waitFor();
  const workTarget = prefix + "/workflow-runs/" + production.id + "/work";
  let completed;
  await page.route(workTarget, async (route) => {
    completed = await actual(
      route,
      "browser-production-completed-work",
      workTarget,
    );
    await route.abort("failed");
  });
  await button("Execute production run").click();
  await page.getByText(/Execution is not confirmed/).waitFor();
  assert.equal(JSON.parse(completed.body).status.observed_state, "succeeded");
  await page.unroute(workTarget);
  await button("Inspect current production run").click();
  const done = section.getByRole("heading", {
    name: "Production run: succeeded",
    exact: true,
  });
  await done.waitFor();
  assert.equal(
    await done.evaluate((el) => el === document.activeElement),
    true,
  );
  assert.equal(await button("Execute production run").isDisabled(), true);
  await audit("production-completed");
  record(
    "private-reload-and-lost-completed-work-response-recover-exact-production-receipt",
  );
  await writeFile(
    c.raw + "/onboarding-release-browser-result.json",
    JSON.stringify(
      {
        state: "passed",
        release: { ...release, state: "active", revision: 5 },
        stale,
        production,
        work_key: completed.idempotency_key,
      },
      null,
      2,
    ) + "\n",
  );
}
