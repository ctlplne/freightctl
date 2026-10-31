import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";

// Uses the same real HTTPS service and completed-response-loss relay as the
// read-only journey. No successful response or application state is invented.
export async function qualifyRecordedTests(
  page,
  c,
  audit,
  record,
  actual,
  openPlan,
) {
  const section = page.getByRole("region", {
    name: "Recorded onboarding test exchanges",
  });
  const r = c.test_selection;
  await section
    .getByLabel("Saved test requirement", { exact: true })
    .selectOption(r.requirement_id);
  await section
    .getByLabel("Successful probe UUID", { exact: true })
    .fill(r.probe_id);
  await section
    .getByLabel("Approved test workflow UUID", { exact: true })
    .fill(r.workflow.id);
  await section
    .getByLabel("Approved test workflow version", { exact: true })
    .fill(String(r.workflow.version));
  await section
    .getByLabel("Approved test workflow SHA-256", { exact: true })
    .fill(r.workflow.hash);
  await section
    .getByLabel("Accepted test file UUID", { exact: true })
    .fill(r.file_id);
  await section
    .getByRole("button", { name: "Preview test exchange", exact: true })
    .click();
  const heading = page.getByRole("heading", {
    name: "Review recorded test intent",
    exact: true,
  });
  await heading.waitFor();
  assert.equal(
    await heading.evaluate((el) => document.activeElement === el),
    true,
  );
  await audit("test-intent-review");
  const target =
    c.url + `/v1/tenants/${c.tenant}/partners/${c.partner}/onboarding-tests`;
  const responses = [];
  await page.route(target, async (route) => {
    const response = await actual(
      route,
      "browser-test-save-" + responses.length,
      target,
    );
    responses.push(response);
    if (responses.length === 1) await route.abort("failed");
    else
      await route.fulfill({
        status: response.status,
        contentType: "application/json",
        body: response.body,
      });
  });
  const save = page.getByRole("button", {
    name: "Save reviewed test intent",
    exact: true,
  });
  await save.click();
  await page.getByText(/The saved result is not confirmed/).waitFor();
  assert.equal(responses.length, 1);
  await save.click();
  const queued = section.getByRole("heading", {
    name: "Recorded test: queued",
    exact: true,
  });
  await queued.waitFor();
  assert.equal(responses.length, 2);
  assert.ok(responses[0].idempotency_key);
  assert.equal(responses[0].idempotency_key, responses[1].idempotency_key);
  assert.deepEqual(responses[0].selection, responses[1].selection);
  const first = JSON.parse(responses[0].body),
    second = JSON.parse(responses[1].body);
  assert.equal(first.replayed, false);
  assert.equal(second.replayed, true);
  assert.deepEqual(first.resource, second.resource);
  const test = second.resource.test;
  assert.equal(
    await queued.evaluate((el) => document.activeElement === el),
    true,
  );
  await page.unroute(target);
  record("test-save-response-loss-retries-original-key-and-one-run");
  await audit("test-queued");
  await page.reload();
  await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
  await openPlan();
  await section
    .getByRole("button", {
      name: "Inspect test " + test.id.slice(0, 8),
      exact: true,
    })
    .click();
  await queued.waitFor();
  await section
    .getByRole("button", {
      name: "Execute recorded test exchange",
      exact: true,
    })
    .click();
  const done = section.getByRole("heading", {
    name: "Recorded test: succeeded",
    exact: true,
  });
  await done.waitFor();
  assert.equal(
    await done.evaluate((el) => document.activeElement === el),
    true,
  );
  await audit("test-executed");
  assert.equal(
    await section
      .getByRole("button", {
        name: "Execute recorded test exchange",
        exact: true,
      })
      .isDisabled(),
    true,
  );
  record("reloaded-private-test-executes-separately-through-ordinary-worker");
  await writeFile(
    c.raw + "/onboarding-test-browser-result.json",
    JSON.stringify(
      { state: "passed", test, production_active: false },
      null,
      2,
    ) + "\n",
  );
}
