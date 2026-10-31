import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile, readdir, writeFile } from "node:fs/promises";
export async function qualifyQueuedHandoffs(
  page,
  c,
  audit,
  record,
  actual,
  openPlan,
) {
  const section = page.getByRole("region", {
      name: "Queued production handoffs",
    }),
    prefix = c.url + `/v1/tenants/${c.tenant}/partners/${c.partner}`,
    selection = c.handoff_selection;
  const button = (name) => section.getByRole("button", { name, exact: true });
  async function noContact() {
    const log = await readFile(c.raw + "/receiver.log", "utf8");
    assert.equal(
      log.split("Accepted publickey for ").length - 1,
      c.handoff_contacts_before,
    );
    assert.deepEqual(
      (await readdir(c.private + "/inbox")).sort(),
      c.handoff_files_before,
    );
  }
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
    await page.getByText(/The handoff result is not confirmed/).waitFor();
    await action();
    await page.locator("dialog[open]").waitFor({ state: "hidden" });
    assert.equal(seen.length, 2);
    assert.ok(seen[0].idempotency_key);
    assert.equal(seen[0].idempotency_key, seen[1].idempotency_key);
    assert.deepEqual(seen[0].selection, seen[1].selection);
    const first = JSON.parse(seen[0].body),
      second = JSON.parse(seen[1].body);
    assert.equal(first.replayed, false);
    assert.equal(second.replayed, true);
    assert.deepEqual(first.resource, second.resource);
    await page.unroute(target);
    return second.resource.handoff;
  }
  async function state(name) {
    const h = section.getByRole("heading", {
      name: "Queued handoff: " + name,
      exact: true,
    });
    await h.waitFor();
    assert.equal(await h.evaluate((el) => el === document.activeElement), true);
  }
  await section
    .getByLabel("Original production run UUID", { exact: true })
    .fill(selection.source_run_id);
  await section
    .getByLabel("Original production definition SHA-256", { exact: true })
    .fill(selection.source_hash);
  await section
    .getByLabel("Tested target release UUID", { exact: true })
    .fill(selection.target_release.id);
  await section
    .getByLabel("Target activation revision", { exact: true })
    .fill(String(selection.target_release.revision));
  await section
    .getByLabel("Target release SHA-256", { exact: true })
    .fill(selection.target_release.hash);
  await section
    .getByLabel("Accepted replacement file UUID", { exact: true })
    .fill(selection.file_id);
  await button("Preview queued handoff").click();
  const title = page.getByRole("heading", {
    name: "Review queued handoff",
    exact: true,
  });
  await title.waitFor();
  assert.equal(
    await title.evaluate((el) => el === document.activeElement),
    true,
  );
  await page.getByText(c.handoff_hash, { exact: true }).waitFor();
  await page.getByText(c.new_recipient, { exact: true }).waitFor();
  await noContact();
  await audit("handoff-review");
  let h = await loss(
    prefix + "/onboarding-handoffs",
    "browser-handoff-proposal",
    () =>
      page
        .getByRole("button", { name: "Save reviewed handoff", exact: true })
        .click(),
  );
  await state("proposed");
  assert.equal(await button("Execute approved handoff").isDisabled(), true);
  record("handoff-original-key-save-response-recovery");
  await button("Approve handoff").click();
  await page
    .getByRole("heading", { name: "Review approve handoff", exact: true })
    .waitFor();
  await audit("handoff-approval");
  h = await loss(
    prefix + "/onboarding-handoffs/" + h.id + "/approve",
    "browser-handoff-approval",
    () =>
      page
        .getByRole("button", { name: "Confirm approve handoff", exact: true })
        .click(),
  );
  await state("approved");
  await noContact();
  await button("Execute approved handoff").click();
  await page
    .getByRole("heading", { name: "Review execute handoff", exact: true })
    .waitFor();
  await audit("handoff-execution-review");
  h = await loss(
    prefix + "/onboarding-handoffs/" + h.id + "/execute",
    "browser-handoff-completion",
    () =>
      page
        .getByRole("button", { name: "Confirm execute handoff", exact: true })
        .click(),
  );
  await state("completed");
  assert.ok(h.replacement_run_id);
  assert.notEqual(h.replacement_run_id, selection.source_run_id);
  await noContact();
  for (const id of [h.id, selection.source_run_id, h.replacement_run_id])
    assert.match(id, /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/);
  const atomicQuery =
    "SELECT count(DISTINCT xmin::text) FROM (SELECT xmin FROM onboarding_handoffs WHERE handoff_id='" +
    h.id +
    "' UNION ALL SELECT xmin FROM workflow_runs WHERE run_id IN ('" +
    selection.source_run_id +
    "','" +
    h.replacement_run_id +
    "') UNION ALL SELECT xmin FROM delivery_intents WHERE delivery_id IN (SELECT delivery_id FROM workflow_steps WHERE run_id IN ('" +
    selection.source_run_id +
    "','" +
    h.replacement_run_id +
    "'))) committed";
  const transactions = Number(
    execFileSync(
      "docker",
      [
        "exec",
        c.postgres_container_id,
        "psql",
        "-X",
        "-At",
        "-v",
        "ON_ERROR_STOP=1",
        "-U",
        "postgres",
        "-d",
        c.database,
        "-c",
        atomicQuery,
      ],
      { encoding: "utf8", timeout: 15000, maxBuffer: 4096 },
    ).trim(),
  );
  assert.equal(transactions, 1);
  await writeFile(
    c.raw + "/handoff-atomic-before-transfer.json",
    JSON.stringify(
      {
        distinct_transactions: transactions,
        source_run_id: selection.source_run_id,
        replacement_run_id: h.replacement_run_id,
        handoff_id: h.id,
      },
      null,
      2,
    ) + "\n",
  );
  record(
    "approved-handoff-atomically-preserves-original-and-one-successor-without-contact",
  );
  await page.reload();
  await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
  await openPlan();
  await button("Inspect handoff " + h.id.slice(0, 8)).click();
  await state("completed");
  await button("Inspect replacement run").click();
  const queued = section.getByRole("heading", {
    name: "Replacement run: queued",
    exact: true,
  });
  await queued.waitFor();
  assert.equal(
    await queued.evaluate((el) => el === document.activeElement),
    true,
  );
  await noContact();
  await audit("handoff-reloaded-successor");
  const target = prefix + "/workflow-runs/" + h.replacement_run_id + "/work";
  let completed;
  await page.route(target, async (route) => {
    completed = await actual(route, "browser-handoff-successor-work", target);
    await route.abort("failed");
  });
  await button("Execute replacement transfer").click();
  await page.getByText(/Transfer outcome is not confirmed/).waitFor();
  assert.equal(JSON.parse(completed.body).status.observed_state, "succeeded");
  await page.unroute(target);
  await button("Inspect replacement run").click();
  const done = section.getByRole("heading", {
    name: "Replacement run: succeeded",
    exact: true,
  });
  await done.waitFor();
  assert.equal(
    await done.evaluate((el) => el === document.activeElement),
    true,
  );
  assert.equal(await button("Execute replacement transfer").isDisabled(), true);
  await audit("handoff-successor-completed");
  record(
    "private-reload-and-lost-transfer-response-preserve-exact-successor-receipt",
  );
  await writeFile(
    c.raw + "/onboarding-handoff-browser-result.json",
    JSON.stringify(
      {
        state: "passed",
        handoff: h,
        work_key: completed.idempotency_key,
        model_started: false,
      },
      null,
      2,
    ) + "\n",
  );
}
