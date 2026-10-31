import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, readdir, writeFile } from "node:fs/promises";

export async function qualifyReceiptObservations(
  page,
  c,
  audit,
  record,
  actual,
  openPlan,
) {
  const section = page.getByRole("region", {
      name: "Read-only receipt observations",
    }),
    prefix = c.url + `/v1/tenants/${c.tenant}/partners/${c.partner}`,
    selection = c.observation_selection;
  const button = (name) => section.getByRole("button", { name, exact: true });
  async function contacts() {
    return (
      (await readFile(c.receiver_log, "utf8")).split("Accepted publickey for ")
        .length - 1
    );
  }
  async function unchanged() {
    const files = {};
    for (const name of (await readdir(c.private + "/inbox")).sort()) {
      files[name] = createHash("sha256")
        .update(await readFile(c.private + "/inbox/" + name))
        .digest("hex");
    }
    assert.deepEqual(files, c.observation_files_before);
  }
  async function noContact() {
    assert.equal(await contacts(), c.observation_contacts_before);
    await unchanged();
  }
  async function state(name) {
    const h = section.getByRole("heading", {
      name: "Receipt observation: " + name,
      exact: true,
    });
    await h.waitFor();
    assert.equal(await h.evaluate((el) => el === document.activeElement), true);
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
    await page
      .getByText(/The receipt observation result is not confirmed/)
      .waitFor();
    await action();
    await page.locator("dialog[open]").waitFor({ state: "hidden" });
    assert.equal(seen.length, 2);
    assert.ok(seen[0].idempotency_key);
    assert.equal(seen[0].idempotency_key, seen[1].idempotency_key);
    assert.deepEqual(seen[0].selection, seen[1].selection);
    await page.unroute(target);
    return seen;
  }
  for (const [label, value] of [
    ["Published production run UUID", selection.source_run_id],
    ["Original production definition SHA-256", selection.source_hash],
    ["Current successful probe UUID", selection.probe_id],
    ["Authorized same-byte file UUID", selection.file_id],
  ])
    await section.getByLabel(label, { exact: true }).fill(value);
  await button("Preview receipt observation").click();
  const title = page.getByRole("heading", {
    name: "Review receipt observation",
    exact: true,
  });
  await title.waitFor();
  assert.equal(
    await title.evaluate((el) => el === document.activeElement),
    true,
  );
  for (const text of [
    c.observation_hash,
    c.observation_path,
    c.observation_wire.sha256,
    c.observer_host,
    c.original_recipient,
  ])
    await page.getByText(text, { exact: true }).waitFor();
  await noContact();
  await audit("receipt-observation-review");
  let seen = await loss(
    prefix + "/onboarding-observations",
    "browser-observation-propose",
    () =>
      page
        .getByRole("button", { name: "Save reviewed observation", exact: true })
        .click(),
  );
  let first = JSON.parse(seen[0].body),
    second = JSON.parse(seen[1].body);
  assert.equal(first.replayed, false);
  assert.equal(second.replayed, true);
  assert.deepEqual(first.resource, second.resource);
  let observation = second.resource.observation;
  await state("proposed");
  assert.equal(await button("Review read-only observation").isDisabled(), true);
  await noContact();
  record(
    "lost-receipt-observation-proposal-recovers-original-key-without-contact",
  );
  await button("Approve receipt observation").click();
  await page
    .getByRole("heading", {
      name: "Review approve receipt observation",
      exact: true,
    })
    .waitFor();
  await audit("receipt-observation-approval");
  seen = await loss(
    prefix + "/onboarding-observations/" + observation.id + "/approve",
    "browser-observation-approve",
    () =>
      page
        .getByRole("button", {
          name: "Confirm approve receipt observation",
          exact: true,
        })
        .click(),
  );
  first = JSON.parse(seen[0].body);
  second = JSON.parse(seen[1].body);
  assert.equal(first.replayed, false);
  assert.equal(second.replayed, true);
  assert.deepEqual(first.resource, second.resource);
  observation = second.resource.observation;
  await state("approved");
  await noContact();
  await button("Review read-only observation").click();
  await page
    .getByRole("heading", {
      name: "Review read-only receiver contact",
      exact: true,
    })
    .waitFor();
  await audit("receipt-observation-contact-review");
  await noContact();
  seen = await loss(
    prefix + "/onboarding-observations/" + observation.id + "/work",
    "browser-observation-work",
    () =>
      page
        .getByRole("button", {
          name: "Confirm read-only observation",
          exact: true,
        })
        .click(),
  );
  first = JSON.parse(seen[0].body);
  second = JSON.parse(seen[1].body);
  assert.equal(first.contact_attempted, true);
  assert.equal(second.contact_attempted, false);
  assert.deepEqual(first.observation, second.observation);
  assert.equal(second.observation.result.integrity_confirmed, true);
  assert.equal(second.observation.result.sha256, c.observation_wire.sha256);
  assert.equal(second.resend_authorized, false);
  observation = second.observation;
  await state("succeeded");
  assert.equal(await contacts(), c.observation_contacts_before + 1);
  await unchanged();
  await audit("receipt-observation-recovered");
  record(
    "lost-read-response-recovers-exact-receipt-with-one-read-only-contact-and-unchanged-files",
  );
  await page.reload();
  await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
  await openPlan();
  await button("Inspect observation " + observation.id.slice(0, 8)).click();
  await state("succeeded");
  await page.getByText(observation.result.sha256, { exact: true }).waitFor();
  assert.equal(await contacts(), c.observation_contacts_before + 1);
  await unchanged();
  await audit("receipt-observation-private-reload");
  const releases = page.getByRole("region", {
    name: "Onboarding production releases",
  });
  await releases
    .getByRole("button", {
      name: "Inspect release " + c.original_release.id.slice(0, 8),
      exact: true,
    })
    .click();
  await releases
    .getByRole("button", {
      name: "Inspect production " + selection.source_run_id.slice(0, 8),
      exact: true,
    })
    .click();
  await page.getByText(/Recovered integrity receipt/).waitFor();
  assert.ok((await releases.innerText()).includes(observation.id));
  assert.equal(
    await releases
      .getByRole("button", { name: "Execute production run", exact: true })
      .isDisabled(),
    true,
  );
  await audit("receipt-original-outcome");
  await unchanged();
  record(
    "original-production-outcome-joins-recovered-receipt-with-execution-still-blocked",
  );
  await writeFile(
    c.raw + "/onboarding-observation-browser-result.json",
    JSON.stringify(
      {
        state: "passed",
        observation,
        work_key: observation.worker_key,
        one_contact: true,
        files_unchanged: true,
        model_started: false,
      },
      null,
      2,
    ) + "\n",
  );
}
