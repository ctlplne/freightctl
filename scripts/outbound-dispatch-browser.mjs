import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
export async function qualifyOutboundDispatch(page, c, audit, record, actual) {
  const prefix = c.url + `/v1/tenants/${c.tenant}/partners/${c.partner}`,
    region = page.getByRole("region", {
      name: "Outbound dispatch approvals",
    }),
    responses = [];
  const contacts = async () =>
    (await readFile(c.receiver_log, "utf8")).split("Accepted publickey for ")
      .length - 1;
  const before = await contacts();
  await page.getByRole("button", { name: "Approvals", exact: true }).click();
  await region
    .getByRole("heading", {
      name: "Outbound dispatch approvals",
      exact: true,
    })
    .waitFor();
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
    await region.getByText(/Dispatch decision not confirmed/).waitFor();
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
  let review;
  if (c.dispatch_phase.startsWith("request")) {
    await region
      .getByLabel("Outbound delivery ID", { exact: true })
      .fill(c.dispatch_delivery.id);
    await region
      .getByRole("button", { name: "Inspect outbound delivery", exact: true })
      .click();
    await region
      .getByRole("heading", { name: "Outbound delivery: queued", exact: true })
      .waitFor();
    await audit("dispatch-" + c.dispatch_phase + "-source");
    await region
      .getByLabel("Dispatch reviewer account ID", { exact: true })
      .fill(c.dispatch_reviewer_id);
    await region
      .getByRole("button", {
        name: "Preview dispatch review package",
        exact: true,
      })
      .click();
    const heading = page.getByRole("heading", {
      name: "Share exact dispatch metadata",
      exact: true,
    });
    await heading.waitFor();
    assert.equal(
      await heading.evaluate((el) => el === document.activeElement),
      true,
    );
    await audit("dispatch-" + c.dispatch_phase + "-disclosure");
    const result = await loss(
      prefix + "/outbound-dispatch-reviews",
      "browser-dispatch-" + c.dispatch_phase,
      () =>
        page
          .getByRole("button", { name: "Confirm exact decision", exact: true })
          .click(),
    );
    review = result.review;
    assert.equal(review.delivery_id, c.dispatch_delivery.id);
    assert.equal(review.reviewer_id, c.dispatch_reviewer_id);
    await region
      .getByRole("button", {
        name: "Inspect dispatch review " + review.id.slice(0, 8),
        exact: true,
      })
      .click();
    await region
      .getByRole("heading", { name: "Dispatch review: pending", exact: true })
      .waitFor();
    await audit("dispatch-" + c.dispatch_phase + "-history");
    await page.reload();
    await page.getByRole("button", { name: "Approvals", exact: true }).click();
    await region
      .getByRole("button", {
        name: "Inspect dispatch review " + review.id.slice(0, 8),
        exact: true,
      })
      .click();
    await region
      .getByRole("heading", { name: "Dispatch review: pending", exact: true })
      .waitFor();
    record(
      "dispatch-" +
        c.dispatch_phase +
        "-lost-response-exact-key-private-reload",
    );
  } else {
    const source = c.dispatch_review;
    await region
      .getByRole("button", {
        name: "Inspect dispatch review " + source.id.slice(0, 8),
        exact: true,
      })
      .click();
    const state = c.dispatch_phase === "withdraw" ? "approved" : "pending";
    const title = region.getByRole("heading", {
      name: "Dispatch review: " + state,
      exact: true,
    });
    await title.waitFor();
    assert.equal(
      await title.evaluate((el) => el === document.activeElement),
      true,
    );
    assert.equal(
      await region.getByLabel("Outbound delivery ID", { exact: true }).count(),
      0,
    );
    await audit("dispatch-" + c.dispatch_phase + "-reviewer");
    const action = c.dispatch_phase === "withdraw" ? "withdraw" : "approve";
    await region
      .getByRole("button", {
        name:
          action === "withdraw"
            ? "Review dispatch withdrawal"
            : "Review dispatch approval",
        exact: true,
      })
      .click();
    await page
      .getByRole("heading", { name: "Confirm dispatch " + action, exact: true })
      .waitFor();
    await audit("dispatch-" + c.dispatch_phase + "-confirmation");
    const result = await loss(
      prefix + "/outbound-dispatch-reviews/" + source.id + "/" + action,
      "browser-dispatch-" + c.dispatch_phase,
      () =>
        page
          .getByRole("button", { name: "Confirm exact decision", exact: true })
          .click(),
    );
    review = result.review;
    assert.equal(
      review.state,
      action === "withdraw" ? "withdrawn" : "approved",
    );
    await region
      .getByRole("button", {
        name: "Inspect dispatch review " + review.id.slice(0, 8),
        exact: true,
      })
      .click();
    await region
      .getByRole("heading", {
        name: "Dispatch review: " + review.state,
        exact: true,
      })
      .waitFor();
    await audit("dispatch-" + c.dispatch_phase + "-decision-history");
    record(
      "dispatch-" +
        c.dispatch_phase +
        "-least-privilege-exact-consent-original-key",
    );
  }
  assert.equal(await contacts(), before);
  await writeFile(
    c.raw + "/outbound-dispatch-browser-result.json",
    JSON.stringify(
      {
        state: "passed",
        phase: c.dispatch_phase,
        review,
        receiver_contacts_unchanged: true,
        responses,
      },
      null,
      2,
    ) + "\n",
  );
}
