import assert from "node:assert/strict";
export async function probe(page, c, selected, view, audit, record, actual) {
  assert.equal(c.routing_target.id, view.job.workflow_id);
  assert.equal(c.routing_target.version, view.job.workflow_version + 1);
  const prefix = c.url + `/v1/tenants/${c.tenant}/partners/${c.partner}`,
    base = `/workflow-collections/${view.job.id}/routing`;
  const panel = () =>
    selected.getByRole("region", {
      name: "Captured batch routing authorization",
      exact: true,
    });
  const confirm = () =>
    page
      .getByRole("button", { name: "Confirm exact decision", exact: true })
      .click();
  const response = async (path, action) => {
    const [r] = await Promise.all([
      page
        .waitForResponse((r) => r.url() === prefix + path && r.status() === 200)
        .then((r) => r.json()),
      action(),
    ]);
    return r;
  };
  async function prepare() {
    await panel()
      .getByRole("spinbutton", {
        name: "Approved routing workflow revision",
        exact: true,
      })
      .fill(String(c.routing_target.version));
    await response(
      `/workflows/${c.routing_target.id}/${c.routing_target.version}`,
      () =>
        panel()
          .getByRole("button", {
            name: "Inspect approved routing revision",
            exact: true,
          })
          .click(),
    );
    await response(base + "/preview", () =>
      panel()
        .getByRole("button", {
          name: "Preview routing authorization",
          exact: true,
        })
        .click(),
    );
  }
  async function review() {
    for (const i of view.inputs) {
      const p = await response(base + "/inputs/" + i.id + "/preview", () =>
        panel()
          .getByRole("button", {
            name: "Inspect routing plan for " + i.source_name,
            exact: true,
          })
          .click(),
      );
      assert.equal(p.execution_plan.facts.source.collection_id, view.job.id);
      assert.equal(
        p.execution_plan.facts.source.manifest_hash,
        view.job.manifest_hash,
      );
      assert.deepEqual(
        p.execution_plan.selected_steps,
        c.expected[i.source_name],
      );
      await panel()
        .getByRole("checkbox", {
          name: "I reviewed this file’s plan and selected recipients",
          exact: true,
        })
        .check();
    }
  }
  async function propose() {
    await prepare();
    await review();
    await panel()
      .getByRole("button", {
        name: "Review proposing routing authorization",
        exact: true,
      })
      .click();
    return response(base + "/proposals", confirm);
  }
  async function approve(r, loss = false) {
    await response(base + "/" + r.id + "/details", () =>
      panel()
        .getByRole("button", {
          name: "Inspect pending routing proposal",
          exact: true,
        })
        .click(),
    );
    await response(base + "/preview", () =>
      panel()
        .getByRole("button", {
          name: "Review pending routing plans for approval",
          exact: true,
        })
        .click(),
    );
    await review();
    await panel()
      .getByRole("button", {
        name: "Review approving exact routing authorization",
        exact: true,
      })
      .click();
    if (!loss) return response(base + "/" + r.id + "/approve", confirm);
    const path = base + "/" + r.id + "/approve",
      target = prefix + path,
      seen = [];
    await page.route(target, async (route) => {
      const result = await actual(
        route,
        "captured-approve-loss-" + seen.length,
        target,
      );
      seen.push(result);
      if (seen.length === 1) await route.abort("failed");
      else
        await route.fulfill({
          status: result.status,
          contentType: "application/json",
          body: result.body,
        });
    });
    await confirm();
    await page.getByText(/^The command result was not confirmed/).waitFor();
    await confirm();
    await page.locator("dialog[open]").waitFor({ state: "hidden" });
    await page.unroute(target);
    assert.equal(seen.length, 2);
    assert.equal(seen[0].idempotency_key, seen[1].idempotency_key);
    assert.deepEqual(
      JSON.parse(seen[0].body).resource,
      JSON.parse(seen[1].body).resource,
    );
    record("captured-routing-approval-original-key-after-real-response-loss");
    return JSON.parse(seen[1].body);
  }
  // Lose the committed proposal response, then recover by GET after a reload.
  await prepare();
  await review();
  await panel()
    .getByRole("button", {
      name: "Review proposing routing authorization",
      exact: true,
    })
    .click();
  await audit("captured-routing-proposal-review");
  const target = prefix + base + "/proposals";
  let lost;
  await page.route(target, async (route) => {
    lost = await actual(route, "captured-propose-lost-response", target);
    await route.abort("failed");
  });
  await confirm();
  await page.getByText(/^The command result was not confirmed/).waitFor();
  await page.unroute(target);
  assert.equal(lost.status, 200);
  const original = JSON.parse(lost.body);
  await page.reload();
  await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
  await page.getByRole("button", { name: "Collections", exact: true }).click();
  await response(`/workflow-collections/${view.job.id}`, () =>
    page
      .getByRole("button", {
        name: "Inspect collection " + view.job.id,
        exact: true,
      })
      .click(),
  );
  const recovered = await response(
    base + "/receipts/" + lost.idempotency_key + "/result",
    () =>
      panel()
        .getByRole("button", {
          name: "Recover original propose receipt",
          exact: true,
        })
        .click(),
  );
  assert.equal(recovered.replayed, true);
  assert.deepEqual(recovered.resource, original.resource);
  record(
    "captured-routing-proposal-receipt-after-real-response-loss-and-reload",
  );
  await response(base + "/" + original.resource.id + "/details", () =>
    panel()
      .getByRole("button", {
        name: "Inspect pending routing proposal",
        exact: true,
      })
      .click(),
  );
  await panel()
    .getByRole("button", {
      name: "Review withdrawing routing proposal",
      exact: true,
    })
    .click();
  await response(base + "/" + original.resource.id + "/withdraw", confirm);
  await page.locator("dialog[open]").waitFor({ state: "hidden" });
  record("captured-routing-withdrawal-without-execution");
  const second = await propose();
  await approve(second.resource, true);
  await response(base + "/" + second.resource.id + "/details", () =>
    panel()
      .getByRole("button", {
        name: "Inspect effective routing decision",
        exact: true,
      })
      .click(),
  );
  await panel()
    .getByRole("button", {
      name: "Review revoking routing authorization",
      exact: true,
    })
    .click();
  await response(base + "/" + second.resource.id + "/revoke", confirm);
  await page.locator("dialog[open]").waitFor({ state: "hidden" });
  await panel()
    .getByText(/New execution under this decision is blocked/)
    .waitFor();
  assert.equal(
    await selected
      .getByRole("button", {
        name: "Review recording routing outcomes",
        exact: true,
      })
      .count(),
    0,
  );
  record("captured-routing-revocation-refuses-original-rule-fallback");
  const third = await propose();
  const effective = await approve(third.resource);
  await page.locator("dialog[open]").waitFor({ state: "hidden" });
  await audit("captured-routing-effective-approval");
  record("captured-routing-explicit-new-approval-before-ordinary-admission");
  return effective.resource;
}
