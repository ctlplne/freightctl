import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
export async function qualifyIndependentApprovals(
  page,
  c,
  audit,
  record,
  actual,
) {
  const prefix = c.url + `/v1/tenants/${c.tenant}/partners/${c.partner}`,
    responses = [];
  const contacts = async () =>
    (await readFile(c.receiver_log, "utf8")).split("Accepted publickey for ")
      .length - 1;
  const before = await contacts();
  async function loss(target, label, action, message) {
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
    await page.getByText(message).waitFor();
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
  let review, release;
  if (c.approval_phase === "request") {
    const section = page.getByRole("region", {
      name: "Onboarding production releases",
    });
    await section
      .getByRole("button", {
        name: "Inspect release " + c.approval_release.id.slice(0, 8),
        exact: true,
      })
      .click();
    await section
      .getByRole("heading", {
        name: "Onboarding release: proposed",
        exact: true,
      })
      .waitFor();
    await section
      .getByLabel("Assigned reviewer account ID", { exact: true })
      .fill(c.approval_reviewer_id);
    await section
      .getByRole("button", {
        name: "Preview independent review package",
        exact: true,
      })
      .click();
    await page
      .getByRole("heading", {
        name: "Share exact review metadata",
        exact: true,
      })
      .waitFor();
    await audit("independent-review-disclosure");
    const result = await loss(
      prefix + "/onboarding-approval-reviews",
      "browser-independent-propose",
      () =>
        page
          .getByRole("button", { name: "Confirm exact decision", exact: true })
          .click(),
      /Request not confirmed/,
    );
    review = result.review;
    assert.equal(review.reviewer_id, c.approval_reviewer_id);
    assert.equal(review.author_id, c.approval_author_id);
    await page.getByRole("button", { name: "Approvals", exact: true }).click();
    await page
      .getByRole("button", {
        name: "Inspect exact review " + review.id.slice(0, 8),
        exact: true,
      })
      .click();
    await page
      .getByRole("heading", {
        name: "Independent review: pending",
        exact: true,
      })
      .waitFor();
    await audit("independent-owner-private-history");
    await page.reload();
    await page.getByRole("button", { name: "Approvals", exact: true }).click();
    await page
      .getByRole("button", {
        name: "Inspect exact review " + review.id.slice(0, 8),
        exact: true,
      })
      .click();
    await page
      .getByRole("heading", {
        name: "Independent review: pending",
        exact: true,
      })
      .waitFor();
    record("independent-request-lost-response-same-key-private-reload");
  } else if (c.approval_phase === "review") {
    await page.getByRole("button", { name: "Approvals", exact: true }).click();
    await page
      .getByRole("button", {
        name: "Inspect exact review " + c.approval_review.id.slice(0, 8),
        exact: true,
      })
      .click();
    const title = page.getByRole("heading", {
      name: "Independent review: pending",
      exact: true,
    });
    await title.waitFor();
    assert.equal(
      await title.evaluate((el) => el === document.activeElement),
      true,
    );
    assert.equal(
      await page
        .getByRole("button", { name: "Onboarding", exact: true })
        .count(),
      0,
    );
    await audit("independent-named-reviewer-package");
    await page
      .getByRole("button", { name: "Review independent approval", exact: true })
      .click();
    await page
      .getByRole("heading", { name: "Confirm approve review", exact: true })
      .waitFor();
    await audit("independent-reviewer-decision");
    const result = await loss(
      prefix +
        "/onboarding-approval-reviews/" +
        c.approval_review.id +
        "/approve",
      "browser-independent-approve",
      () =>
        page
          .getByRole("button", { name: "Confirm exact decision", exact: true })
          .click(),
      /Decision not confirmed/,
    );
    review = result.review;
    assert.equal(review.state, "approved");
    await page
      .getByRole("button", {
        name: "Inspect exact review " + review.id.slice(0, 8),
        exact: true,
      })
      .click();
    await page
      .getByRole("heading", {
        name: "Independent review: approved",
        exact: true,
      })
      .waitFor();
    await audit("independent-approved-history");
    record("independent-reviewer-approval-lost-response-original-key");
  } else {
    const section = page.getByRole("region", {
      name: "Onboarding production releases",
    });
    await section
      .getByRole("button", {
        name: "Inspect release " + c.approval_release.id.slice(0, 8),
        exact: true,
      })
      .click();
    await section
      .getByRole("heading", {
        name: "Onboarding release: proposed",
        exact: true,
      })
      .waitFor();
    for (const action of ["approve", "activate"]) {
      await section
        .getByRole("button", {
          name: (action === "approve" ? "Approve" : "Activate") + " release",
          exact: true,
        })
        .click();
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
      await page.locator("dialog[open]").waitFor({ state: "hidden" });
      await section
        .getByRole("heading", {
          name:
            "Onboarding release: " +
            (action === "approve" ? "approved" : "active"),
          exact: true,
        })
        .waitFor();
    }
    await audit("independent-author-activation");
    record("independent-review-followed-by-separate-owner-activation");
    release = c.approval_release;
  }
  assert.equal(await contacts(), before);
  await writeFile(
    c.raw + "/onboarding-approval-browser-result.json",
    JSON.stringify(
      {
        state: "passed",
        phase: c.approval_phase,
        review,
        release,
        receiver_contacts_unchanged: true,
        responses,
      },
      null,
      2,
    ) + "\n",
  );
}
