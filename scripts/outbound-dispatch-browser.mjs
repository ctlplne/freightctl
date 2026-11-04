import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
export async function qualifyOutboundDispatch(page, c, audit, record, actual) {
  const prefix = c.url + `/v1/tenants/${c.tenant}/partners/${c.partner}`,
    region = page.getByRole("region", {
      name: "Outbound dispatch approvals",
    }),
    responses = [];
  let stage = "contacts-before",
    wire = "idle",
    responseCount = 0;
  const contacts = async () => {
    const raw = await readFile(c.receiver_log, "utf8");
    if (c.dispatch_protocol !== "ftps")
      return raw.split("Accepted publickey for ").length - 1;
    assert.ok(raw.length <= 1024);
    const counter = JSON.parse(raw);
    assert.deepEqual(Object.keys(counter).sort(), [
      "accepted_connections",
      "budget_exhausted",
      "kind",
      "schema_version",
      "stopped",
    ]);
    assert.equal(counter.schema_version, 1);
    assert.equal(counter.kind, "freightctl-ftps-contact-spy");
    assert.equal(counter.stopped, false);
    assert.equal(counter.budget_exhausted, false);
    assert.equal(counter.accepted_connections, 0);
    return counter.accepted_connections;
  };
  async function captureFTPS(locator) {
    if (c.dispatch_protocol !== "ftps") return;
    const text = await locator.innerText();
    assert.ok(text.length <= 65536);
    const effect = c.dispatch_expected.effect;
    assert.equal(effect.protocol, "ftps");
    assert.ok(text.includes(effect.final_path));
    assert.ok(text.includes(effect.ftps.staging_path));
    assert.ok(text.includes(effect.ftps.password_reference_sha256));
    await writeFile(c.raw + "/ftps-visible.txt", text + "\n");
  }
  try {
    const before = await contacts();
    stage = "navigation";
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
        wire = "request";
        const r = await actual(route, label + "-" + seen.length, target);
        seen.push(r);
        responseCount = seen.length;
        wire = seen.length === 1 ? "abort-first" : "fulfill-replay";
        if (seen.length === 1) await route.abort("failed");
        else
          await route.fulfill({
            status: r.status,
            contentType: "application/json",
            body: r.body,
          });
      });
      stage = "first-decision";
      await action();
      stage = "lost-response-notice";
      await region.getByText(/Dispatch decision not confirmed/).waitFor();
      stage = "replay-decision";
      await action();
      stage = "dialog-close";
      await page.locator("dialog[open]").waitFor({ state: "hidden" });
      stage = "receipt-binding";
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
      stage = "source-inspect";
      await region
        .getByLabel("Outbound delivery ID", { exact: true })
        .fill(c.dispatch_delivery.id);
      await region
        .getByRole("button", { name: "Inspect outbound delivery", exact: true })
        .click();
      await region
        .getByRole("heading", {
          name: "Outbound delivery: queued",
          exact: true,
        })
        .waitFor();
      stage = "source-audit";
      await audit("dispatch-" + c.dispatch_phase + "-source");
      stage = "disclosure-preview";
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
      stage = "disclosure-terms-focus";
      await captureFTPS(page.locator("dialog[open]"));
      assert.equal(
        await heading.evaluate((el) => el === document.activeElement),
        true,
      );
      stage = "disclosure-audit";
      await audit("dispatch-" + c.dispatch_phase + "-disclosure");
      const result = await loss(
        prefix + "/outbound-dispatch-reviews",
        "browser-dispatch-" + c.dispatch_phase,
        () =>
          page
            .getByRole("button", {
              name: "Confirm exact decision",
              exact: true,
            })
            .click(),
      );
      review = result.review;
      stage = "requested-review-binding";
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
      stage = "history-audit";
      await audit("dispatch-" + c.dispatch_phase + "-history");
      stage = "history-reload";
      await page.reload();
      await page
        .getByRole("button", { name: "Approvals", exact: true })
        .click();
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
      stage = "reviewer-inspect";
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
      stage = "reviewer-terms-focus";
      await captureFTPS(region);
      assert.equal(
        await title.evaluate((el) => el === document.activeElement),
        true,
      );
      assert.equal(
        await region
          .getByLabel("Outbound delivery ID", { exact: true })
          .count(),
        0,
      );
      stage = "reviewer-audit";
      await audit("dispatch-" + c.dispatch_phase + "-reviewer");
      stage = "confirmation-open";
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
        .getByRole("heading", {
          name: "Confirm dispatch " + action,
          exact: true,
        })
        .waitFor();
      stage = "confirmation-audit";
      await audit("dispatch-" + c.dispatch_phase + "-confirmation");
      const result = await loss(
        prefix + "/outbound-dispatch-reviews/" + source.id + "/" + action,
        "browser-dispatch-" + c.dispatch_phase,
        () =>
          page
            .getByRole("button", {
              name: "Confirm exact decision",
              exact: true,
            })
            .click(),
      );
      review = result.review;
      stage = "decided-review-binding";
      assert.equal(
        review.state,
        action === "withdraw" ? "withdrawn" : "approved",
      );
      stage = "decision-history";
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
      stage = "decision-history-audit";
      await audit("dispatch-" + c.dispatch_phase + "-decision-history");
      record(
        "dispatch-" +
          c.dispatch_phase +
          "-least-privilege-exact-consent-original-key",
      );
    }
    stage = "contacts-after";
    assert.equal(await contacts(), before);
    stage = "result-write";
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
  } catch (error) {
    if (c.dispatch_protocol === "ftps") {
      console.log(
        JSON.stringify({
          kind: "ftps-dispatch-failure",
          phase: c.dispatch_phase,
          stage,
          wire,
          response_count: Math.min(responseCount, 8),
          response_overflow: responseCount > 8,
          dialog_open: await page
            .locator("dialog[open]")
            .isVisible()
            .catch(() => null),
          decision_error_visible: await region
            .getByText(/Dispatch decision not confirmed/)
            .isVisible()
            .catch(() => null),
        }),
      );
    }
    throw error;
  }
}
