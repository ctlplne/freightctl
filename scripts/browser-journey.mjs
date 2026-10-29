import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { createReadStream } from "node:fs";
import { X509Certificate, createHash } from "node:crypto";
import { createRequire } from "node:module";
import path from "node:path";
process.umask(0o077);
const require = createRequire(import.meta.url);
const { chromium } = require("../web/node_modules/playwright");
const c = JSON.parse(await readFile(process.argv[2], "utf8")),
  stage = process.argv[3];
const cert = new X509Certificate(await readFile(c.certificate));
const spki = createHash("sha256")
  .update(cert.publicKey.export({ format: "der", type: "spki" }))
  .digest("base64");
const browser = await chromium.launch({
  headless: true,
  chromiumSandbox: true,
  args: [
    "--ignore-certificate-errors-spki-list=" + spki,
    "--disable-background-networking",
    "--disable-component-update",
  ],
});
const steps = [],
  runtimeErrors = [],
  egress = [];
let context, page;
const record = (name, extra = {}) => {
  steps.push({ name, ...extra });
  console.log("passed: " + name);
};
const digestFile = async (p) => {
  const h = createHash("sha256");
  for await (const b of createReadStream(p)) h.update(b);
  return h.digest("hex");
};
try {
  context = await browser.newContext({
    acceptDownloads: true,
    viewport: { width: 1320, height: 950 },
    ...(stage === "resume"
      ? { storageState: c.private + "/browser-state.json" }
      : {}),
  });
  page = await context.newPage();
  page.setDefaultTimeout(15000);
  page.on("pageerror", (e) => runtimeErrors.push(e.message));
  page.on("request", (r) => {
    if (!r.url().startsWith(c.url + "/")) egress.push(new URL(r.url()).origin);
  });
  const prefix = () => `/v1/tenants/${c.tenant}/partners/${c.partner}`;
  async function signIn(index = 0) {
    await page
      .getByRole("heading", { name: "Connect to your workspace" })
      .waitFor();
    const who = c.identities[index];
    await page.getByLabel("Tenant ID", { exact: true }).fill(who.tenant);
    await page.getByLabel("Partner ID", { exact: true }).fill(who.partner);
    await page
      .getByLabel("Account credential file", { exact: true })
      .setInputFiles(who.token);
    await page.getByRole("button", { name: "Connect", exact: true }).click();
    await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
  }
  async function audit(name) {
    const source = await readFile(
      path.join(c.root, "web/node_modules/axe-core/axe.min.js"),
      "utf8",
    );
    await page.evaluate(source);
    const results = await page.evaluate(async () => {
      const r = await window.axe.run(document, {
        runOnly: {
          type: "tag",
          values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"],
        },
      });
      return {
        violations: r.violations.map((v) => ({
          id: v.id,
          impact: v.impact,
          nodes: v.nodes.map((n) => ({
            target: n.target,
            failureSummary: n.failureSummary,
          })),
        })),
        passes: r.passes.length,
      };
    });
    await writeFile(
      c.raw + "/" + name + "-axe.json",
      JSON.stringify(results, null, 2) + "\n",
    );
    assert.equal(
      results.violations.length,
      0,
      "accessibility violations in " + name,
    );
    record(name + "-axe", { passes: results.passes });
  }
  async function status(id) {
    return page.evaluate(
      async ({ url, id }) => {
        const r = await fetch(url + "/uploads/" + id, {
          credentials: "same-origin",
        });
        if (!r.ok) throw new Error("upload status " + r.status);
        return r.json();
      },
      { url: prefix(), id },
    );
  }
  async function saved(id) {
    await page.getByRole("button", { name: "Uploads", exact: true }).click();
    const row = page.getByRole("row").filter({ hasText: id });
    await row.waitFor();
    return row;
  }
  await page.goto(c.url);
  if (stage === "pause") {
    await audit("login");
    await page.screenshot({ path: c.raw + "/login.png", fullPage: true });
    await signIn();
    record("credential-file-signin");
    await audit("workspace");
    const storage = await page.evaluate(() => ({
      cookie: document.cookie,
      local: Object.keys(localStorage),
      session: Object.keys(sessionStorage),
    }));
    assert.equal(storage.cookie.includes("freightctl"), false);
    assert.deepEqual(storage.local, []);
    assert.deepEqual(storage.session, []);
    record("httponly-session-no-web-storage");
    await page.evaluate(() => {
      window.__freightctlUntrusted = false;
      const s = document.createElement("script");
      s.textContent = "window.__freightctlUntrusted=true";
      s.id = "untrusted-csp-probe";
      document.body.append(s);
    });
    assert.equal(
      await page.evaluate(() => window.__freightctlUntrusted),
      false,
    );
    await page.locator("#untrusted-csp-probe").evaluate((e) => e.remove());
    record("inline-script-blocked-by-csp");
    const csrfStatus = await page.evaluate(async (url) => {
      const r = await fetch(url + "/uploads", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "missing-csrf",
        },
        body: "{}",
      });
      return r.status;
    }, prefix());
    assert.equal(csrfStatus, 403);
    record("browser-mutation-without-csrf-denied");
    let patchMetadata = [];
    let patches = 0,
      release;
    const gate = new Promise((resolve) => (release = resolve));
    let reached;
    const held = new Promise((resolve) => (reached = resolve));
    await page.route("**/uploads/*", async (route) => {
      if (route.request().method() === "PATCH")
        patchMetadata.push({
          offset: route.request().headers()["upload-offset"],
          size: route.request().headers()["x-file-size"],
        });
      if (route.request().method() === "PATCH" && ++patches === 2) {
        reached();
        await gate;
        try {
          await route.abort("aborted");
        } catch {}
      } else await route.continue();
    });
    await page
      .getByRole("button", { name: "Upload file", exact: true })
      .click();
    await page
      .getByLabel("File to send", { exact: true })
      .setInputFiles(c.payload);
    await page
      .getByLabel("Destination path", { exact: true })
      .fill("/business.csv");
    await page
      .getByRole("button", { name: "Start upload", exact: true })
      .click();
    await held;
    await page
      .getByRole("button", { name: "Pause upload", exact: true })
      .click();
    await page.waitForTimeout(500);
    await writeFile(
      c.raw + "/before-route-release.txt",
      await page.locator("body").innerText(),
    );
    await writeFile(
      c.raw + "/patch-metadata.json",
      JSON.stringify(patchMetadata, null, 2) + "\n",
    );
    release();
    await page
      .getByRole("button", { name: "Resume upload", exact: true })
      .waitFor();
    await page.unroute("**/uploads/*");
    const uploads = await page.evaluate(async (url) => {
      const r = await fetch(url + "/uploads", { credentials: "same-origin" });
      if (!r.ok) throw new Error("listing failed");
      return r.json();
    }, prefix());
    assert.equal(uploads.uploads.length, 1);
    const upload = uploads.uploads[0];
    assert.equal(upload.state, "open");
    assert.ok(
      upload.committed_offset > 0 &&
        upload.committed_offset < upload.expected_size,
    );
    record("pause-after-durable-checkpoint", {
      offset: upload.committed_offset,
      size: upload.expected_size,
      upload_id: upload.id,
    });
    await writeFile(
      c.private + "/checkpoint.json",
      JSON.stringify(upload, null, 2) + "\n",
    );
    await context.storageState({ path: c.private + "/browser-state.json" });
    await page.reload();
    await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
    const row = await saved(upload.id);
    await row.getByRole("button", { name: "Resume", exact: true }).click();
    await page.getByLabel("Original complete file", { exact: true }).waitFor();
    record("reload-discovers-owned-upload-without-credential");
    await audit("paused");
    await page.screenshot({ path: c.raw + "/paused.png", fullPage: true });
  } else if (stage === "resume") {
    const checkpoint = JSON.parse(
      await readFile(c.private + "/checkpoint.json", "utf8"),
    );
    await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
    record("session-survives-server-and-browser-restart");
    const row = await saved(checkpoint.id);
    await row.getByRole("button", { name: "Resume", exact: true }).click();
    await page
      .getByLabel("Original complete file", { exact: true })
      .setInputFiles(c.wrongPayload);
    await page
      .getByRole("button", { name: "Resume upload", exact: true })
      .click();
    await page
      .getByRole("alert")
      .filter({ hasText: "Choose the original complete file" })
      .waitFor();
    assert.equal(
      (await status(checkpoint.id)).committed_offset,
      checkpoint.committed_offset,
    );
    record("different-source-refused-without-appending");
    await page
      .getByLabel("Original complete file", { exact: true })
      .setInputFiles(c.payload);
    await page
      .getByRole("button", { name: "Resume upload", exact: true })
      .click();
    await page
      .getByText("Upload accepted", { exact: true })
      .waitFor({ timeout: 45000 });
    const completed = await status(checkpoint.id);
    assert.equal(completed.state, "completed");
    assert.equal(completed.committed_offset, completed.expected_size);
    assert.equal(
      completed.acceptance,
      "durable-held-pending-checks-and-release",
    );
    record("resume-uses-confirmed-prefix-and-completes-held");
    const heldStatus = await page.evaluate(
      async ({ url, id }) => {
        const r = await fetch(url + "/files/" + id, {
          credentials: "same-origin",
        });
        return r.status;
      },
      { url: prefix(), id: completed.file_id },
    );
    assert.equal(heldStatus, 409);
    record("held-file-cannot-download");
    await page
      .getByRole("button", { name: "Inspect intake check", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Run required checks", exact: true })
      .click();
    await page
      .getByText(
        "Validation passed. These bytes remain held until you approve release.",
        { exact: true },
      )
      .waitFor();
    record("browser-runs-current-csv-policy");
    await audit("passing-check");
    await page
      .getByRole("button", { name: "Review release", exact: true })
      .click();
    await page.getByRole("dialog").waitFor();
    await audit("release-dialog");
    await page.screenshot({
      path: c.raw + "/release-review.png",
      fullPage: true,
    });
    await page
      .getByRole("button", { name: "Release file", exact: true })
      .click();
    await page
      .getByText(
        "Released under this intake policy. Current access and policy checks still apply.",
        { exact: true },
      )
      .waitFor();
    record("explicit-report-and-revision-bound-release");
    await page.getByRole("button", { name: "Files", exact: true }).click();
    const published = page.getByRole("row").filter({ hasText: "business.csv" });
    await published.waitFor();
    const downloadPromise = page.waitForEvent("download");
    await published
      .getByRole("link", { name: "Download business.csv", exact: true })
      .click();
    const download = await downloadPromise;
    assert.equal(await download.failure(), null);
    assert.equal(download.suggestedFilename(), "business.csv");
    await download.saveAs(c.private + "/browser-received.csv");
    assert.equal(
      await digestFile(c.private + "/browser-received.csv"),
      await digestFile(c.payload),
    );
    record("native-browser-download-matches-exact-source");
    await audit("published-files");
    await page.screenshot({
      path: c.raw + "/published-files.png",
      fullPage: true,
    });
    await page.setViewportSize({ width: 390, height: 844 });
    assert.ok(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    );
    await audit("mobile-files");
    await page.screenshot({ path: c.raw + "/mobile.png", fullPage: true });
    await page.setViewportSize({ width: 1320, height: 950 });
    await page.getByRole("button", { name: "Sign out", exact: true }).click();
    await page
      .getByRole("heading", { name: "Connect to your workspace" })
      .waitFor();
    await signIn(1);
    await page.getByRole("button", { name: "Uploads", exact: true }).click();
    await page
      .getByText("No saved uploads under your current access settings.", {
        exact: true,
      })
      .waitFor();
    assert.equal(
      await page.getByRole("row").filter({ hasText: checkpoint.id }).count(),
      0,
    );
    record("same-partner-other-account-cannot-see-private-upload");
    await page
      .getByRole("button", { name: "Intake checks", exact: true })
      .click();
    await page
      .getByText(
        "No controlled intake revisions are visible to this account.",
        { exact: true },
      )
      .waitFor();
    record("other-account-cannot-see-private-checks");
    await page.getByRole("button", { name: "Sign out", exact: true }).click();
    await signIn(2);
    await page.getByText("No published files here", { exact: true }).waitFor();
    assert.equal(
      await page.getByText("business.csv", { exact: true }).count(),
      0,
    );
    record("other-tenant-has-no-file-name-disclosure");
    await page.getByRole("button", { name: "Sign out", exact: true }).click();
  } else if (stage === "expiry") {
    await signIn();
    await page.waitForTimeout(3500);
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await page
      .getByRole("heading", { name: "Connect to your workspace" })
      .waitFor();
    assert.equal(
      await page.getByRole("row").filter({ hasText: "business.csv" }).count(),
      0,
    );
    record("database-expiry-requires-new-login-and-clears-workspace");
  } else throw new Error("Unknown qualification stage");
  assert.deepEqual(runtimeErrors, []);
  assert.deepEqual(egress, []);
  await writeFile(
    c.raw + "/" + stage + "-result.json",
    JSON.stringify(
      {
        state: "passed",
        stage,
        browser_version: browser.version(),
        node: process.version,
        steps,
        runtime_errors: runtimeErrors,
        page_request_egress_origins: egress,
        inference_performed: false,
        scanner_engine_started: false,
      },
      null,
      2,
    ) + "\n",
  );
} catch (error) {
  if (page && !page.isClosed()) {
    await page
      .screenshot({
        path: c.raw + "/" + stage + "-failure.png",
        fullPage: true,
      })
      .catch(() => {});
    await writeFile(
      c.raw + "/" + stage + "-visible.txt",
      await page.locator("body").innerText(),
    ).catch(() => {});
  }

  await writeFile(
    c.raw + "/" + stage + "-failure.json",
    JSON.stringify(
      {
        state: "failed",
        stage,
        steps,
        error: String(error),
        runtime_errors: runtimeErrors,
      },
      null,
      2,
    ) + "\n",
  );
  throw error;
} finally {
  await context?.close();
  await browser.close();
}
