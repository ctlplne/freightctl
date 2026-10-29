import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
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
  // Faulted responses still come from the real service over verified TLS.
  // Playwright route.fetch uses a separate trust store from Chromium's SPKI
  // pin. Stock curl receives only this fixture CA and protected header refs.
  async function trustedMutation(route, label) {
    const request = route.request(),
      url = new URL(request.url());
    assert.equal(url.origin, c.url);
    assert.equal(request.method(), "POST");
    assert.ok(
      url.pathname.startsWith(prefix() + "/checks/") &&
        /\/(?:run|release)$/.test(url.pathname),
    );
    const headers = c.private + "/" + label + ".headers",
      body = c.private + "/" + label + ".request",
      output = c.private + "/" + label + ".response";
    const filtered = Object.entries(request.headers()).filter(
      ([key]) =>
        !["host", "connection", "content-length", "transfer-encoding"].includes(
          key,
        ),
    );
    await writeFile(
      headers,
      filtered.map(([key, value]) => key + ": " + value).join("\n") + "\n",
    );
    const bytes = request.postDataBuffer() ?? Buffer.alloc(0);
    assert.ok(bytes.length <= 32768);
    await writeFile(body, bytes);
    const status = Number(
      execFileSync(
        "curl",
        [
          "--silent",
          "--show-error",
          "--proto",
          "=https",
          "--cacert",
          c.certificate,
          "--max-time",
          "85",
          "--max-filesize",
          "262144",
          "--header",
          "@" + headers,
          "--request",
          "POST",
          "--data-binary",
          "@" + body,
          "--output",
          output,
          "--write-out",
          "%{http_code}",
          url.href,
        ],
        { encoding: "utf8", timeout: 90000, maxBuffer: 4096 },
      ),
    );
    const response = await readFile(output);
    assert.ok(response.length <= 262144);
    return { status, body: response.toString("utf8") };
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
    await writeFile(
      c.private + "/checkpoint-completed.json",
      JSON.stringify(completed, null, 2) + "\n",
    );
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
    if (c.signatures) {
      assert.equal(
        await page
          .getByRole("button", { name: "Run required checks", exact: true })
          .isDisabled(),
        true,
      );
      const held = await page.evaluate(
        async ({ url, id }) => (await fetch(url + "/checks/" + id)).json(),
        { url: prefix(), id: completed.file_id },
      );
      assert.equal(held.check.attempts, 0);
      await page
        .getByLabel("Public signature file", { exact: true })
        .setInputFiles(c.signatures.good);
      await page
        .getByRole("button", { name: "Attach signature", exact: true })
        .click();
      await page
        .getByText(
          "Signature attached. Its validity is determined by the required check.",
          { exact: true },
        )
        .waitFor();
      record(
        "browser-attaches-independent-armored-signature-before-running-checks",
      );
    }
    let lostRun, retriedRun;
    if (c.signatures) {
      let lost, retry;
      lostRun = new Promise((resolve) => {
        lost = resolve;
      });
      retriedRun = new Promise((resolve) => {
        retry = resolve;
      });
      const keys = [];
      await page.route("**/checks/*/run", async (route) => {
        keys.push(route.request().headers()["idempotency-key"]);
        try {
          const response = await trustedMutation(
            route,
            "check-loss-" + keys.length,
          );
          if (keys.length === 1) {
            await route.abort("failed");
            lost({ status: response.status });
          } else {
            await route.fulfill({
              status: response.status,
              contentType: "application/json",
              body: response.body,
            });
            retry({
              status: response.status,
              keys: [...keys],
              replayed: JSON.parse(response.body).replayed,
            });
          }
        } catch {
          await route.abort("failed").catch(() => {});
          lost({ status: 0 });
          retry({ status: 0, keys: [...keys] });
        }
      });
    }
    await page
      .getByRole("button", { name: "Run required checks", exact: true })
      .click();
    if (c.signatures) {
      const committed = await lostRun;
      assert.equal(
        committed.status,
        200,
        "fault injection must first reach a committed check over verified TLS",
      );
      await page
        .getByRole("button", { name: "Run required checks", exact: true })
        .click();
      const retried = await retriedRun;
      await writeFile(
        c.raw + "/run-response-loss.json",
        JSON.stringify(retried, null, 2) + "\n",
      );
      assert.equal(
        retried.status,
        200,
        "retry after committed check must recover its original receipt",
      );
      assert.equal(
        retried.keys[1],
        retried.keys[0],
        "an unconfirmed check must keep its idempotency key",
      );
      assert.equal(retried.replayed, true);
      await page.unroute("**/checks/*/run");
      record("lost-check-response-replays-original-command-with-one-attempt");
    }
    await page
      .getByText(
        "Validation passed. These bytes remain held until you approve release.",
        { exact: true },
      )
      .waitFor();
    record("browser-runs-current-csv-policy");
    if (c.signatures) {
      await page
        .getByText("Verified primary signer", { exact: true })
        .waitFor();
      await page.getByText(c.signatures.primary, { exact: true }).waitFor();
      await page.getByText(c.signatures.subkey, { exact: true }).waitFor();
      record(
        "passing-browser-report-shows-exact-independent-signer-and-subkey",
      );
    }

    await audit("passing-check");
    await page
      .getByRole("button", { name: "Review release", exact: true })
      .click();
    await page.getByRole("dialog").waitFor();
    let lostRelease, retriedRelease;
    if (c.signatures) {
      const review = page.getByRole("dialog");
      await review.getByText(c.signatures.primary, { exact: true }).waitFor();
      await review.getByText(c.signatures.subkey, { exact: true }).waitFor();
      assert.equal(
        await page.evaluate(() => document.activeElement?.id),
        "release-title",
      );
      const before = await page.evaluate(
        async ({ url, id }) => {
          const view = await (await fetch(url + "/checks/" + id)).json();
          const bytes = await fetch(url + "/files/" + id);
          return {
            attempts: view.check.attempts,
            state: view.check.state,
            download: bytes.status,
          };
        },
        { url: prefix(), id: completed.file_id },
      );
      assert.deepEqual(before, { attempts: 1, state: "passed", download: 409 });
      let lost, retry;
      lostRelease = new Promise((resolve) => {
        lost = resolve;
      });
      retriedRelease = new Promise((resolve) => {
        retry = resolve;
      });
      const keys = [];
      await page.route("**/checks/*/release", async (route) => {
        keys.push(route.request().headers()["idempotency-key"]);
        try {
          const response = await trustedMutation(
            route,
            "release-loss-" + keys.length,
          );
          if (keys.length === 1) {
            await route.abort("failed");
            lost({ status: response.status });
          } else {
            await route.fulfill({
              status: response.status,
              contentType: "application/json",
              body: response.body,
            });
            retry({
              status: response.status,
              keys: [...keys],
              replayed: JSON.parse(response.body).replayed,
            });
          }
        } catch {
          await route.abort("failed").catch(() => {});
          lost({ status: 0 });
          retry({ status: 0, keys: [...keys] });
        }
      });
    }
    await audit("release-dialog");
    await page.screenshot({
      path: c.raw + "/release-review.png",
      fullPage: true,
    });
    await page
      .getByRole("button", { name: "Release file", exact: true })
      .click();
    if (c.signatures) {
      const committed = await lostRelease;
      assert.equal(committed.status, 200);
      const review = page.getByRole("dialog");
      await review
        .getByRole("alert")
        .filter({ hasText: "Release was not confirmed" })
        .waitFor();
      await review
        .getByRole("button", { name: "Retry reviewed release", exact: true })
        .click();
      const replay = await retriedRelease;
      await writeFile(
        c.raw + "/release-response-loss.json",
        JSON.stringify(replay, null, 2) + "\n",
      );
      assert.equal(replay.status, 200);
      assert.equal(replay.keys[1], replay.keys[0]);
      assert.equal(replay.replayed, true);
      await page.unroute("**/checks/*/release");
      record(
        "lost-release-response-keeps-reviewed-command-and-recovers-original-receipt",
      );
    }
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
  } else if (stage === "signed-refusals") {
    assert.ok(c.signatures);
    await signIn();
    async function uploadCase(filename, source) {
      await page.getByRole("button", { name: "Files", exact: true }).click();
      await page
        .getByRole("button", { name: "Upload file", exact: true })
        .click();
      await page
        .getByLabel("File to send", { exact: true })
        .setInputFiles(source);
      await page
        .getByLabel("Destination path", { exact: true })
        .fill("/" + filename);
      await page
        .getByRole("button", { name: "Start upload", exact: true })
        .click();
      await page
        .getByText("Upload accepted", { exact: true })
        .waitFor({ timeout: 45000 });
      await page
        .getByRole("button", { name: "Inspect intake check", exact: true })
        .click();
      await page.getByLabel("Public signature file", { exact: true }).waitFor();
    }
    for (const [label, source, signature] of [
      ["wrong-signer.csv", c.payload, c.signatures.wrongSigner],
      ["changed-content.csv", c.wrongPayload, c.signatures.good],
    ]) {
      await uploadCase(label, source);
      await page
        .getByLabel("Public signature file", { exact: true })
        .setInputFiles(signature);
      await page
        .getByRole("button", { name: "Attach signature", exact: true })
        .click();
      await page
        .getByText(
          "Signature attached. Its validity is determined by the required check.",
          { exact: true },
        )
        .waitFor();
      await page
        .getByRole("button", { name: "Run required checks", exact: true })
        .click();
      await page
        .getByText(
          "The signature does not verify under the selected signer policy. The file remains held.",
          { exact: true },
        )
        .waitFor();
      assert.equal(
        await page
          .getByRole("button", { name: "Review release", exact: true })
          .isDisabled(),
        true,
      );
      assert.equal(
        await page
          .getByText("Verified primary signer", { exact: true })
          .count(),
        0,
      );
      const rejected = await page.evaluate(
        async ({ url, label }) => {
          const checks = await (await fetch(url + "/checks")).json();
          const check = checks.checks.find((c) => c.path === "/" + label);
          const result = await fetch(url + "/files/" + check.file_id);
          return { code: check.code, status: result.status };
        },
        { url: prefix(), label },
      );
      assert.deepEqual(rejected, { code: "signature_invalid", status: 409 });
      record("browser-" + label + "-cannot-release-or-download");
    }
    await uploadCase("signature-input.csv", c.payload);
    for (const file of [
      {
        name: "oversized.sig",
        buffer: Buffer.alloc(32769),
        mimeType: "application/octet-stream",
      },
      {
        name: "malformed.sig",
        buffer: Buffer.from("synthetic malformed signature"),
        mimeType: "application/octet-stream",
      },
    ]) {
      await page
        .getByLabel("Public signature file", { exact: true })
        .setInputFiles(file);
      await page
        .getByRole("button", { name: "Attach signature", exact: true })
        .click();
      await page
        .getByRole("alert")
        .filter({ hasText: "Choose one detached OpenPGP signature" })
        .waitFor();
      assert.equal(
        await page
          .getByRole("button", { name: "Run required checks", exact: true })
          .isDisabled(),
        true,
      );
      record("browser-" + file.name + "-refused-before-check");
    }
    await page
      .getByLabel("Public signature file", { exact: true })
      .setInputFiles(c.signatures.good);
    await page
      .getByRole("button", { name: "Attach signature", exact: true })
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
    await page.getByText("1 of 3", { exact: true }).waitFor();
    record(
      "invalid-signature-inputs-preserve-check-budget-and-good-file-can-be-checked",
    );
    await audit("signature-refusals");
    await page.screenshot({
      path: c.raw + "/signature-refusals.png",
      fullPage: true,
    });
    await page.getByRole("button", { name: "Sign out", exact: true }).click();
  } else if (stage === "signed-revoked") {
    assert.ok(c.signatures);
    await signIn();
    const binary = path.join(c.root, ".cache/freightctl-browser"),
      key = c.signatures.key;
    const revoked = JSON.parse(
      execFileSync(
        binary,
        [
          "pgp-key-revoke",
          "--tenant",
          c.tenant,
          "--partner",
          c.partner,
          "--token-file",
          c.identities[0].token,
          "--pgp-key-id",
          key.id,
          "--version",
          String(key.version),
          "--definition-hash",
          key.hash,
          "--expected-revision",
          String(c.signatures.keyRevision),
          "--idempotency-key",
          "signed-browser-revoke",
        ],
        { encoding: "utf8", timeout: 20000 },
      ),
    );
    assert.equal(revoked.resource.state, "revoked");
    await page
      .getByRole("button", { name: "Intake checks", exact: true })
      .click();
    const row = page.getByRole("row").filter({ hasText: "/business.csv" });
    await row
      .getByRole("button", { name: "Inspect check", exact: true })
      .click();
    await page
      .getByText(
        "Access or policy changed. An administrator must review this revision before further action.",
        { exact: true },
      )
      .waitFor();
    assert.equal(
      await page
        .getByRole("button", { name: "Review release", exact: true })
        .isDisabled(),
      true,
    );
    await page.getByRole("button", { name: "Files", exact: true }).click();
    const file = page.getByRole("row").filter({ hasText: "business.csv" });
    await file.waitFor();
    const downloads = [];
    page.on("download", (d) => downloads.push(d));
    const blocked = page.waitForResponse(
      (r) => r.url().includes("/namespace/file?") && r.status() === 409,
    );
    await file
      .getByRole("link", { name: "Download business.csv", exact: true })
      .click();
    await blocked;
    await page
      .getByRole("heading", { name: "Download unavailable", exact: true })
      .waitFor();
    assert.equal(downloads.length, 0);
    record(
      "revoked-signer-disables-release-and-native-browser-retrieval-returns-readable-refusal",
    );
    await page.screenshot({
      path: c.raw + "/revoked-download.png",
      fullPage: true,
    });
    await page
      .getByRole("link", { name: "Return to your workspace", exact: true })
      .click();
    await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
    await page.getByRole("button", { name: "Sign out", exact: true }).click();
  } else if (stage === "accounts") {
    await signIn();
    await page.getByRole("button", { name: "Accounts", exact: true }).click();
    await page
      .getByLabel("Account label", { exact: true })
      .fill("Native partner reader");
    await page
      .getByRole("button", { name: "Review new account", exact: true })
      .click();
    const review = page.getByRole("dialog");
    const apply = review.getByRole("button", {
      name: "Apply reviewed change",
      exact: true,
    });
    assert.equal(await apply.isDisabled(), true);
    await audit("account-create-review");
    async function saveCredential(filename) {
      const download = page.waitForEvent("download");
      await review
        .getByRole("button", { name: "Download new credential", exact: true })
        .click();
      await (await download).saveAs(filename);
      assert.equal((await readFile(filename)).length, 64);
      await review
        .getByLabel("I saved the credential file securely.", { exact: true })
        .check();
    }
    const first = c.private + "/managed-first.token",
      second = c.private + "/managed-second.token";
    await saveCredential(first);
    const firstProof = createHash("sha256")
      .update(await readFile(first))
      .digest("hex");
    let accountRequest;
    page.on("request", (r) => {
      if (r.url().endsWith("/accounts/commands"))
        accountRequest = r.postDataJSON();
    });
    await apply.click();
    await review.waitFor({ state: "hidden" });
    assert.equal(accountRequest.credential_sha256, firstProof);
    assert.equal(
      JSON.stringify(accountRequest).includes(
        (await readFile(first)).toString(),
      ),
      false,
    );
    const id = accountRequest.account_id;
    await page.getByRole("row").filter({ hasText: id }).waitFor();
    record(
      "browser-reviewed-account-create-saves-credential-before-proof-only-enrollment",
    );
    await audit("accounts-created");
    await page.screenshot({ path: c.raw + "/accounts.png", fullPage: true });
    const binary = path.join(c.root, ".cache/freightctl-browser");
    const flags = [
      "--tenant",
      c.tenant,
      "--partner",
      c.partner,
      "--token-file",
      c.identities[0].token,
    ];
    const current = JSON.parse(
      execFileSync(binary, ["account-status", ...flags, "--account-id", id], {
        encoding: "utf8",
      }),
    );
    assert.equal(current.revision, 1);
    assert.deepEqual(current.permissions, ["list", "read"]);
    async function curlIdentity(token, label, expected) {
      const header = c.private + "/" + label + ".headers";
      await writeFile(
        header,
        Buffer.concat([
          Buffer.from("Authorization: Bearer "),
          await readFile(token),
          Buffer.from("\n"),
        ]),
      );
      const code = execFileSync(
        "curl",
        [
          "--silent",
          "--show-error",
          "--cacert",
          c.certificate,
          "--header",
          "@" + header,
          "--output",
          c.private + "/" + label + ".json",
          "--write-out",
          "%{http_code}",
          c.url + prefix() + "/identity",
        ],
        { encoding: "utf8" },
      );
      assert.equal(code, String(expected));
    }
    await curlIdentity(first, "before-rotation", 200);
    await page
      .getByRole("button", { name: "Review credential rotation", exact: true })
      .click();
    await saveCredential(second);
    await apply.click();
    await review.waitFor({ state: "hidden" });
    await curlIdentity(first, "old-after-rotation", 401);
    await curlIdentity(second, "new-after-rotation", 200);
    record("browser-rotation-denies-old-stock-curl-credential-and-accepts-new");
    const revoke = c.private + "/managed-revoke.json";
    await writeFile(
      revoke,
      JSON.stringify({
        operation: "revoke",
        account_id: id,
        expected_revision: 2,
      }),
    );
    const revoked = JSON.parse(
      execFileSync(
        binary,
        [
          "account-revoke",
          ...flags,
          "--request-file",
          revoke,
          "--idempotency-key",
          "native-revoke",
        ],
        { encoding: "utf8" },
      ),
    );
    assert.equal(revoked.account.state, "revoked");
    const replay = JSON.parse(
      execFileSync(
        binary,
        [
          "account-revoke",
          ...flags,
          "--request-file",
          revoke,
          "--idempotency-key",
          "native-revoke",
        ],
        { encoding: "utf8" },
      ),
    );
    assert.equal(replay.replayed, true);
    assert.equal(
      replay.account.changed_event_id,
      revoked.account.changed_event_id,
    );
    await curlIdentity(second, "after-revocation", 401);
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await page
      .getByRole("row")
      .filter({ hasText: id })
      .filter({ hasText: "revoked" })
      .waitFor();
    record(
      "ordinary-cli-revocation-replays-original-receipt-and-browser-refreshes-current-state",
    );
    const local = await page.evaluate(() => ({
      local: Object.keys(localStorage),
      session: Object.keys(sessionStorage),
    }));
    assert.deepEqual(local, { local: [], session: [] });
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
