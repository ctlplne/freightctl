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
    ...(stage === "resume" || stage === "recovery-after"
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
  async function trustedMutation(route, label, allowedPrefix = prefix()) {
    const request = route.request(),
      url = new URL(request.url());
    assert.equal(url.origin, c.url);
    assert.equal(request.method(), "POST");
    assert.ok(
      (url.pathname.startsWith(allowedPrefix + "/checks/") &&
        /\/(?:run|release|recover)$/.test(url.pathname)) ||
        url.pathname === allowedPrefix + "/partner-directory" ||
        url.pathname === allowedPrefix + "/onboarding-plans" ||
        url.pathname === allowedPrefix + "/onboarding-probes" ||
        (url.pathname.startsWith(allowedPrefix + "/onboarding-probes/") &&
          /\/onboarding-probes\/[0-9a-f-]{36}\/work$/.test(url.pathname)),
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
  async function exerciseOnboarding(partner, token) {
    const base = `/v1/tenants/${c.tenant}/partners/${partner.id}`;
    const flags = [
      "--dsn-file",
      c.runtime,
      "--tenant",
      c.tenant,
      "--partner",
      partner.id,
      "--token-file",
      token,
    ];
    const cli = (args) =>
      JSON.parse(
        execFileSync(c.binary, args, { encoding: "utf8", timeout: 30000 }),
      );
    async function curlGet(suffix, credential, label, expected) {
      const headers = c.private + "/" + label + ".headers",
        output = c.private + "/" + label + ".json";
      await writeFile(
        headers,
        Buffer.concat([
          Buffer.from("Authorization: Bearer "),
          await readFile(credential),
          Buffer.from("\n"),
        ]),
      );
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
            "15",
            "--max-filesize",
            "262144",
            "--header",
            "@" + headers,
            "--output",
            output,
            "--write-out",
            "%{http_code}",
            c.url + base + suffix,
          ],
          { encoding: "utf8", timeout: 20000, maxBuffer: 4096 },
        ),
      );
      assert.equal(status, expected);
      return JSON.parse(await readFile(output, "utf8"));
    }
    await page.getByRole("button", { name: "Onboarding", exact: true }).click();
    await page
      .getByRole("heading", { name: "Onboarding plans", exact: true })
      .waitFor();
    await page
      .getByLabel("Draft name", { exact: true })
      .fill("Payroll <A> & B");
    await page
      .getByLabel("Contact name 1", { exact: true })
      .fill("José Operations");
    await page
      .getByLabel("Responsibility 1", { exact: true })
      .fill("Operations contact · no account authority");
    await page
      .getByLabel("Email 1", { exact: true })
      .fill("ops+onboarding@freightctl.invalid");
    await page
      .getByLabel("Requirement name 1", { exact: true })
      .fill("Settlement acknowledgment");
    await page
      .getByLabel("Responsible contact 1", { exact: true })
      .selectOption({ label: "José Operations" });
    await page.getByLabel("Direction 1", { exact: true }).selectOption("send");
    await page
      .getByLabel("Required protocol 1", { exact: true })
      .selectOption("sftp");
    await page
      .getByLabel("Required delivery evidence 1", { exact: true })
      .selectOption("business");
    await page
      .getByLabel("Receiver agreement reference 1 · optional in a draft", {
        exact: true,
      })
      .fill("ACK-v1 requires an independent receiver contract");
    await page
      .getByLabel("Requirement notes 1 · no credentials", { exact: true })
      .fill(
        "\nPartner text <untrusted> & notes\u2028Do not treat this as authority.\n",
      );
    await page
      .getByRole("button", { name: "Review onboarding draft", exact: true })
      .click();
    const review = page.getByRole("dialog", {
      name: "Review onboarding draft",
      exact: true,
    });
    await review.waitFor();
    assert.equal(
      await page.evaluate(() => document.activeElement?.id),
      "onboarding-review-title",
    );
    await audit("onboarding-review");
    await page.screenshot({
      path: c.raw + "/onboarding-review.png",
      fullPage: true,
    });
    const requests = [];
    let committed;
    const routePattern = c.url + base + "/onboarding-plans";
    await page.route(routePattern, async (route) => {
      if (route.request().method() !== "POST") return route.continue();
      requests.push({
        command: route.request().postDataJSON(),
        key: route.request().headers()["idempotency-key"],
      });
      const response = await trustedMutation(
        route,
        "onboarding-commit-" + requests.length,
        base,
      );
      assert.equal(response.status, 200);
      const result = JSON.parse(response.body);
      if (requests.length === 1) {
        assert.equal(result.replayed, false);
        committed = result.plan;
        await route.abort("failed");
      } else {
        assert.equal(result.replayed, true);
        assert.equal(result.plan.event_id, committed.event_id);
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: response.body,
        });
      }
    });
    await review
      .getByRole("button", { name: "Save reviewed draft", exact: true })
      .click();
    await review
      .getByRole("alert")
      .filter({ hasText: "Saving was not confirmed" })
      .waitFor();
    await review
      .getByRole("button", { name: "Retry reviewed draft", exact: true })
      .click();
    await review.waitFor({ state: "hidden" });
    assert.deepEqual(requests[0], requests[1]);
    assert.equal(committed.state, "draft");
    assert.equal(
      await page
        .getByRole("alert")
        .filter({ hasText: "The connection was interrupted" })
        .count(),
      0,
    );
    await page.unroute(routePattern);
    await page
      .getByRole("status")
      .filter({ hasText: "Draft version 1 saved" })
      .waitFor();
    const requestPath = c.private + "/onboarding-original-request.json";
    await writeFile(requestPath, JSON.stringify(requests[0].command));
    const downloaded = page.waitForEvent("download");
    await page
      .getByRole("button", { name: "Download saved draft JSON", exact: true })
      .click();
    await (await downloaded).saveAs(c.private + "/onboarding-saved.json");
    assert.deepEqual(
      JSON.parse(await readFile(c.private + "/onboarding-saved.json", "utf8"))
        .plan,
      committed,
    );
    record(
      "onboarding-frozen-contact-requirements-and-original-receipt-recover-after-response-loss",
    );
    const identity = cli(["identity", ...flags]);
    const peerToken = c.private + "/onboarding-peer.token",
      peerID = crypto.randomUUID();
    execFileSync(c.binary, ["token", "--token-file", peerToken]);
    const peerRequest = c.private + "/onboarding-peer.json";
    await writeFile(
      peerRequest,
      JSON.stringify({
        operation: "create",
        account_id: peerID,
        expected_revision: 0,
        policy: {
          label: "Onboarding co-manager",
          namespace_root: "/",
          permissions: identity.permissions,
          expires_at: null,
        },
      }),
    );
    cli([
      "account-create",
      ...flags,
      "--request-file",
      peerRequest,
      "--new-token-file",
      peerToken,
      "--idempotency-key",
      "onboarding-peer",
    ]);
    const peerFlags = [...flags];
    peerFlags[peerFlags.indexOf(token)] = peerToken;
    await page.reload();
    await page.getByRole("button", { name: "Onboarding", exact: true }).click();
    await page
      .getByRole("button", { name: "Open " + committed.name, exact: true })
      .click();
    await page.getByText("Editing draft", { exact: false }).waitFor();
    await page
      .getByRole("button", { name: "Review onboarding draft", exact: true })
      .click();
    await review.waitFor();
    const concurrent = structuredClone(requests[0].command);
    concurrent.expected_version = 1;
    concurrent.definition.name = "Concurrent reviewed requirements";
    const concurrentPath = c.private + "/onboarding-concurrent.json";
    await writeFile(concurrentPath, JSON.stringify(concurrent));
    const second = cli([
      "partner-onboarding-save",
      ...peerFlags,
      "--request-file",
      concurrentPath,
      "--idempotency-key",
      "onboarding-concurrent",
    ]);
    assert.equal(second.plan.version, 2);
    assert.equal(second.plan.author_id, peerID);
    await review
      .getByRole("button", { name: "Save reviewed draft", exact: true })
      .click();
    await review
      .getByRole("alert")
      .filter({ hasText: "The server refused this draft" })
      .waitFor();
    assert.equal(
      await review
        .getByRole("button", { name: "Retry reviewed draft", exact: true })
        .isDisabled(),
      true,
    );
    await review
      .getByRole("button", { name: "Cancel review", exact: true })
      .click();
    record(
      "onboarding-concurrent-manager-version-refuses-stale-browser-review",
    );
    const source = c.identities[0].token;
    await curlGet(
      "/onboarding-plans/" + committed.id,
      source,
      "onboarding-cross-partner",
      401,
    );
    const readerToken = c.private + "/onboarding-reader.token",
      readerRequest = c.private + "/onboarding-reader.json";
    execFileSync(c.binary, ["token", "--token-file", readerToken]);
    await writeFile(
      readerRequest,
      JSON.stringify({
        operation: "create",
        account_id: crypto.randomUUID(),
        expected_revision: 0,
        policy: {
          label: "Onboarding audit reader",
          namespace_root: "/",
          permissions: ["audit_read", "list", "read"],
          expires_at: null,
        },
      }),
    );
    cli([
      "account-create",
      ...flags,
      "--request-file",
      readerRequest,
      "--new-token-file",
      readerToken,
      "--idempotency-key",
      "onboarding-reader",
    ]);
    await curlGet(
      "/onboarding-plans/" + committed.id,
      readerToken,
      "onboarding-reader-refusal",
      403,
    );
    const beforePolicy = await curlGet(
      "/onboarding-plans/" + committed.id,
      token,
      "onboarding-before-policy",
      200,
    );
    assert.equal(beforePolicy.plan.version, 2);
    async function policy(permissions, revision, key) {
      const file = c.private + "/" + key + ".json";
      await writeFile(
        file,
        JSON.stringify({
          operation: "update",
          account_id: partner.admin_id,
          expected_revision: revision,
          policy: {
            label: "Payroll administrator",
            namespace_root: "/",
            permissions,
            expires_at: null,
          },
        }),
      );
      return cli([
        "account-update",
        ...peerFlags,
        "--request-file",
        file,
        "--idempotency-key",
        key,
      ]);
    }
    const revoked = await policy(
      identity.permissions.filter((p) => p !== "accounts_manage"),
      1,
      "onboarding-revoke-management",
    );
    assert.equal(revoked.account.authority_revision, 2);
    await curlGet(
      "/onboarding-plans/" + committed.id,
      token,
      "onboarding-live-revocation",
      403,
    );
    assert.equal(
      await page.evaluate(
        async (url) =>
          (await fetch(url, { credentials: "same-origin" })).status,
        base + "/onboarding-plans/" + committed.id,
      ),
      401,
    );
    const restored = await policy(
      identity.permissions,
      2,
      "onboarding-restore-management",
    );
    assert.equal(restored.account.authority_revision, 3);
    const stale = structuredClone(concurrent);
    stale.expected_version = 2;
    const stalePath = c.private + "/onboarding-stale-authority.json";
    await writeFile(stalePath, JSON.stringify(stale));
    assert.throws(
      () =>
        execFileSync(
          c.binary,
          [
            "partner-onboarding-save",
            ...flags,
            "--request-file",
            stalePath,
            "--idempotency-key",
            "onboarding-stale-authority",
          ],
          {
            encoding: "utf8",
            timeout: 30000,
            stdio: ["ignore", "pipe", "pipe"],
          },
        ),
      /resource revision changed/,
    );
    const historical = cli([
      "partner-onboarding-save",
      ...flags,
      "--request-file",
      requestPath,
      "--idempotency-key",
      requests[0].key,
    ]);
    assert.equal(historical.replayed, true);
    assert.equal(historical.plan.event_id, committed.event_id);
    const first = cli([
      "partner-onboarding-status",
      ...flags,
      "--onboarding-id",
      committed.id,
      "--onboarding-version",
      "1",
    ]);
    assert.equal(first.plan.definition_hash, committed.definition_hash);
    assert.equal(first.authority_revision, 3);
    record(
      "onboarding-live-authority-refusals-and-current-credential-private-receipt-replay",
    );
    await page.reload();
    await page
      .getByRole("heading", { name: "Connect to your workspace", exact: true })
      .waitFor();
    await page.getByLabel("Tenant ID", { exact: true }).fill(c.tenant);
    await page.getByLabel("Partner ID", { exact: true }).fill(partner.id);
    await page
      .getByLabel("Account credential file", { exact: true })
      .setInputFiles(token);
    await page.getByRole("button", { name: "Connect", exact: true }).click();
    await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
    await page.getByRole("button", { name: "Onboarding", exact: true }).click();
    await page
      .getByRole("button", { name: "Open " + second.plan.name, exact: true })
      .click();
    await page
      .getByLabel("Draft name", { exact: true })
      .fill("Current reviewed requirements");
    await page
      .getByRole("button", { name: "Review onboarding draft", exact: true })
      .click();
    await review.waitFor();
    await review
      .getByRole("button", { name: "Save reviewed draft", exact: true })
      .click();
    await review.waitFor({ state: "hidden" });
    await page
      .getByRole("status")
      .filter({ hasText: "Draft version 3 saved" })
      .waitFor();
    const final = cli([
      "partner-onboarding-status",
      ...flags,
      "--onboarding-id",
      committed.id,
    ]);
    assert.equal(final.plan.version, 3);
    assert.equal(final.plan.state, "draft");
    assert.equal(final.authority_revision, 3);
    const events = await curlGet(
      "/events",
      readerToken,
      "onboarding-redacted-events",
      200,
    );
    assert.ok(Array.isArray(events.events));
    const privateEvents = events.events.filter((e) =>
      ["OnboardingPlanRecorded", "OnboardingCommandCompleted"].includes(e.kind),
    );
    assert.equal(privateEvents.length, 6);
    for (const event of privateEvents) {
      assert.equal(event.payload.redacted, true);
      assert.match(event.payload.source_payload_sha256, /^[0-9a-f]{64}$/);
      assert.equal(
        JSON.stringify(event.payload).includes("ops+onboarding"),
        false,
      );
    }
    const refusals = await page.evaluate(
      async ({ url, command }) => {
        const session = await (
          await fetch("/v1/browser/session", { credentials: "same-origin" })
        ).json();
        async function send(body, csrf) {
          return (
            await fetch(url, {
              method: "POST",
              credentials: "same-origin",
              headers: {
                "Content-Type": "application/json",
                "Idempotency-Key": crypto.randomUUID(),
                ...(csrf ? { "X-CSRF-Token": session.csrf_token } : {}),
              },
              body: JSON.stringify(body),
            })
          ).status;
        }
        return [
          await send(command, false),
          await send(
            {
              ...command,
              active: true,
              approved: true,
              endpoint: "https://untrusted.invalid",
            },
            true,
          ),
        ];
      },
      { url: base + "/onboarding-plans", command: requests[0].command },
    );
    assert.deepEqual(refusals, [403, 400]);
    await audit("onboarding-current-draft");
    await page.screenshot({
      path: c.raw + "/onboarding-draft.png",
      fullPage: true,
    });
    await writeFile(
      c.private + "/onboarding-observations.json",
      JSON.stringify(
        {
          plan_id: committed.id,
          original_event_id: committed.event_id,
          original_hash: committed.definition_hash,
          current_hash: final.plan.definition_hash,
          current_version: 3,
          current_authority_revision: 3,
          draft_only: true,
          original_request_key: requests[0].key,
          cross_partner_status: 401,
          reader_status: 403,
          redacted_events: privateEvents.length,
          requests,
        },
        null,
        2,
      ),
    );
    record(
      "onboarding-current-draft-preserves-history-redacts-audit-and-cannot-claim-activation",
    );
    await page.getByRole("button", { name: "Files", exact: true }).click();
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
  if (stage === "probes") {
    await signIn();
    await page.getByRole("button", { name: "Onboarding", exact: true }).click();
    await page
      .getByRole("button", { name: "Open " + c.probe_plan.name, exact: true })
      .click();
    await page
      .getByRole("heading", { name: "Connectivity tests", exact: true })
      .waitFor();
    await page
      .getByLabel("Saved exchange requirement", { exact: true })
      .selectOption(c.probe_plan.definition.requirements[0].id);
    await page
      .getByLabel("Registered connection UUID", { exact: true })
      .fill(c.probe_connection.id);
    await page
      .getByLabel("Registered connection version", { exact: true })
      .fill(String(c.probe_connection.version));
    await page
      .getByRole("button", { name: "Read registered connection", exact: true })
      .click();
    await page.getByText("Registered receiver:", { exact: false }).waitFor();
    await page
      .getByRole("button", { name: "Review connectivity test", exact: true })
      .click();
    const dialog = page.getByRole("dialog", {
      name: "Review connectivity probe",
    });
    await dialog.waitFor();
    assert.equal(
      await page.evaluate(() => document.activeElement?.id),
      "onboarding-probe-review-title",
    );
    assert.ok(
      (await dialog.innerText()).includes(c.probe_connection.host_fingerprint),
    );
    assert.ok(
      (await dialog.innerText()).includes(c.probe_connection.definition_hash),
    );
    await audit("probe-review");
    await page.screenshot({
      path: c.raw + "/probe-review.png",
      fullPage: true,
    });
    const starts = [],
      works = [];
    await page.route(c.url + prefix() + "/onboarding-probes", async (route) => {
      const request = route.request();
      if (request.method() !== "POST") {
        await route.continue();
        return;
      }
      starts.push({
        body: request.postDataJSON(),
        key: request.headers()["idempotency-key"],
      });
      const result = await trustedMutation(
        route,
        "probe-browser-start-" + starts.length,
      );
      if (starts.length === 1) {
        await route.abort("failed");
        return;
      }
      assert.equal(result.status, 200);
      assert.equal(JSON.parse(result.body).replayed, true);
      await route.fulfill({
        status: result.status,
        contentType: "application/json",
        body: result.body,
      });
    });
    await page.route(
      c.url + prefix() + "/onboarding-probes/*/work",
      async (route) => {
        const request = route.request();
        if (request.headers()["idempotency-key"] === "missing-probe-csrf") {
          await route.continue();
          return;
        }
        works.push({
          url: request.url(),
          body: request.postDataJSON(),
          key: request.headers()["idempotency-key"],
        });
        const result = await trustedMutation(
          route,
          "probe-browser-work-" + works.length,
        );
        assert.equal(result.status, 200);
        assert.equal(JSON.parse(result.body).probe.state, "succeeded");
        if (works.length === 1) {
          await route.abort("failed");
          return;
        }
        await route.fulfill({
          status: result.status,
          contentType: "application/json",
          body: result.body,
        });
      },
    );
    await page
      .getByRole("button", {
        name: "Run reviewed connectivity test",
        exact: true,
      })
      .click();
    await dialog
      .getByText("The probe result is not confirmed.", { exact: false })
      .waitFor();
    await page
      .getByRole("button", {
        name: "Run reviewed connectivity test",
        exact: true,
      })
      .click();
    await page
      .getByRole("button", { name: "Recover same recorded probe", exact: true })
      .waitFor();
    await dialog
      .getByText("The probe result is not confirmed.", { exact: false })
      .waitFor();
    await page
      .getByRole("button", { name: "Recover same recorded probe", exact: true })
      .click();
    await page
      .getByRole("heading", {
        name: "Read-only connectivity: succeeded",
        exact: true,
      })
      .waitFor();
    assert.deepEqual(starts[1], starts[0]);
    assert.deepEqual(works[1], works[0]);
    assert.equal(
      await page
        .getByText("The probe result is not confirmed.", { exact: false })
        .count(),
      0,
    );
    const committed = JSON.parse(
      await readFile(c.private + "/probe-browser-work-1.response", "utf8"),
    );
    assert.equal(committed.evidence_strength, "connectivity_only");
    assert.equal(committed.file_exchange_performed, false);
    assert.equal(committed.production_active, false);
    assert.ok(
      (await page.locator("body").innerText()).includes(
        "Connectivity probe outcome recorded.",
      ),
    );
    record(
      "native-probe-recovers-committed-start-and-work-responses-with-original-keys",
    );
    await page.reload();
    await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
    await page.getByRole("button", { name: "Onboarding", exact: true }).click();
    await page
      .getByRole("button", { name: "Open " + c.probe_plan.name, exact: true })
      .click();
    await page
      .getByRole("button", {
        name: "Inspect probe " + committed.probe.id.slice(0, 8),
        exact: true,
      })
      .click();
    await page
      .getByRole("heading", {
        name: "Read-only connectivity: succeeded",
        exact: true,
      })
      .waitFor();
    await page
      .getByRole("button", {
        name: "Review recorded probe recovery",
        exact: true,
      })
      .click();
    await page
      .getByRole("button", { name: "Recover same recorded probe", exact: true })
      .click();
    await page
      .getByRole("heading", {
        name: "Read-only connectivity: succeeded",
        exact: true,
      })
      .waitFor();
    assert.deepEqual(works[2], works[0]);
    const csrf = await page.evaluate(
      async ({ url, hash }) => {
        const r = await fetch(url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": "missing-probe-csrf",
          },
          body: JSON.stringify({ definition_hash: hash }),
        });
        return r.status;
      },
      {
        url: prefix() + "/onboarding-probes/" + committed.probe.id + "/work",
        hash: committed.probe.definition_hash,
      },
    );
    assert.equal(csrf, 403);
    await audit("probe-result");
    await page.screenshot({
      path: c.raw + "/probe-result.png",
      fullPage: true,
    });
    await writeFile(
      c.private + "/probe-browser-observations.json",
      JSON.stringify(
        {
          probe_id: committed.probe.id,
          state: committed.probe.state,
          definition_hash: committed.probe.definition_hash,
          author_id: committed.probe.author_id,
          start_requests: starts.length,
          work_requests: works.length,
          starts,
          works,
          file_exchange_performed: false,
          production_active: false,
          missing_csrf_status: csrf,
        },
        null,
        2,
      ) + "\n",
    );
    record(
      "native-probe-history-recovers-original-result-after-reload-without-claiming-exchange-or-activation",
    );
  } else if (stage === "partners") {
    const binary = c.binary,
      flags = [
        "--dsn-file",
        c.runtime,
        "--tenant",
        c.tenant,
        "--partner",
        c.partner,
        "--token-file",
        c.identities[0].token,
      ];
    const cli = (args) =>
      JSON.parse(
        execFileSync(binary, args, { encoding: "utf8", timeout: 30000 }),
      );
    const sourceActor = cli(["identity", ...flags]).actor_id;
    const peerToken = c.private + "/peer.token";
    execFileSync(binary, ["token", "--token-file", peerToken]);
    const peerID = crypto.randomUUID(),
      peerRequest = c.private + "/peer-account.json";
    const sourceIdentity = cli(["identity", ...flags]);
    await writeFile(
      peerRequest,
      JSON.stringify({
        operation: "create",
        account_id: peerID,
        expected_revision: 0,
        policy: {
          label: "Partner-scoped manager",
          namespace_root: "/",
          expires_at: null,
          permissions: sourceIdentity.permissions,
        },
      }),
    );
    cli([
      "account-create",
      ...flags,
      "--request-file",
      peerRequest,
      "--new-token-file",
      peerToken,
      "--idempotency-key",
      "peer-account",
    ]);
    c.identities.push({
      tenant: c.tenant,
      partner: c.partner,
      token: peerToken,
    });
    await signIn(1);
    assert.equal(
      await page.getByRole("button", { name: "Partners", exact: true }).count(),
      0,
    );
    const denied = await page.evaluate(
      async (url) =>
        (
          await fetch(url + "/partner-directory", {
            credentials: "same-origin",
          })
        ).status,
      prefix(),
    );
    assert.equal(denied, 403);
    record("ordinary-partner-manager-cannot-discover-tenant-directory");
    await page.getByRole("button", { name: "Sign out", exact: true }).click();
    await signIn();
    await page.getByRole("button", { name: "Partners", exact: true }).click();
    await page
      .getByRole("heading", { name: "Partners", exact: true })
      .waitFor();
    await page
      .getByLabel("Partner name", { exact: true })
      .fill("Payroll partner");
    await page
      .getByLabel("First administrator name", { exact: true })
      .fill("Payroll administrator");
    await page
      .getByRole("button", { name: "Review partner enrollment", exact: true })
      .click();
    const review = page.getByRole("dialog", {
      name: "Review partner enrollment",
      exact: true,
    });
    await review.waitFor();
    assert.equal(
      await review.evaluate((d) => d.contains(document.activeElement)),
      true,
    );
    await audit("partner-enrollment-review");
    await page.screenshot({
      path: c.raw + "/partner-review.png",
      fullPage: true,
    });
    const pendingDownload = page.waitForEvent("download");
    await review
      .getByRole("button", { name: "Download partner credential", exact: true })
      .click();
    const credentialDownload = await pendingDownload;
    assert.equal(await credentialDownload.failure(), null);
    const newToken = c.private + "/new-partner.token";
    await credentialDownload.saveAs(newToken);
    await review
      .getByRole("checkbox", {
        name: "I saved the partner credential in a protected location",
        exact: true,
      })
      .check();
    const requests = [];
    let committed;
    await page.route("**/partner-directory", async (route) => {
      if (route.request().method() !== "POST") {
        await route.continue();
        return;
      }
      const request = route.request();
      requests.push({
        key: request.headers()["idempotency-key"],
        command: JSON.parse(request.postData()),
      });
      const r = await trustedMutation(
        route,
        "partner-enroll-" + requests.length,
      );
      assert.equal(r.status, 200);
      const body = JSON.parse(r.body);
      if (requests.length === 1) {
        assert.equal(body.replayed, false);
        committed = body.partner;
        await route.abort("failed");
      } else {
        assert.equal(body.replayed, true);
        assert.equal(body.partner.event_id, committed.event_id);
        await route.fulfill({
          status: r.status,
          contentType: "application/json",
          body: r.body,
        });
      }
    });
    await review
      .getByRole("button", { name: "Enroll reviewed partner", exact: true })
      .click();
    await review
      .getByRole("alert")
      .filter({ hasText: "Enrollment was not confirmed" })
      .waitFor();
    await review
      .getByRole("button", { name: "Retry reviewed enrollment", exact: true })
      .click();
    await page
      .getByRole("heading", { name: "Partner enrolled", exact: true })
      .waitFor();
    await page.unroute("**/partner-directory");
    assert.equal(requests.length, 2);
    assert.deepEqual(requests[0], requests[1]);
    assert.equal(
      createHash("sha256")
        .update(await readFile(newToken))
        .digest("hex"),
      requests[0].command.credential_sha256,
    );
    await writeFile(
      c.private + "/enrollment-receipt.json",
      JSON.stringify({ requests, replayed: true, partner: committed }, null, 2),
    );
    const workspaceDownload = page.waitForEvent("download");
    await page
      .getByRole("button", { name: "Download partner workspace", exact: true })
      .click();
    const workspace = await workspaceDownload;
    const workspacePath = c.private + "/new-partner-workspace.json";
    await workspace.saveAs(workspacePath);
    const metadata = JSON.parse(await readFile(workspacePath, "utf8"));
    assert.equal(metadata.tenant_id, c.tenant);
    assert.equal(metadata.partner_id, committed.id);
    assert.equal(
      await page
        .getByRole("alert")
        .filter({ hasText: "The connection was interrupted" })
        .count(),
      0,
      "confirmed enrollment must clear its earlier connection error",
    );
    await audit("tenant-directory");
    const refusals = await page.evaluate(
      async ({ url, base }) => {
        const session = await (
          await fetch("/v1/browser/session", { credentials: "same-origin" })
        ).json();
        const command = {
          ...base,
          partner_id: crypto.randomUUID(),
          admin_id: crypto.randomUUID(),
        };
        async function send(key, body, csrf) {
          return (
            await fetch(url, {
              method: "POST",
              credentials: "same-origin",
              headers: {
                "Content-Type": "application/json",
                "Idempotency-Key": key,
                ...(csrf ? { "X-CSRF-Token": session.csrf_token } : {}),
              },
              body: JSON.stringify(body),
            })
          ).status;
        }
        return [
          await send("partner-no-csrf", command, false),
          await send(
            "partner-unknown-field",
            { ...command, tenant_administration: true },
            true,
          ),
          await send(
            "partner-stale-review",
            { ...command, expected_tenant_revision: 999 },
            true,
          ),
        ];
      },
      { url: prefix() + "/partner-directory", base: requests[0].command },
    );
    assert.deepEqual(refusals, [403, 400, 409]);
    record(
      "partner-api-refuses-missing-csrf-unknown-fields-and-stale-authority",
    );
    await page.screenshot({
      path: c.raw + "/partner-directory.png",
      fullPage: true,
    });
    record(
      "reviewed-tenant-enrollment-replays-one-cross-scope-receipt-after-response-loss",
    );
    await page.getByRole("button", { name: "Sign out", exact: true }).click();
    await page
      .getByRole("heading", { name: "Connect to your workspace", exact: true })
      .waitFor();
    await page
      .getByLabel("Workspace reference file (optional)", { exact: true })
      .setInputFiles(workspacePath);
    await page
      .getByText(
        "Workspace IDs loaded. Choose the account credential file to connect.",
        { exact: true },
      )
      .waitFor();
    await page
      .getByLabel("Account credential file", { exact: true })
      .setInputFiles(newToken);
    await page.getByRole("button", { name: "Connect", exact: true }).click();
    await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
    assert.equal(
      await page.getByRole("button", { name: "Partners", exact: true }).count(),
      0,
    );
    assert.equal(
      await page.evaluate(
        async (url) =>
          (
            await fetch(url + "/partner-directory", {
              credentials: "same-origin",
            })
          ).status,
        `/v1/tenants/${c.tenant}/partners/${committed.id}`,
      ),
      403,
    );
    await exerciseOnboarding(committed, newToken);
    await page
      .getByRole("button", { name: "Upload file", exact: true })
      .click();
    await page
      .getByLabel("File to send", { exact: true })
      .setInputFiles(c.payload);
    await page
      .getByLabel("Destination path", { exact: true })
      .fill("/partner.csv");
    await page
      .getByRole("button", { name: "Start upload", exact: true })
      .click();
    await page.getByText("Upload accepted", { exact: true }).waitFor();
    await page.getByRole("button", { name: "Files", exact: true }).click();
    const row = page.getByRole("row").filter({ hasText: "partner.csv" });
    await row.waitFor();
    const received = page.waitForEvent("download");
    await row
      .getByRole("link", { name: "Download partner.csv", exact: true })
      .click();
    const bytes = await received;
    await bytes.saveAs(c.private + "/browser-received.csv");
    assert.equal(
      await digestFile(c.private + "/browser-received.csv"),
      await digestFile(c.payload),
    );
    await audit("new-partner-files");
    await page.screenshot({
      path: c.raw + "/partner-published.png",
      fullPage: true,
    });
    record("new-partner-signin-transfer-and-download-without-tenant-authority");
    await page.getByRole("button", { name: "Sign out", exact: true }).click();
    await signIn();
    await page.getByRole("button", { name: "Partners", exact: true }).click();
    await page
      .getByLabel("Partner name", { exact: true })
      .fill("Stale reviewed partner");
    await page
      .getByLabel("First administrator name", { exact: true })
      .fill("Uncommitted administrator");
    await page
      .getByRole("button", { name: "Review partner enrollment", exact: true })
      .click();
    await review.waitFor();
    const unused = page.waitForEvent("download");
    await review
      .getByRole("button", { name: "Download partner credential", exact: true })
      .click();
    await (await unused).saveAs(c.private + "/unused-reviewed.token");
    await review
      .getByRole("checkbox", {
        name: "I saved the partner credential in a protected location",
        exact: true,
      })
      .check();
    async function maintenance(operation, expectedRevision, authority, key) {
      const file = c.private + "/" + key + ".json";
      await writeFile(
        file,
        JSON.stringify({
          operation,
          actor_id: sourceActor,
          expected_revision: expectedRevision,
          expected_authority_revision: authority,
        }),
      );
      return cli([
        "tenant-admin-" + operation,
        "--admin-dsn-file",
        c.admin,
        "--tenant",
        c.tenant,
        "--partner",
        c.partner,
        "--request-file",
        file,
        "--idempotency-key",
        key,
      ]);
    }
    await maintenance("revoke", 1, 1, "revoke-tenant");
    assert.equal(
      await page.evaluate(
        async (url) =>
          (
            await fetch(url + "/partner-directory", {
              credentials: "same-origin",
            })
          ).status,
        prefix(),
      ),
      403,
    );
    await maintenance("grant", 2, 1, "renew-tenant");
    await review
      .getByRole("button", { name: "Enroll reviewed partner", exact: true })
      .click();
    await review
      .getByRole("alert")
      .filter({ hasText: "The server refused this enrollment" })
      .waitFor();
    assert.equal(
      await review
        .getByRole("button", { name: "Retry reviewed enrollment", exact: true })
        .isDisabled(),
      true,
    );
    await review.getByRole("button", { name: "Cancel", exact: true }).click();
    record("renewed-tenant-grant-refuses-old-reviewed-new-enrollment");
    const rotated = c.private + "/rotated-manager.token";
    execFileSync(binary, ["token", "--token-file", rotated]);
    const rotate = c.private + "/rotate-manager.json";
    await writeFile(
      rotate,
      JSON.stringify({
        operation: "rotate",
        account_id: sourceActor,
        expected_revision: 1,
      }),
    );
    cli([
      "account-rotate",
      "--dsn-file",
      c.runtime,
      "--tenant",
      c.tenant,
      "--partner",
      c.partner,
      "--token-file",
      peerToken,
      "--request-file",
      rotate,
      "--new-token-file",
      rotated,
      "--idempotency-key",
      "rotate-manager",
    ]);
    const rotatedFlags = [...flags];
    rotatedFlags[rotatedFlags.indexOf(c.identities[0].token)] = rotated;
    assert.equal(
      cli(["identity", ...rotatedFlags]).tenant_administration,
      false,
    );
    const renewal = await maintenance(
      "grant",
      3,
      2,
      "authorize-rotated-manager",
    );
    assert.equal(renewal.membership.revision, 4);
    const status = cli([
      "tenant-admin-status",
      "--admin-dsn-file",
      c.admin,
      "--tenant",
      c.tenant,
      "--partner",
      c.partner,
      "--account-id",
      sourceActor,
    ]);
    assert.equal(status.revision, 4);
    assert.equal(status.authority_revision, 2);
    const replayFile = c.private + "/cross-interface-enrollment.json";
    await writeFile(replayFile, JSON.stringify(requests[0].command));
    const replay = cli([
      "partner-create",
      ...rotatedFlags,
      "--request-file",
      replayFile,
      "--idempotency-key",
      requests[0].key,
    ]);
    assert.equal(replay.replayed, true);
    assert.equal(replay.partner.event_id, committed.event_id);
    await writeFile(
      c.private + "/partner-enrolled.json",
      JSON.stringify(
        {
          partner_id: committed.id,
          admin_id: committed.admin_id,
          event_id: committed.event_id,
          receipt_key: requests[0].key,
          source_actor_id: sourceActor,
          source_authority_revision: 2,
          source_tenant_grant_revision: 4,
        },
        null,
        2,
      ),
    );
    record(
      "rotated-manager-needs-explicit-reauthorization-and-cli-replays-original-receipt",
    );
  } else if (stage === "setup") {
    await audit("setup-login");
    await page
      .getByLabel("Workspace reference file (optional)", { exact: true })
      .setInputFiles(c.badWorkspace);
    await page
      .getByRole("alert")
      .filter({ hasText: "Choose the workspace JSON saved by setup" })
      .waitFor();
    assert.equal(
      await page.getByLabel("Tenant ID", { exact: true }).inputValue(),
      "",
    );
    await page
      .getByLabel("Workspace reference file (optional)", { exact: true })
      .setInputFiles(c.untrustedWorkspace);
    await page
      .getByText(
        "Workspace IDs loaded. Choose the account credential file to connect.",
        { exact: true },
      )
      .waitFor();
    assert.equal(new URL(page.url()).origin, c.url);
    assert.equal(
      await page
        .getByLabel("Account credential file", { exact: true })
        .inputValue(),
      "",
    );
    record(
      "workspace-file-refuses-invalid-ids-and-cannot-select-origin-or-credential",
    );
    await page
      .getByLabel("Workspace reference file (optional)", { exact: true })
      .setInputFiles(c.workspace);
    await page
      .getByText(
        "Workspace IDs loaded. Choose the account credential file to connect.",
        { exact: true },
      )
      .waitFor();
    assert.equal(
      await page.getByLabel("Tenant ID", { exact: true }).inputValue(),
      c.tenant,
    );
    assert.equal(
      await page.getByLabel("Partner ID", { exact: true }).inputValue(),
      c.partner,
    );
    await page.screenshot({ path: c.raw + "/setup-login.png", fullPage: true });
    await page
      .getByLabel("Account credential file", { exact: true })
      .setInputFiles(c.identities[0].token);
    await page.getByRole("button", { name: "Connect", exact: true }).click();
    await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
    record("saved-setup-reference-and-first-admin-authenticate");
    await page
      .getByRole("button", { name: "Upload file", exact: true })
      .click();
    await page
      .getByLabel("File to send", { exact: true })
      .setInputFiles(c.payload);
    await page
      .getByLabel("Destination path", { exact: true })
      .fill("/setup.csv");
    await page
      .getByRole("button", { name: "Start upload", exact: true })
      .click();
    await page
      .getByText("Upload accepted", { exact: true })
      .waitFor({ timeout: 45000 });
    record("fresh-first-admin-browser-durable-upload");
    await page.getByRole("button", { name: "Files", exact: true }).click();
    const published = page.getByRole("row").filter({ hasText: "setup.csv" });
    await published.waitFor();
    const pending = page.waitForEvent("download");
    await published
      .getByRole("link", { name: "Download setup.csv", exact: true })
      .click();
    const download = await pending;
    assert.equal(await download.failure(), null);
    await download.saveAs(c.private + "/browser-received.csv");
    assert.equal(
      await digestFile(c.private + "/browser-received.csv"),
      await digestFile(c.payload),
    );
    await audit("setup-published-files");
    await page.screenshot({
      path: c.raw + "/setup-published-files.png",
      fullPage: true,
    });
    record("fresh-first-admin-native-download-exact-bytes");
  } else if (stage === "pause") {
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
  } else if (stage === "recovery-wait" || stage === "recovery-after") {
    if (stage === "recovery-wait") await signIn();
    else
      await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
    await page
      .getByRole("button", { name: "Intake checks", exact: true })
      .click();
    await page
      .getByRole("row")
      .filter({ hasText: "/recovery.csv" })
      .getByRole("button", { name: "Inspect check", exact: true })
      .click();
    await page
      .getByRole("heading", { name: "Check worker reservation", exact: true })
      .waitFor();
    const read = () =>
      page.evaluate(
        async ({ url, id }) => (await fetch(url + "/checks/" + id)).json(),
        { url: prefix(), id: c.fileID },
      );
    const post = (body, key) =>
      page.evaluate(
        async ({ url, id, body, key }) => {
          const session = await (await fetch("/v1/browser/session")).json();
          const response = await fetch(url + "/checks/" + id + "/recover", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-CSRF-Token": session.csrf_token,
              "Idempotency-Key": key,
            },
            body: JSON.stringify(body),
          });
          return response.status;
        },
        { url: prefix(), id: c.fileID, body, key },
      );
    if (stage === "recovery-wait") {
      const initial = await read();
      assert.equal(initial.recovery.code, "lease_active");
      assert.equal(initial.recovery.eligible, false);
      assert.equal(
        await page
          .getByRole("button", { name: "Run required checks", exact: true })
          .isDisabled(),
        true,
      );
      assert.equal(
        await page
          .getByRole("button", { name: "Recover expired check", exact: true })
          .isDisabled(),
        true,
      );
      assert.equal(
        await post(initial.recovery.decision, "native-too-early"),
        409,
      );
      assert.equal((await read()).check.attempts, 1);
      await context.storageState({ path: c.private + "/browser-state.json" });
      record(
        "dead-worker-live-lease-refuses-ui-and-api-replacement-without-spending-attempt",
      );
    } else {
      const ready = await read();
      assert.equal(ready.recovery.eligible, true);
      assert.equal(ready.check.attempts, 1);
      assert.equal(ready.check.worker_id, c.originalWorker);
      const d = ready.recovery.decision;
      await writeFile(
        c.private + "/recovery-decision.json",
        JSON.stringify(d, null, 2) + "\n",
      );
      for (const [name, body] of [
        ["revision", { ...d, expected_revision: d.expected_revision + 1 }],
        ["worker", { ...d, expected_worker_id: crypto.randomUUID() }],
        ["source", { ...d, sha256: "0".repeat(64) }],
        ["policy", { ...d, policy_hash: "0".repeat(64) }],
        [
          "lease",
          {
            ...d,
            expected_lease_until: new Date(
              Date.parse(d.expected_lease_until) - 1000,
            ).toISOString(),
          },
        ],
      ])
        assert.equal(await post(body, "native-wrong-" + name), 409);
      assert.equal(
        await post({ ...d, ignore_lease: true }, "native-unknown-field"),
        400,
      );
      assert.equal((await read()).check.attempts, 1);
      record(
        "recovery-refuses-changed-selectors-and-unknown-fields-without-changing-budget",
      );
      await page
        .getByRole("button", { name: "Recover expired check", exact: true })
        .click();
      const review = page.getByRole("dialog");
      await review
        .getByRole("heading", { name: "Recover this check?", exact: true })
        .waitFor();
      assert.equal(
        await page.evaluate(() => document.activeElement?.id),
        "recovery-title",
      );
      await review.getByText(d.expected_worker_id, { exact: true }).waitFor();
      await review.getByText(c.sourceSHA256, { exact: true }).waitFor();
      await audit("recovery-review");
      await page.screenshot({
        path: c.raw + "/recovery-review.png",
        fullPage: true,
      });
      let lost, retry;
      const dropped = new Promise((resolve) => {
          lost = resolve;
        }),
        replayed = new Promise((resolve) => {
          retry = resolve;
        }),
        keys = [];
      await page.route("**/checks/*/recover", async (route) => {
        keys.push(route.request().headers()["idempotency-key"]);
        try {
          const response = await trustedMutation(
            route,
            "recovery-loss-" + keys.length,
          );
          if (keys.length === 1) {
            await route.abort("failed");
            lost(response.status);
          } else {
            await route.fulfill({
              status: response.status,
              contentType: "application/json",
              body: response.body,
            });
            retry({
              status: response.status,
              replayed: JSON.parse(response.body).replayed,
              keys: [...keys],
            });
          }
        } catch {
          await route.abort("failed").catch(() => {});
          lost(0);
          retry({ status: 0, keys: [...keys] });
        }
      });
      await review
        .getByRole("button", { name: "Start replacement check", exact: true })
        .click();
      assert.equal(await dropped, 200);
      await review
        .getByRole("alert")
        .filter({ hasText: "Recovery was not confirmed" })
        .waitFor();
      await review
        .getByRole("button", { name: "Retry reviewed recovery", exact: true })
        .click();
      const replay = await replayed;
      assert.equal(replay.status, 200);
      assert.equal(replay.replayed, true);
      assert.equal(replay.keys[1], replay.keys[0]);
      await writeFile(
        c.raw + "/recovery-response-loss.json",
        JSON.stringify(replay, null, 2) + "\n",
      );
      await page.unroute("**/checks/*/recover");
      await page
        .getByText(
          "Validation passed. These bytes remain held until you approve release.",
          { exact: true },
        )
        .waitFor();
      const completed = await read();
      assert.equal(completed.check.attempts, 2);
      assert.equal(completed.check.report.rows, 900000);
      assert.equal(completed.check.report.sha256, c.sourceSHA256);
      await writeFile(
        c.raw + "/recovered-check.json",
        JSON.stringify(completed, null, 2) + "\n",
      );
      record(
        "browser-replacement-attempt-two-checks-original-bytes-and-replays-one-receipt",
      );
      const held = await page.evaluate(
        async ({ url, id }) => (await fetch(url + "/files/" + id)).status,
        { url: prefix(), id: c.fileID },
      );
      assert.equal(held, 409);
      await page
        .getByRole("button", { name: "Review release", exact: true })
        .click();
      await page
        .getByRole("dialog")
        .getByRole("button", { name: "Release file", exact: true })
        .click();
      await page
        .getByText(
          "Released under this intake policy. Current access and policy checks still apply.",
          { exact: true },
        )
        .waitFor();
      await page.getByRole("button", { name: "Files", exact: true }).click();
      const row = page.getByRole("row").filter({ hasText: "recovery.csv" });
      const downloaded = page.waitForEvent("download");
      await row
        .getByRole("link", { name: "Download recovery.csv", exact: true })
        .click();
      const file = await downloaded;
      assert.equal(await file.failure(), null);
      await file.saveAs(c.private + "/browser-recovered.csv");
      assert.equal(
        await digestFile(c.private + "/browser-recovered.csv"),
        c.sourceSHA256,
      );
      record(
        "recovered-file-needs-separate-release-and-native-download-matches-exact-source",
      );
      await page.getByRole("button", { name: "Sign out", exact: true }).click();
      await signIn(1);
      assert.equal(await post(d, "other-actor"), 404);
      record("other-partner-actor-cannot-recover-private-check");
      await page.getByRole("button", { name: "Sign out", exact: true }).click();
    }
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
