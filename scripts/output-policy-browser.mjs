// Actual native Chrome/HTTPS/PostgreSQL administrator profile. A stock curl
// request commits the original registration before its browser reply is lost.
import assert from "node:assert/strict";
import { createHash, X509Certificate } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
process.umask(0o077);
assert.equal(process.env.GITHUB_ACTIONS, "true");
assert.equal(process.platform, "linux");
assert.equal(process.arch, "x64");
assert.equal(process.env.FREIGHTCTL_BROWSER_CHANNEL, "chrome");
const c = JSON.parse(await readFile(process.argv[2], "utf8"));
assert.equal(new URL(c.url).protocol, "https:");
assert.equal(new URL(c.url).hostname, "127.0.0.1");
const require = createRequire(import.meta.url),
  { chromium } = require("../web/node_modules/playwright"),
  sha = (b) => createHash("sha256").update(b).digest("hex"),
  cert = new X509Certificate(Buffer.from(c.certificate_der, "base64")),
  spki = createHash("sha256")
    .update(cert.publicKey.export({ type: "spki", format: "der" }))
    .digest("base64"),
  ca = c.private + "/fixture-ca.pem",
  prefix = `/v1/tenants/${c.tenant}/partners/${c.partner}`;
await writeFile(ca, cert.toString());
let browser,
  policy = "",
  egress = 0,
  errors = 0,
  accessibility = 0,
  state = "failed",
  failure = "";
const registrations = [];
try {
  browser = await chromium.launch({
    channel: "chrome",
    headless: true,
    chromiumSandbox: true,
    args: ["--ignore-certificate-errors-spki-list=" + spki],
  });
  const context = await browser.newContext({
    acceptDownloads: true,
    serviceWorkers: "block",
  });
  await context.route("**/*", async (route) => {
    if (new URL(route.request().url()).origin !== c.url) {
      egress++;
      await route.abort("blockedbyclient");
    } else await route.continue();
  });
  const page = await context.newPage();
  page.on("pageerror", () => errors++);
  const button = (name, scope = page) =>
      scope.getByRole("button", { name, exact: true }),
    region = () =>
      page.getByRole("region", {
        name: "Producer output policy administration",
        exact: true,
      }),
    dialog = () =>
      page.getByRole("dialog", {
        name: "Review output contract registration",
        exact: true,
      });
  async function audit(label) {
    await page.evaluate(
      await readFile(
        new URL("../web/node_modules/axe-core/axe.min.js", import.meta.url),
        "utf8",
      ),
    );
    const report = await page.evaluate(async () => {
      const result = await window.axe.run(document, {
        runOnly: {
          type: "tag",
          values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"],
        },
      });
      return { passes: result.passes.length, violations: result.violations };
    });
    await writeFile(
      c.private + "/" + label + "-axe.json",
      JSON.stringify(report),
    );
    assert.equal(report.violations.length, 0);
    assert.ok(report.passes > 0);
    accessibility++;
  }
  await page.goto(c.url);
  await page.getByLabel("Tenant ID", { exact: true }).fill(c.tenant);
  await page.getByLabel("Partner ID", { exact: true }).fill(c.partner);
  await page
    .getByLabel("Account credential file", { exact: true })
    .setInputFiles(c.token);
  await button("Connect").click();
  await button("Intake policy").click();
  await region().waitFor();
  await region()
    .getByLabel("Producer account ID", { exact: true })
    .fill(c.producer);
  await region()
    .getByLabel("Output checking definition JSON", { exact: true })
    .setInputFiles(c.definition);
  await region().getByText(c.definition_hash, { exact: true }).waitFor();
  await button("Review output contract registration", region()).click();
  await dialog().waitFor();
  await audit("output-policy-registration-review");
  const url = c.url + prefix + "/processing-output-policies";
  const loseFirst = async (route) => {
    const request = route.request();
    if (request.method() !== "POST") {
      await route.continue();
      return;
    }
    assert.equal(request.url(), url);
    const body = request.postDataBuffer(),
      headers = Object.entries(await request.allHeaders()).filter(([k]) =>
        [
          "content-type",
          "idempotency-key",
          "cookie",
          "origin",
          "x-csrf-token",
        ].includes(k),
      ),
      base = c.private + "/registration-" + registrations.length;
    assert.ok(body && body.length <= 32768);
    await writeFile(base + ".request", body);
    await writeFile(
      base + ".headers",
      headers.map(([k, v]) => k + ": " + v).join("\n") + "\n",
    );
    const code = execFileSync(
      "curl",
      [
        "-q",
        "--silent",
        "--show-error",
        "--noproxy",
        "*",
        "--proto",
        "=https",
        "--cacert",
        ca,
        "--max-time",
        "20",
        "--request",
        "POST",
        "--header",
        "@" + base + ".headers",
        "--data-binary",
        "@" + base + ".request",
        "--output",
        base + ".response",
        "--write-out",
        "%{http_code}",
        url,
      ],
      { encoding: "utf8", maxBuffer: 65536 },
    );
    assert.equal(code, "200");
    const raw = await readFile(base + ".response"),
      reply = JSON.parse(raw);
    assert.equal(reply.resource.ingress_changed, false);
    assert.equal(reply.resource.binding.producer.actor_id, c.producer);
    assert.equal(reply.resource.binding.publisher_id, c.publisher);
    assert.equal(reply.resource.policy.definition_hash, c.definition_hash);
    registrations.push({
      key: headers.find(([k]) => k === "idempotency-key")?.[1],
      body: JSON.parse(body),
      reply,
    });
    policy = reply.resource.policy.id;
    if (registrations.length === 1) await route.abort("failed");
    else
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: raw,
      });
  };
  await page.route(url, loseFirst);
  await button("Register reviewed output contract", dialog()).click();
  await dialog()
    .getByText(/This command is not confirmed/)
    .waitFor();
  const downloaded = page.waitForEvent("download");
  await button("Save exact output policy request", dialog()).click();
  const recovery = c.private + "/saved-request.json";
  await (await downloaded).saveAs(recovery);
  const saved = JSON.parse(await readFile(recovery, "utf8"));
  assert.equal(JSON.stringify(saved).includes("csrf"), false);
  assert.equal(saved.request.key, registrations[0].key);
  await page.reload();
  await button("Intake policy").click();
  await region().waitFor();
  await region()
    .getByLabel("Open output policy recovery JSON", { exact: true })
    .setInputFiles(recovery);
  await dialog().waitFor();
  assert.equal(registrations.length, 1);
  await audit("output-policy-recovery-review");
  await button("Retry exact output policy command", dialog()).click();
  await page
    .getByRole("region", {
      name: "Original output policy command receipt",
      exact: true,
    })
    .waitFor();
  assert.equal(registrations.length, 2);
  assert.equal(registrations[1].reply.replayed, true);
  assert.equal(registrations[0].key, registrations[1].key);
  assert.deepEqual(registrations[0].body, registrations[1].body);
  assert.equal(
    registrations[0].reply.resource.policy.id,
    registrations[1].reply.resource.policy.id,
  );
  await page.unroute(url, loseFirst);
  const current = () =>
    page.getByRole("region", { name: "Current output contract", exact: true });
  await current()
    .getByText(/output_active/)
    .waitFor();
  await button("Review output contract revocation", current()).click();
  const revoke = page.getByRole("dialog", {
    name: "Review output contract revocation",
    exact: true,
  });
  await revoke.waitFor();
  await audit("output-policy-revocation-review");
  await button("Revoke reviewed output contract", revoke).click();
  await current()
    .getByText(/output_revoked/)
    .waitFor();
  await audit("output-policy-revoked-current");
  assert.equal(egress, 0);
  assert.equal(errors, 0);
  state = "passed";
} catch (error) {
  const raw = String(error.stack ?? error);
  failure = sha(raw);
  await writeFile(c.private + "/failure.log", raw);
} finally {
  if (browser) await browser.close();
  await writeFile(
    c.result,
    JSON.stringify({
      state,
      policy,
      registration_requests: registrations.length,
      accessibility_checks: accessibility,
      external_egress: egress,
      runtime_errors: errors,
      browser_sandbox: true,
      inference_performed: false,
      failure_sha256: failure,
    }) + "\n",
  );
}
if (state !== "passed") process.exitCode = 1;
