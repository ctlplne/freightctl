// Actual native Chrome/HTTPS/PG proof. Only the first committed policy reply
// is discarded; all requests execute against the real service.
import assert from "node:assert/strict";
import { createHash, X509Certificate } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import {
  nativeUploadCompletionResponse,
  nativeWireObservation,
} from "./browser-native-wire.mjs";

process.umask(0o077);
assert.equal(process.env.GITHUB_ACTIONS, "true");
assert.equal(process.platform, "linux");
assert.equal(process.arch, "x64");
assert.equal(process.env.FREIGHTCTL_BROWSER_CHANNEL, "chrome");
const c = JSON.parse(await readFile(process.argv[2], "utf8"));
assert.ok(
  c.format === "json_records" ||
    c.format === "fixed_width" ||
    c.format === "xml_records" ||
    c.format === "xlsx_records",
);
const fixed = c.format === "fixed_width",
  xmlRecords = c.format === "xml_records",
  xlsxRecords = c.format === "xlsx_records",
  schema = xlsxRecords ? 5 : xmlRecords ? 4 : fixed ? 3 : 2,
  code = xlsxRecords
    ? "valid_xlsx_records"
    : xmlRecords
      ? "valid_xml_records"
      : fixed
        ? "valid_fixed_width"
        : "valid_json_records",
  engine = xlsxRecords
    ? "freightctl-xlsx-records-v1"
    : xmlRecords
      ? "freightctl-xml-records-v1"
      : fixed
        ? "freightctl-fixed-width-v1"
        : "freightctl-json-records-v1",
  policyPrefix = xlsxRecords
    ? "intake-xlsx-records-v1:"
    : xmlRecords
      ? "intake-xml-records-v1:"
      : fixed
        ? "intake-fixed-width-v1:"
        : "intake-json-records-v1:";
assert.equal(new URL(c.url).protocol, "https:");
assert.equal(new URL(c.url).hostname, "127.0.0.1");
const require = createRequire(import.meta.url);
const { chromium } = require("../web/node_modules/playwright");
const axe = require("../web/node_modules/axe-core");
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const cert = new X509Certificate(Buffer.from(c.certificate_der, "base64"));
const spki = createHash("sha256")
  .update(cert.publicKey.export({ type: "spki", format: "der" }))
  .digest("base64");
const ca = c.private + "/fixture-ca.pem";
await writeFile(ca, cert.toString());
const prefix = `/v1/tenants/${c.tenant}/partners/${c.partner}`;
let browser,
  file = "",
  policyHash = "",
  state = "failed",
  failureHash = "",
  stage = "launch";
let accessibility = 0,
  egress = 0,
  errors = 0;
const policyRequests = [];
try {
  browser = await chromium.launch({
    headless: true,
    chromiumSandbox: true,
    channel: "chrome",
    args: [
      "--ignore-certificate-errors-spki-list=" + spki,
      "--disable-background-networking",
      "--disable-component-update",
    ],
  });
  process.once("SIGINT", async () => {
    await browser.close();
    process.exit(1);
  });
  const context = await browser.newContext({
    viewport: { width: 1320, height: 950 },
  });
  const page = await context.newPage();
  page.setDefaultTimeout(15000);
  page.on("pageerror", () => errors++);
  page.on("request", (request) => {
    if (new URL(request.url()).origin !== c.url) egress++;
  });
  const button = (name, parent = page) =>
    parent.getByRole("button", { name, exact: true });
  const dialog = () => page.getByRole("dialog");
  async function audit(label) {
    stage = "accessibility";
    await page.evaluate(
      await readFile(
        new URL("../web/node_modules/axe-core/axe.min.js", import.meta.url),
        "utf8",
      ),
    );
    const report = await page.evaluate(async () => {
      const r = await window.axe.run(document, {
        runOnly: {
          type: "tag",
          values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"],
        },
      });
      return { passes: r.passes.length, violations: r.violations };
    });
    await writeFile(
      c.private + "/" + label + "-axe.json",
      JSON.stringify(report),
    );
    assert.equal(report.violations.length, 0);
    assert.ok(report.passes > 0);
    accessibility++;
  }
  async function api(path, method = "GET", binary = false) {
    return page.evaluate(
      async ({ path, method, binary }) => {
        const response = await fetch(path, {
          method,
          credentials: "same-origin",
        });
        return {
          status: response.status,
          body: binary
            ? Array.from(new Uint8Array(await response.arrayBuffer()))
            : await response.text(),
        };
      },
      { path: prefix + path, method, binary },
    );
  }
  stage = "login";
  await page.goto(c.url);
  await page.getByLabel("Tenant ID", { exact: true }).fill(c.tenant);
  await page.getByLabel("Partner ID", { exact: true }).fill(c.partner);
  await page
    .getByLabel("Account credential file", { exact: true })
    .setInputFiles(c.token);
  await button("Connect").click();
  await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
  stage = "open-policy";
  await button("Intake policy").click();
  const editor = page.getByRole("region", { name: "Incoming file policy" });
  stage = "edit-policy";
  await editor
    .getByRole("combobox", { name: "File format", exact: true })
    .selectOption(c.format);
  if (fixed)
    await editor
      .getByRole("combobox", { name: "Column 2 padding", exact: true })
      .selectOption("space_left");
  await audit("json-editor");
  stage = "review-policy";
  await button("Review intake policy", editor).click();
  await dialog()
    .getByText(
      xlsxRecords
        ? "XLSX worksheet records"
        : xmlRecords
          ? "XML records"
          : fixed
            ? "Fixed-width records"
            : "JSON record array",
      {
        exact: false,
      },
    )
    .waitFor();
  assert.ok(
    (await dialog().locator("code").allTextContents()).includes(c.hash),
  );
  await audit("json-review");
  const policyURL = c.url + prefix + "/intake-policy";
  const loseFirst = async (route) => {
    const request = route.request();
    if (request.method() !== "POST") {
      await route.continue();
      return;
    }
    assert.equal(request.url(), policyURL);
    const body = request.postDataBuffer();
    assert.ok(body && body.length <= 16384);
    const headers = Object.entries(await request.allHeaders()).filter(
      ([name]) =>
        [
          "content-type",
          "idempotency-key",
          "cookie",
          "origin",
          "x-csrf-token",
        ].includes(name),
    );
    const base = c.private + "/policy-" + policyRequests.length;
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
        policyURL,
      ],
      { encoding: "utf8", maxBuffer: 65536 },
    );
    assert.equal(code, "200");
    const reply = await readFile(base + ".response");
    assert.ok(reply.length <= 32768);
    policyRequests.push({
      key: headers.find(([k]) => k === "idempotency-key")?.[1],
      request: JSON.parse(body),
      response: JSON.parse(reply),
    });
    if (policyRequests.length === 1) await route.abort("failed");
    else
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: reply,
      });
  };
  stage = "commit-policy-loss";
  await page.route(policyURL, loseFirst);
  await button("Apply reviewed policy", dialog()).click();
  await dialog().getByRole("alert").waitFor();
  await audit("json-uncertain-policy");
  stage = "retry-policy";
  await button("Apply reviewed policy", dialog()).click();
  await dialog().waitFor({ state: "hidden" });
  await page.unroute(policyURL, loseFirst);
  assert.equal(policyRequests.length, 2);
  assert.ok(policyRequests[0].key);
  assert.equal(policyRequests[0].key, policyRequests[1].key);
  assert.deepEqual(policyRequests[0].request, policyRequests[1].request);
  assert.equal(policyRequests[0].request.expected_version, 1);
  assert.equal(policyRequests[0].request.definition.schema_version, schema);
  assert.equal(policyRequests[0].request.definition.kind, c.format);
  const original = policyRequests[0].response;
  assert.equal(original.replayed, false);
  assert.deepEqual(policyRequests[1].response, { ...original, replayed: true });
  assert.equal(original.resource.version, 2);
  assert.equal(original.resource.definition_hash, c.hash);
  policyHash = original.resource.definition_hash;

  stage = "upload";
  await button("Files").click();
  await button("Upload file").click();
  await page
    .getByLabel("File to send", { exact: true })
    .setInputFiles(c.source);
  await page
    .getByLabel("Destination path", { exact: true })
    .fill("/browser-records.json");
  const accepted = await nativeUploadCompletionResponse(
    page,
    { origin: c.url, tenant: c.tenant, partner: c.partner },
    () => button("Start upload").click(),
    async (observed, _label, target) => {
      const request = observed.request();
      assert.equal(request.url(), target);
      assert.equal(request.method(), "POST");
      assert.equal(request.postDataBuffer().length, 0);
      const id = new URL(target).pathname.split("/").at(-2);
      const headers = await request.allHeaders();
      assert.equal(headers["idempotency-key"], "browser-complete-" + id);
      const original = observed[nativeWireObservation];
      assert.equal(original.status, 200);
      assert.equal(JSON.parse(original.body).upload.id, id);
      return original;
    },
    "intake-upload-complete",
  );
  assert.equal(accepted.acceptance, "durable-held-pending-checks-and-release");
  assert.equal(accepted.file.policy, policyPrefix + c.hash);
  assert.equal(accepted.upload.expected_sha256, c.sha256);
  assert.equal(accepted.upload.committed_offset, c.size);
  file = accepted.file.id;
  assert.equal((await api("/files/" + file)).status, 409);
  assert.equal((await api("/files/" + file, "HEAD")).status, 409);
  stage = "check";
  await button("Intake checks").click();
  await page
    .getByRole("row")
    .filter({ hasText: "/browser-records.json" })
    .getByRole("button", { name: "Inspect check", exact: true })
    .click();
  const run = page.waitForResponse(
    (r) =>
      r.url() === c.url + prefix + "/checks/" + file + "/run" &&
      r.request().method() === "POST",
  );
  await button("Run required checks").click();
  assert.equal((await run).status(), 200);
  await page
    .getByText(
      "Validation passed. These bytes remain held until you approve release.",
      { exact: true },
    )
    .waitFor();
  const detail = JSON.parse((await api("/checks/" + file)).body);
  assert.equal(detail.check.state, "passed");
  assert.equal(detail.check.attempts, 1);
  assert.equal(detail.check.report.engine, engine);
  assert.equal(detail.check.report.code, code);
  assert.equal(detail.check.report.rows, 1);
  assert.equal(detail.check.report.bytes_read, c.size);
  assert.equal((await api("/files/" + file)).status, 409);
  await audit("json-passed-held");
  stage = "review-release";
  await button("Review release").click();
  assert.ok(
    (await dialog().locator("code").allTextContents()).includes(
      detail.check.report_hash,
    ),
  );
  await audit("json-release-review");
  stage = "release";
  const release = page.waitForResponse(
    (r) =>
      r.url() === c.url + prefix + "/checks/" + file + "/release" &&
      r.request().method() === "POST",
  );
  await button("Release file", dialog()).click();
  assert.equal((await release).status(), 200);
  await dialog().waitFor({ state: "hidden" });
  stage = "download";
  const download = await api(
    "/namespace/file?path=/browser-records.json",
    "GET",
    true,
  );
  assert.equal(download.status, 200);
  assert.equal(sha(Buffer.from(download.body)), c.sha256);
  assert.equal(errors, 0);
  assert.equal(egress, 0);
  assert.equal(accessibility, 5);
  state = "passed";
} catch (error) {
  const raw = String(error.stack ?? error);
  failureHash = sha(raw);
  await writeFile(c.private + "/failure.log", raw);
} finally {
  const version = browser?.version() ?? "";
  if (browser) await browser.close();
  await writeFile(
    c.result,
    JSON.stringify({
      state,
      file,
      policy_hash: policyHash,
      policy_requests: policyRequests.length,
      accessibility_checks: accessibility,
      external_egress: egress,
      runtime_errors: errors,
      browser_sandbox: true,
      inference_performed: false,
      browser_version: version,
      node_version: process.version,
      axe_version: axe.version,
      failure_sha256: failureHash,
      failed_stage: state === "passed" ? "" : stage,
    }) + "\n",
  );
}
if (state !== "passed") process.exitCode = 1;
