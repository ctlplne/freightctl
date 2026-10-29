import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { X509Certificate, createHash } from "node:crypto";
import { createRequire } from "node:module";
process.umask(0o077);
const require = createRequire(import.meta.url),
  { chromium } = require("../web/node_modules/playwright");
const c = JSON.parse(await readFile(process.argv[2], "utf8"));
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
const context = await browser.newContext({
    viewport: { width: 1320, height: 950 },
  }),
  page = await context.newPage(),
  steps = [],
  errors = [],
  egress = [];
page.setDefaultTimeout(15000);
page.on("pageerror", (e) => errors.push(e.message));
page.on("request", (r) => {
  if (!r.url().startsWith(c.url + "/")) egress.push(new URL(r.url()).origin);
});
const prefix = `/v1/tenants/${c.tenant}/partners/${c.partner}`;
const record = (name, extra = {}) => {
  steps.push({ name, ...extra });
  console.log("passed: " + name);
};
let child,
  state = "failed",
  failure;
async function api(route, method = "GET", body, csrf = true) {
  return page.evaluate(
    async ({ route, method, body, csrf }) => {
      const session = await (await fetch("/v1/browser/session")).json();
      const r = await fetch(route, {
        method,
        credentials: "same-origin",
        headers: {
          ...(method === "GET"
            ? {}
            : {
                "Content-Type": "application/json",
                "Idempotency-Key": crypto.randomUUID(),
                ...(csrf ? { "X-CSRF-Token": session.csrf_token } : {}),
              }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      return { status: r.status, body: await r.json() };
    },
    { route: prefix + route, method, body, csrf },
  );
}
async function audit(label) {
  await page.evaluate(
    await readFile(c.root + "/web/node_modules/axe-core/axe.min.js", "utf8"),
  );
  const result = await page.evaluate(async () => {
    const r = await window.axe.run(document, {
      runOnly: {
        type: "tag",
        values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"],
      },
    });
    return {
      passes: r.passes.length,
      violations: r.violations.map((v) => ({
        id: v.id,
        impact: v.impact,
        nodes: v.nodes.map((n) => ({
          target: n.target,
          failureSummary: n.failureSummary,
        })),
      })),
    };
  });
  await writeFile(
    c.raw + "/" + label + "-axe.json",
    JSON.stringify(result, null, 2) + "\n",
  );
  assert.equal(result.violations.length, 0);
  record(label + "-axe", { passes: result.passes });
}
async function loseOnce(pattern, label) {
  let saved;
  await page.route(c.url + prefix + pattern, async (route) => {
    const req = route.request();
    if (req.method() !== "POST" || saved) {
      await route.continue();
      return;
    }
    const headers = c.private + "/" + label + ".headers",
      body = c.private + "/" + label + ".request",
      output = c.private + "/" + label + ".response";
    await writeFile(
      headers,
      Object.entries(req.headers())
        .filter(
          ([k]) =>
            ![
              "host",
              "connection",
              "content-length",
              "transfer-encoding",
            ].includes(k),
        )
        .map(([k, v]) => k + ": " + v)
        .join("\n") + "\n",
    );
    const bytes = req.postDataBuffer() ?? Buffer.alloc(0);
    assert.ok(bytes.length <= 32768);
    await writeFile(body, bytes);
    const code = Number(
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
          req.url(),
        ],
        { encoding: "utf8", timeout: 90000, maxBuffer: 4096 },
      ),
    );
    assert.equal(code, 200);
    saved = {
      key: req.headers()["idempotency-key"],
      value: JSON.parse(await readFile(output, "utf8")),
    };
    await route.abort("connectionfailed");
  });
  return () => saved;
}
async function enabled(locator) {
  await locator.waitFor();
  await page.waitForFunction(
    (el) => !el.disabled,
    await locator.elementHandle(),
  );
}
try {
  await page.goto(c.url);
  await page.getByLabel("Tenant ID", { exact: true }).fill(c.tenant);
  await page.getByLabel("Partner ID", { exact: true }).fill(c.partner);
  await page
    .getByLabel("Account credential file", { exact: true })
    .setInputFiles(c.token);
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
  await page
    .getByRole("button", { name: "Intake checks", exact: true })
    .click();
  const section = page.getByRole("region", { name: "Governed file re-checks" });
  await section
    .getByLabel("Source file revision", { exact: true })
    .fill(c.source);
  await section
    .getByLabel("Target path after separate release", { exact: true })
    .fill(c.target);
  await section
    .getByLabel("Reason", { exact: true })
    .fill("Fresh approved checks under the selected current policy");
  assert.equal(
    (
      await api(
        "/checks/" + c.source + "/recheck-preview",
        "POST",
        {
          target_path: c.target,
          signature_mode: "not_required",
          reason: "CSRF refusal remains required",
        },
        false,
      )
    ).status,
    403,
  );
  record("rechecks-browser-csrf-refusal");
  await section
    .getByRole("button", { name: "Preview re-check request", exact: true })
    .click();
  let dialog = page.locator("dialog[open]");
  await dialog
    .getByRole("heading", { name: "Save this immutable request", exact: true })
    .waitFor();
  assert.equal(
    await dialog
      .getByRole("heading")
      .evaluate((el) => document.activeElement === el),
    true,
  );
  await audit("recheck-save-review");
  await page.screenshot({
    path: c.raw + "/recheck-save-review.png",
    fullPage: true,
  });
  const lostProposal = await loseOnce(
    "/checks/" + c.source + "/rechecks",
    "recheck-browser-save-loss",
  );
  await dialog
    .getByRole("button", { name: "Save reviewed request", exact: true })
    .click();
  await dialog.getByText(/The result was not confirmed/).waitFor();
  const saved = lostProposal();
  assert.ok(saved);
  await enabled(
    dialog.getByRole("button", { name: "Save reviewed request", exact: true }),
  );
  await dialog
    .getByRole("button", { name: "Save reviewed request", exact: true })
    .click();
  await page
    .getByRole("heading", { name: "Selected re-check: proposed", exact: true })
    .waitFor();
  const row = saved.value.resource.recheck;
  record("rechecks-browser-proposal-response-loss-original-key", {
    id: row.id,
  });
  await page.reload();
  await page
    .getByRole("button", { name: "Intake checks", exact: true })
    .click();
  await section
    .getByLabel("Source file revision", { exact: true })
    .fill(c.source);
  await section
    .getByRole("button", { name: "proposed · " + row.id, exact: true })
    .click();
  await page
    .getByRole("heading", { name: "Selected re-check: proposed", exact: true })
    .waitFor();
  await page.waitForFunction(
    (el) => document.activeElement === el,
    await page
      .getByRole("heading", {
        name: "Selected re-check: proposed",
        exact: true,
      })
      .elementHandle(),
  );
  assert.equal(
    await page
      .getByRole("heading", {
        name: "Selected re-check: proposed",
        exact: true,
      })
      .evaluate((el) => document.activeElement === el),
    true,
  );
  record("rechecks-browser-private-history-after-reload");
  const lostApproval = await loseOnce(
    "/rechecks/" + row.id + "/decide",
    "recheck-browser-approval-loss",
  );
  await section
    .getByRole("button", { name: "Review re-check approval", exact: true })
    .click();
  await dialog
    .getByRole("heading", { name: "Approve this re-check", exact: true })
    .waitFor();
  await audit("recheck-approval-review");
  await dialog
    .getByRole("button", { name: "Approve exact re-check", exact: true })
    .click();
  await dialog.getByText(/The result was not confirmed/).waitFor();
  assert.ok(lostApproval());
  await enabled(
    dialog.getByRole("button", { name: "Approve exact re-check", exact: true }),
  );
  await dialog
    .getByRole("button", { name: "Approve exact re-check", exact: true })
    .click();
  await page
    .getByRole("heading", { name: "Selected re-check: approved", exact: true })
    .waitFor();
  record("rechecks-browser-approval-response-loss-original-key");
  const lostCopy = await loseOnce(
    "/rechecks/" + row.id + "/copy",
    "recheck-browser-copy-loss",
  );
  await section
    .getByRole("button", { name: "Review held copy", exact: true })
    .click();
  await dialog
    .getByRole("heading", {
      name: "Create a held checked revision",
      exact: true,
    })
    .waitFor();
  await dialog
    .getByRole("button", { name: "Create held revision", exact: true })
    .click();
  await dialog.getByText(/The result was not confirmed/).waitFor();
  assert.ok(lostCopy());
  await enabled(
    dialog.getByRole("button", { name: "Create held revision", exact: true }),
  );
  await dialog
    .getByRole("button", { name: "Create held revision", exact: true })
    .click();
  await page
    .getByRole("heading", { name: "Selected re-check: copied", exact: true })
    .waitFor();
  child = lostCopy().value.resource.recheck.new_file_id;
  assert.equal((await api("/files/" + child)).status, 409);
  record("rechecks-browser-copy-response-loss-remains-held", {
    file_id: child,
  });
  await section
    .getByRole("button", { name: "Open new checked revision", exact: true })
    .click();
  await enabled(
    page.getByRole("button", { name: "Run required checks", exact: true }),
  );
  await page
    .getByRole("button", { name: "Run required checks", exact: true })
    .click();
  await enabled(
    page.getByRole("button", { name: "Review release", exact: true }),
  );
  assert.equal((await api("/files/" + child)).status, 409);
  await page
    .getByRole("button", { name: "Review release", exact: true })
    .click();
  await page.getByRole("button", { name: "Release file", exact: true }).click();
  await page.waitForFunction(() => !document.querySelector("dialog[open]"));
  const checked = await api("/checks/" + child);
  assert.equal(checked.status, 200);
  assert.equal(checked.body.check.state, "released");
  assert.equal(checked.body.check.attempts, 1);
  record("rechecks-browser-separate-fresh-check-and-exact-release");
  await audit("recheck-released-result");
  await page.screenshot({
    path: c.raw + "/recheck-released-result.png",
    fullPage: true,
  });
  assert.deepEqual(errors, []);
  assert.deepEqual(egress, []);
  state = "passed";
} catch (e) {
  failure = e.stack;
  await page
    .screenshot({
      path: c.raw + "/recheck-browser-failure.png",
      fullPage: true,
    })
    .catch(() => {});
  throw e;
} finally {
  await writeFile(
    c.raw + "/rechecks-browser.json",
    JSON.stringify(
      {
        state,
        new_file_id: child,
        steps,
        runtime_errors: errors,
        unexpected_egress: egress,
        failure,
      },
      null,
      2,
    ) + "\n",
  );
  await browser.close();
}
