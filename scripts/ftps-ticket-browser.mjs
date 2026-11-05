// Actual browser/HTTPS operator actions coordinated with an external FTPS peer.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile, open } from "node:fs/promises";
import { createHash, X509Certificate } from "node:crypto";
import { createRequire } from "node:module";
import { createInterface } from "node:readline";
import { wireResponse } from "./browser-wire.mjs";
process.umask(0o077);
const rawConfig = await readFile(process.argv.at(-1));
const c = JSON.parse(rawConfig);
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
assert.equal(new URL(c.url).hostname, "127.0.0.1");
const payload = await readFile(c.source);
assert.ok(payload.length > 65536 && payload.length <= 1048576);
const expectedHash = sha(payload);
const emit = (state, fields = {}) =>
  console.log(JSON.stringify({ state, ...fields }));
async function save(name, bytes) {
  const file = await open(c.private + "/" + name, "wx");
  try {
    await file.writeFile(bytes);
    await file.sync();
  } finally {
    await file.close();
  }
}
await save("config.json", rawConfig);
const commands = [],
  queue = [];
let pending, stopping;
const input = createInterface({ input: process.stdin });
function failPending(error) {
  stopping = error;
  if (pending) {
    pending.reject(error);
    pending = undefined;
  }
}
input.on("line", (line) => {
  try {
    assert.ok(line.length <= 1024 && queue.length < 4);
    const message = JSON.parse(line);
    assert.deepEqual(Object.keys(message), ["action"]);
    if (pending) {
      const p = pending;
      pending = undefined;
      p.resolve(message);
    } else queue.push(message);
  } catch {
    failPending(new Error("invalid controller phase"));
  }
});
process.once("SIGTERM", () => failPending(new Error("controller canceled")));
async function phase(action) {
  if (stopping) throw stopping;
  let timer;
  try {
    const message = queue.length
      ? queue.shift()
      : await new Promise((resolve, reject) => {
          pending = { resolve, reject };
          timer = setTimeout(
            () => failPending(new Error("controller phase deadline")),
            45000,
          );
        });
    assert.deepEqual(message, { action });
    commands.push(action);
  } finally {
    clearTimeout(timer);
  }
}
const { chromium } = createRequire(import.meta.url)(
  "../web/node_modules/playwright",
);
assert.ok(
  !process.env.FREIGHTCTL_BROWSER_CHANNEL ||
    process.env.FREIGHTCTL_BROWSER_CHANNEL === "chrome",
);
const spki = createHash("sha256")
  .update(
    new X509Certificate(await readFile(c.certificate)).publicKey.export({
      format: "der",
      type: "spki",
    }),
  )
  .digest("base64");
const browser = await chromium.launch({
  headless: true,
  chromiumSandbox: true,
  ...(process.env.FREIGHTCTL_BROWSER_CHANNEL ? { channel: "chrome" } : {}),
  args: [
    "--ignore-certificate-errors-spki-list=" + spki,
    "--disable-background-networking",
    "--disable-component-update",
    ...(process.env.GITHUB_ACTIONS === "true" ? [] : ["--renderer-process-limit=1", "--js-flags=--max-old-space-size=128"]),
  ],
});
let context,
  page,
  stage = "prepare",
  state = "failed",
  failure,
  ident,
  accepted;
const responses = [],
  errors = [],
  egress = [],
  mutations = [],
  audits = [];
const prefix =
  c.url + `/v1/tenants/${c.owner.tenant}/partners/${c.owner.partner}`;
const button = (name, within = page) =>
  within.getByRole("button", { name, exact: true });
async function signIn(who) {
  if (context) {
    assert.deepEqual(
      await page.evaluate(() => [localStorage.length, sessionStorage.length]),
      [0, 0],
    );
    await context.close();
  }
  context = await browser.newContext({
    viewport: { width: 1320, height: 950 },
  });
  page = await context.newPage();
  page.setDefaultTimeout(15000);
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("request", (r) => {
    if (new URL(r.url()).origin !== c.url) egress.push(new URL(r.url()).origin);
    if (r.url().startsWith(prefix + "/uploads") && r.method() !== "GET")
      mutations.push({ method: r.method(), url: r.url() });
  });
  await page.goto(c.url);
  await page.getByLabel("Tenant ID", { exact: true }).fill(who.tenant);
  await page.getByLabel("Partner ID", { exact: true }).fill(who.partner);
  await page
    .getByLabel("Account credential file", { exact: true })
    .setInputFiles(who.token);
  await button("Connect").click();
  await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
}
async function audit(name) {
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
      violations: r.violations.map((v) => ({
        id: v.id,
        impact: v.impact,
        targets: v.nodes.map((n) => n.target),
      })),
      passes: r.passes.length,
    };
  });
  await save(name + "-axe.json", JSON.stringify(result));
  assert.equal(result.violations.length, 0);
  assert.ok(result.passes > 0);
  audits.push(name);
}
async function actual(route, label, target, expected = 200) {
  const request = route.request();
  assert.equal(request.url(), target);
  assert.ok(target.startsWith(prefix + "/"));
  assert.ok(["GET", "POST"].includes(request.method()));
  const fields = Object.entries(await request.allHeaders()).filter(
    ([k]) =>
      !["host", "connection", "content-length", "transfer-encoding"].includes(
        k,
      ),
  );
  const bytes = request.postDataBuffer() ?? Buffer.alloc(0);
  assert.ok(bytes.length <= 32768);
  await save(
    label + ".headers",
    fields.map(([k, v]) => k + ": " + v).join("\n") + "\n",
  );
  await save(label + ".request", bytes);
  const output = c.private + "/" + label + ".response";
  const status = Number(
    execFileSync(
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
        c.certificate,
        "--max-time",
        "12",
        "--max-filesize",
        "262144",
        "--header",
        "@" + c.private + "/" + label + ".headers",
        "--request",
        request.method(),
        ...(bytes.length
          ? ["--data-binary", "@" + c.private + "/" + label + ".request"]
          : []),
        "--output",
        output,
        "--write-out",
        "%{http_code}",
        target,
      ],
      { encoding: "utf8", timeout: 15000, maxBuffer: 4096 },
    ),
  );
  const original = await open(output, "r");
  try {
    await original.sync();
  } finally {
    await original.close();
  }
  const body = await readFile(output, "utf8");
  assert.ok(Buffer.byteLength(body) <= 262144);
  assert.equal(status, expected);
  const result = {
    status,
    body,
    method: request.method(),
    url: target,
    selection: bytes.length ? JSON.parse(bytes) : null,
    idempotency_key: fields.find(([k]) => k === "idempotency-key")?.[1],
  };
  responses.push({ label, ...result });
  return result;
}
const response = (suffix, label, action, expected = 200) =>
  wireResponse(
    page,
    prefix + suffix,
    action,
    (route, name, target) => actual(route, name, target, expected),
    label,
  );
async function lost(suffix, label, action, retry) {
  const target = prefix + suffix,
    seen = [];
  const handler = async (route) => {
    assert.equal(route.request().method(), "POST");
    const result = await actual(
      route,
      label + "-" + seen.length,
      target,
      label === "create" && seen.length === 0 ? 201 : 200,
    );
    seen.push(result);
    if (seen.length === 1) await route.abort("failed");
    else
      await route.fulfill({
        status: result.status,
        contentType: "application/json",
        body: result.body,
      });
  };
  await page.route(target, handler);
  try {
    await action();
    await retry();
    assert.equal(seen.length, 2);
    assert.ok(seen[0].idempotency_key);
    assert.equal(seen[0].idempotency_key, seen[1].idempotency_key);
    assert.deepEqual(seen[0].selection, seen[1].selection);
    const a = JSON.parse(seen[0].body),
      b = JSON.parse(seen[1].body);
    assert.equal(a.replayed, false);
    assert.equal(b.replayed, true);
    assert.deepEqual({ ...a, replayed: true }, b);
    return b;
  } finally {
    await page.unroute(target, handler);
  }
}
async function list(label) {
  return response("/uploads?limit=50&after=", label, () =>
    button("Uploads").click(),
  );
}
async function reloadOwned(label) {
  await page.reload();
  await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
  const values = await list(label);
  assert.equal(values.uploads.length, 1);
  assert.equal(values.uploads[0].id, ident);
  await page
    .getByRole("row")
    .filter({ hasText: ident })
    .getByRole("button")
    .click();
}
async function details(label, upload) {
  const section = page.getByRole("region", {
    name: "Saved upload details",
    exact: true,
  });
  await page.waitForFunction(
    ({ offset, state }) => {
      const values = new Map(
        Array.from(
          document.querySelectorAll('[aria-label="Saved upload details"] dt'),
          (el) => [el.textContent, el.nextElementSibling?.textContent],
        ),
      );
      return (
        values.get("Committed bytes") === String(offset) &&
        values.get("Upload state") === state
      );
    },
    { offset: upload.committed_offset, state: upload.state },
  );
  const get = async (name) =>
    section
      .locator("dt")
      .filter({ hasText: new RegExp("^" + name + "$") })
      .evaluate((el) => el.nextElementSibling.textContent);
  const view = {
    state: await get("Upload state"),
    path: await page
      .getByLabel("Destination path", { exact: true })
      .inputValue(),
    expected_size: await get("Expected bytes"),
    committed_offset: await get("Committed bytes"),
    expected_sha256: await get("Expected SHA-256"),
    sftp_path: await get("SFTP transfer path"),
    ftps_path: await get("FTPS transfer path"),
  };
  assert.equal(view.state, upload.state);
  assert.equal(view.expected_size, String(payload.length));
  assert.equal(view.committed_offset, String(upload.committed_offset));
  assert.equal(view.expected_sha256, expectedHash);
  assert.equal(view.sftp_path, "/.freightctl/uploads/" + ident);
  assert.equal(view.ftps_path, view.sftp_path);
  if (upload.state === "completed") {
    view.file_id = await get("Accepted file ID");
    view.acceptance = await get("Acceptance");
    assert.equal(view.file_id, upload.file_id);
    assert.equal(view.acceptance, "Accepted and held for checks and release");
  }
  assert.equal(
    await page.getByLabel("Destination path", { exact: true }).inputValue(),
    "/recovered.csv",
  );
  assert.equal(
    await page
      .getByLabel("Destination path", { exact: true })
      .getAttribute("readonly"),
    "",
  );
  await save(label + "-view.json", JSON.stringify(view));
}
try {
  await signIn(c.owner);
  await button("Uploads").click();
  await page
    .getByLabel("File to send", { exact: true })
    .setInputFiles(c.source);
  await page
    .getByLabel("Destination path", { exact: true })
    .fill("/recovered.csv");
  const created = await lost(
    "/uploads",
    "create",
    () => button("Prepare transfer ticket").click(),
    async () => {
      await page.getByRole("alert").waitFor();
      await button("Prepare transfer ticket").click();
      await page
        .getByRole("heading", { name: "Saved upload", exact: true })
        .waitFor();
    },
  );
  ident = created.upload.id;
  assert.equal(created.upload.expected_size, payload.length);
  assert.equal(created.upload.expected_sha256, expectedHash);
  assert.equal(created.upload.committed_offset, 0);
  await details("prepared", created.upload);
  await audit("ticket-prepared");
  emit("ticket-prepared", { id: ident });
  await phase("checkpoint-committed");
  stage = "checkpoint";
  const checkpoint = await response("/uploads/" + ident, "checkpoint", () =>
    button("Refresh upload status").click(),
  );
  assert.equal(checkpoint.committed_offset, 65536);
  assert.equal(checkpoint.chunk_count, 1);
  assert.equal(checkpoint.state, "open");
  await details("checkpoint", checkpoint);
  await audit("ticket-checkpoint");
  emit("ticket-checkpoint-inspected");
  await phase("server-restarted");
  stage = "restart";
  await reloadOwned("restarted-list");
  const restarted = await response("/uploads/" + ident, "restarted", () =>
    button("Refresh upload status").click(),
  );
  assert.deepEqual(restarted, checkpoint);
  await details("restarted", restarted);
  await signIn(c.foreign);
  const hidden = await list("foreign-list");
  assert.deepEqual(hidden.uploads, []);
  const refused = await response(
    "/uploads/" + ident,
    "foreign-status",
    () =>
      page.evaluate(
        (url) =>
          fetch(url, { credentials: "same-origin", redirect: "error" }).then(
            (r) => r.json(),
          ),
        prefix + "/uploads/" + ident,
      ),
    404,
  );
  assert.deepEqual(refused, { error: "not_found" });
  await signIn(c.owner);
  await button("Uploads").click();
  await page
    .getByRole("row")
    .filter({ hasText: ident })
    .getByRole("button")
    .click();
  await audit("ticket-restarted");
  emit("ticket-restart-inspected");
  await phase("completion-committed");
  stage = "receipt";
  await reloadOwned("completed-list");
  accepted = await response("/uploads/" + ident, "completed", () =>
    button("Refresh upload status").click(),
  );
  assert.equal(accepted.state, "completed");
  assert.equal(accepted.committed_offset, payload.length);
  assert.ok(accepted.file_id);
  assert.equal(accepted.acceptance, "durable-held-pending-checks-and-release");
  await details("receipt", accepted);
  await audit("ticket-receipt");
  emit("ticket-receipt-inspected");
  await phase("ticket-held");
  stage = "release";
  const check = await response("/checks/" + accepted.file_id, "held", () =>
    button("Inspect intake check").click(),
  );
  assert.equal(check.check.state, "held");
  await response("/checks/" + accepted.file_id + "/run", "check-run", () =>
    button("Run required checks").click(),
  );
  const passed = await response("/checks/" + accepted.file_id, "checked", () =>
    button("Refresh").click(),
  );
  assert.equal(passed.check.state, "passed");
  assert.equal(passed.check.binding.file.sha256, expectedHash);
  assert.equal(passed.check.binding.file.size_bytes, payload.length);
  await button("Review release").click();
  await audit("ticket-release-review");
  const dialog = page.getByRole("dialog");
  const release = await lost(
    "/checks/" + accepted.file_id + "/release",
    "release",
    () => button("Release file", dialog).click(),
    async () => {
      await dialog.getByRole("alert").waitFor();
      await button("Retry reviewed release", dialog).click();
      await dialog.waitFor({ state: "hidden" });
    },
  );
  assert.equal(release.resource.file_id, accepted.file_id);
  assert.equal(release.resource.state, "released");
  await page
    .locator(".check-detail .badge")
    .filter({ hasText: /^released$/ })
    .waitFor();
  await audit("ticket-released");
  emit("ticket-release-committed");
  await phase("retrieval-verified");
  stage = "finished";
  assert.deepEqual(
    await page.evaluate(() => [localStorage.length, sessionStorage.length]),
    [0, 0],
  );
  assert.deepEqual(errors, []);
  assert.deepEqual(egress, []);
  assert.equal(mutations.length, 2);
  assert.ok(
    mutations.every(
      (m) => m.method === "POST" && m.url === prefix + "/uploads",
    ),
  );
  state = "passed";
} catch (error) {
  failure = String(error.stack ?? error);
  if (page)
    await save(
      "failure-visible.txt",
      (
        await page
          .locator("body")
          .innerText()
          .catch(() => "unavailable")
      ).slice(0, 262144),
    );
} finally {
  input.close();
  if (context) await context.close();
  await browser.close();
  if (errors.length || egress.length) state = "failed";
  await save(
    "result.json",
    JSON.stringify({
      state,
      stage,
      failure,
      upload_id: ident,
      accepted_file_id: accepted?.file_id,
      responses,
      audits,
      commands,
      mutations,
      runtime_errors: errors,
      external_egress: egress,
      inference_performed: false,
      scanner_started: false,
    }),
  );
}
if (state === "passed") emit("passed");
else {
  emit("failed", { stage });
  process.exitCode = 1;
}
