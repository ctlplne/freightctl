// Native browser and actual HTTPS/FTPS services. No fabricated API responses.
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { readFile, writeFile, open } from "node:fs/promises";
import { createHash, X509Certificate } from "node:crypto";
import { createRequire } from "node:module";
import { wireResponse } from "./browser-wire.mjs";
process.umask(0o077);
const c = JSON.parse(await readFile(process.argv[2], "utf8"));
const { chromium } = createRequire(import.meta.url)(
  "../web/node_modules/playwright",
);
assert.equal(new URL(c.url).hostname, "127.0.0.1");
assert.ok(
  !process.env.FREIGHTCTL_BROWSER_CHANNEL ||
    process.env.FREIGHTCTL_BROWSER_CHANNEL === "chrome",
);
const sha = (b) => createHash("sha256").update(b).digest("hex");
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
    "--renderer-process-limit=1",
    "--js-flags=--max-old-space-size=128",
  ],
});
let context,
  page,
  activePeer,
  state = "failed",
  failure,
  failureLine,
  phase = "credential-sign-in";
const steps = [],
  errors = [],
  egress = [],
  responses = [];
const record = (name) => {
  steps.push(name);
  console.log("passed: " + name);
};
const button = (name, parent = page) =>
  parent.getByRole("button", { name, exact: true });
const dialog = () => page.getByRole("dialog");
let prefix,
  sequence = 0;
async function signIn(who) {
  if (context) await context.close();
  context = await browser.newContext({
    acceptDownloads: true,
    viewport: { width: 1320, height: 950 },
  });
  page = await context.newPage();
  page.setDefaultTimeout(15000);
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("request", (r) => {
    if (new URL(r.url()).origin !== c.url) egress.push(new URL(r.url()).origin);
  });
  prefix = c.url + `/v1/tenants/${who.tenant}/partners/${who.partner}`;
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
  await writeFile(c.private + "/" + name + "-axe.json", JSON.stringify(result));
  assert.equal(result.violations.length, 0, name + " accessibility");
  record(name + "-axe");
}
async function actual(route, label, target) {
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
  const base = c.private + "/" + label;
  await writeFile(
    base + ".headers",
    fields.map(([k, v]) => k + ": " + v).join("\n") + "\n",
  );
  await writeFile(base + ".request", bytes);
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
        "@" + base + ".headers",
        "--request",
        request.method(),
        ...(bytes.length ? ["--data-binary", "@" + base + ".request"] : []),
        "--output",
        base + ".response",
        "--write-out",
        "%{http_code}",
        target,
      ],
      { encoding: "utf8", timeout: 15000, maxBuffer: 4096 },
    ),
  );
  const body = await readFile(base + ".response", "utf8");
  assert.ok(Buffer.byteLength(body) <= 262144);
  const result = {
    status,
    body,
    selection: bytes.length ? JSON.parse(bytes) : null,
    idempotency_key: fields.find(([k]) => k === "idempotency-key")?.[1],
  };
  responses.push({ label, ...result });
  return result;
}
const response = (suffix, action) =>
  wireResponse(page, prefix + suffix, action, actual, "wire-" + sequence++);
async function commit(suffix, name, lost = false) {
  if (!lost) {
    const r = await response(suffix, () => button(name, dialog()).click());
    await dialog().waitFor({ state: "hidden" });
    return r;
  }
  const target = prefix + suffix,
    seen = [];
  const handler = async (route) => {
    const r = await actual(route, "loss-" + sequence++, target);
    seen.push(r);
    if (seen.length === 1) await route.abort("failed");
    else
      await route.fulfill({
        status: r.status,
        contentType: "application/json",
        body: r.body,
      });
  };
  await page.route(target, handler);
  try {
    await button(name, dialog()).click();
    await dialog().getByRole("alert").waitFor();
    await button(name, dialog()).click();
    await dialog().waitFor({ state: "hidden" });
    assert.equal(seen.length, 2);
    assert.equal(seen[0].status, 200);
    assert.equal(seen[1].status, 200);
    assert.ok(seen[0].idempotency_key);
    assert.equal(seen[0].idempotency_key, seen[1].idempotency_key);
    assert.deepEqual(seen[0].selection, seen[1].selection);
    const first = JSON.parse(seen[0].body),
      again = JSON.parse(seen[1].body);
    assert.equal(first.replayed, false);
    assert.equal(again.replayed, true);
    assert.deepEqual({ ...first, replayed: true }, again);
    record(
      "lost-" + suffix.split("/").filter(Boolean).join("-") + "-original-key",
    );
    return again;
  } finally {
    await page.unroute(target, handler);
  }
}
async function peer(settings, label) {
  const ref = c.private + "/" + label + ".json";
  await writeFile(
    ref,
    JSON.stringify({
      ...settings,
      port: c.port,
      implicit: c.implicit,
      certificate: c.certificate,
    }),
  );
  const err = await open(c.private + "/" + label + ".stderr", "wx");
  const p = spawn(
    "python3",
    ["scripts/ftps-governance-probe.py", "--reference", ref],
    { cwd: c.root, stdio: ["pipe", "pipe", err.fd] },
  );
  let buffer = "",
    total = 0,
    ended = false,
    code,
    waiting;
  const messages = [],
    lines = [];
  function wake() {
    if (waiting) {
      waiting();
      waiting = undefined;
    }
  }
  p.stdout.on("data", (b) => {
    total += b.length;
    if (total > 16384) {
      p.kill("SIGTERM");
      errors.push("FTPS peer output bound");
      ended = true;
      wake();
      return;
    }
    buffer += b.toString("utf8");
    while (buffer.includes("\n")) {
      const index = buffer.indexOf("\n"),
        line = buffer.slice(0, index);
      buffer = buffer.slice(index + 1);
      lines.push(line);
      messages.push(line);
    }
    wake();
  });
  p.on("error", () => {
    errors.push("FTPS peer process failed");
    ended = true;
    wake();
  });
  const closed = new Promise((resolve) =>
    p.on("close", (value) => {
      ended = true;
      code = value;
      wake();
      resolve();
    }),
  );
  const result = {
    async next(expected) {
      const deadline = Date.now() + 15000;
      while (!messages.length && !ended) {
        assert.ok(Date.now() < deadline, "FTPS phase deadline");
        await new Promise((resolve) => {
          const timer = setTimeout(
            () => {
              waiting = undefined;
              resolve();
            },
            Math.max(1, deadline - Date.now()),
          );
          waiting = () => {
            clearTimeout(timer);
            resolve();
          };
        });
      }
      assert.ok(messages.length, "FTPS peer ended before " + expected);
      const line = messages.shift();
      assert.ok(line.length <= 2048);
      const message = JSON.parse(line);
      assert.equal(message.state, expected);
      return message;
    },
    send(action) {
      p.stdin.write(JSON.stringify({ action }) + "\n");
    },
    async close(success = false) {
      if (!success && !ended) p.kill("SIGTERM");
      let timer;
      try {
        await Promise.race([
          closed,
          new Promise((_, reject) => {
            timer = setTimeout(() => {
              p.kill("SIGKILL");
              reject(new Error("FTPS peer exit deadline"));
            }, 5000);
          }),
        ]);
      } finally {
        clearTimeout(timer);
        await err.close();
        await writeFile(
          c.private + "/" + label + ".stdout",
          lines.join("\n") + "\n",
        );
      }
      if (success) {
        assert.equal(code, 0);
        assert.equal(buffer, "");
        assert.equal(messages.length, 0);
      }
    },
  };
  activePeer = result;
  return result;
}
async function saveCredential(filename) {
  const download = page.waitForEvent("download");
  await button("Download new credential", dialog()).click();
  await (await download).saveAs(filename);
  assert.equal((await readFile(filename)).length, 64);
  await dialog()
    .getByLabel("I saved the credential file securely.", { exact: true })
    .check();
}
try {
  await signIn(c.credential);
  phase = "credential-create";
  await button("Accounts").click();
  await page
    .getByLabel("Account label", { exact: true })
    .fill("FTPS browser writer");
  await page.getByLabel("write", { exact: true }).check();
  await button("Review new account").click();
  await audit("credential-create-review");
  const old = c.private + "/old.token",
    next = c.private + "/next.token";
  await saveCredential(old);
  const created = await commit("/accounts/commands", "Apply reviewed change");
  assert.equal(created.account.revision, 1);
  const createdRequest = responses.at(-1).selection;
  assert.equal(createdRequest.credential_sha256, sha(await readFile(old)));
  assert.equal(
    JSON.stringify(createdRequest).includes(await readFile(old, "utf8")),
    false,
  );
  const id = created.account.id;
  await page
    .getByRole("row")
    .filter({ hasText: id })
    .getByRole("button", { name: "Review FTPS browser writer", exact: true })
    .click();
  await button("Review credential rotation").click();
  await saveCredential(next);
  await audit("credential-rotate-review");
  phase = "credential-rotate";
  const writer = await peer(
    {
      scenario: "credential-lifecycle",
      username: c.credential.tenant + "/" + c.credential.partner,
      password: await readFile(old, "utf8"),
      next_password: await readFile(next, "utf8"),
      observer_password: await readFile(c.credential.token, "utf8"),
    },
    "credential-peer",
  );
  assert.equal(
    (await writer.next("writer-open-before-rotation")).resumed,
    true,
  );
  const rotated = await commit(
    "/accounts/commands",
    "Apply reviewed change",
    true,
  );
  assert.equal(rotated.account.id, id);
  assert.equal(rotated.account.revision, 2);
  assert.equal(
    responses.at(-1).selection.credential_sha256,
    sha(await readFile(next)),
  );
  writer.send("rotation-committed");
  assert.equal(
    (await writer.next("writer-open-before-revocation")).resumed,
    true,
  );
  await page
    .getByRole("row")
    .filter({ hasText: id })
    .getByRole("button", { name: "Review FTPS browser writer", exact: true })
    .click();
  phase = "credential-revoke";
  await button("Review revocation").click();
  const revoked = await commit("/accounts/commands", "Apply reviewed change");
  assert.equal(revoked.account.id, id);
  assert.equal(revoked.account.revision, 3);
  assert.equal(revoked.account.state, "revoked");
  writer.send("revocation-committed");
  const credentialProof = await writer.next("passed");
  assert.equal(credentialProof.case_count, 2);
  assert.equal(credentialProof.all_data_resumed, true);
  await writer.close(true);
  activePeer = undefined;
  record("browser-rotation-revocation-refuse-open-ftps-writers");

  phase = "intake-sign-in";
  await signIn(c.intake);
  await button("Intake policy").click();
  await page
    .getByText(
      "No intake policy is configured. Ordinary integrity checks still apply.",
      { exact: true },
    )
    .waitFor();
  await audit("intake-policy-editor");
  await button("Review intake policy").click();
  await audit("intake-policy-register-review");
  phase = "policy-register";
  const configured = await commit(
    "/intake-policy",
    "Apply reviewed policy",
    true,
  );
  assert.equal(configured.resource.version, 1);
  assert.equal(configured.resource.state, "active");
  const intake = await peer(
    {
      scenario: "intake",
      username: c.intake.tenant + "/" + c.intake.partner,
      password: await readFile(c.intake.token, "utf8"),
    },
    "intake-peer",
  );
  await intake.next("uploads-held");
  phase = "intake-list";
  const list = await response("/checks", () => button("Intake checks").click());
  assert.equal(list.checks.length, 2);
  assert.ok(list.checks.every((x) => x.state === "held"));
  const ids = Object.fromEntries(list.checks.map((x) => [x.path, x.file_id]));
  async function inspect(path) {
    return response("/checks/" + ids[path], () =>
      page
        .getByRole("row")
        .filter({ hasText: path })
        .getByRole("button", { name: "Inspect check", exact: true })
        .click(),
    );
  }
  const checks = {};
  for (const path of ["/bad.csv", "/good.csv"]) {
    phase = path === "/bad.csv" ? "check-bad" : "check-good";
    await inspect(path);
    await response("/checks/" + ids[path] + "/run", () =>
      button("Run required checks").click(),
    );
    const v = await response("/checks/" + ids[path], () =>
      button("Refresh").click(),
    );
    checks[path] = v.check;
    assert.equal(v.check.state, path === "/good.csv" ? "passed" : "rejected");
    assert.equal(v.check.attempts, 1);
    if (path === "/bad.csv")
      assert.equal(await button("Review release").count(), 0);
  }
  intake.send("checks-completed");
  await intake.next("passed-still-unreleased");
  phase = "release";
  await button("Review release").click();
  await audit("exact-ftps-release-review");
  const released = await commit(
    "/checks/" + ids["/good.csv"] + "/release",
    "Release file",
  );
  assert.equal(released.check?.state ?? released.resource?.state, "released");
  const selection = responses.at(-1).selection;
  assert.equal(selection.report_hash, checks["/good.csv"].report_hash);
  assert.equal(selection.expected_revision, checks["/good.csv"].revision);
  intake.send("release-committed");
  await intake.next("only-approved-revision-published");
  phase = "policy-revoke";
  await button("Intake policy").click();
  await button("Review policy revocation").click();
  await audit("intake-policy-revoke-review");
  const policyRevoked = await commit(
    "/intake-policy/revoke",
    "Apply reviewed policy",
    true,
  );
  assert.equal(policyRevoked.resource.id, configured.resource.id);
  assert.equal(policyRevoked.resource.state, "revoked");
  assert.equal(policyRevoked.resource.revision, 2);
  intake.send("policy-revocation-committed");
  const intakeProof = await intake.next("passed");
  assert.equal(intakeProof.case_count, 4);
  assert.equal(intakeProof.all_data_resumed, true);
  await intake.close(true);
  activePeer = undefined;
  record("browser-ftps-hold-check-release-and-policy-revocation");
  phase = "final-audit";
  await audit("intake-policy-revoked");
  assert.deepEqual(
    await page.evaluate(() => ({
      local: localStorage.length,
      session: sessionStorage.length,
    })),
    { local: 0, session: 0 },
  );
  assert.equal(errors.length, 0);
  assert.equal(egress.length, 0);
  state = "passed";
} catch (e) {
  failure = String(e.stack ?? e);
  failureLine = Number(
    failure.match(/ftps-operator-browser\.mjs:(\d+):\d+/)?.[1] ?? 0,
  );
  if (page) {
    await writeFile(
      c.private + "/failure-visible.txt",
      await page
        .locator("body")
        .innerText()
        .catch(() => "unavailable"),
    );
    await page
      .screenshot({ path: c.private + "/failure.png", fullPage: true })
      .catch(() => {});
  }
} finally {
  if (activePeer)
    await activePeer.close().catch(() => {
      errors.push("FTPS peer cleanup failed");
    });
  if (context) await context.close();
  await browser.close();
  if (errors.length || egress.length) state = "failed";
  await writeFile(
    c.private + "/result.json",
    JSON.stringify(
      {
        state,
        failure,
        failure_line: failureLine,
        phase,
        steps,
        responses,
        runtime_errors: errors,
        external_egress: egress,
        inference_performed: false,
        scanner_started: false,
      },
      null,
      2,
    ) + "\n",
  );
}
if (state !== "passed")
  console.log(JSON.stringify({ state, phase, line: failureLine ?? 0 }));
if (state !== "passed")
  throw new Error("FTPS operator browser failed; protected evidence retained");
