// Qualification evidence only. Session secrets stay in private runner files.
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";

export async function recordBrowserSessionCookie(context, c) {
  assert.ok(["ftps-metadata", "ftps-operator"].includes(c.collection_phase));
  const url = new URL(c.url);
  assert.equal(url.protocol, "https:");
  assert.equal(url.hostname, "127.0.0.1");
  const cookies = await context.cookies(c.url);
  assert.equal(cookies.length, 1);
  const cookie = cookies[0];
  assert.equal(cookie.name, "__Host-freightctl-session");
  assert.equal(cookie.domain, url.hostname);
  assert.equal(cookie.path, "/");
  assert.equal(cookie.secure, true);
  assert.equal(cookie.httpOnly, true);
  assert.equal(cookie.sameSite, "Strict");
  assert.ok(cookie.value.startsWith(c.tenant + "." + c.partner + "."));
  assert.match(
    cookie.value.slice((c.tenant + "." + c.partner + ".").length),
    /^[0-9a-f]{64}$/,
  );
  const observed = Date.now(),
    expires = Math.floor(cookie.expires * 1000);
  assert.ok(
    Number.isSafeInteger(expires) &&
      expires > observed &&
      expires - observed <= 600000,
  );
  await writeFile(
    c.raw + "/browser-session-cookie.json",
    JSON.stringify({
      kind: "freightctl-browser-session-cookie-v1",
      name: cookie.name,
      value: cookie.value,
      domain: cookie.domain,
      path: cookie.path,
      secure: cookie.secure,
      http_only: cookie.httpOnly,
      same_site: cookie.sameSite,
      expires_unix_ms: expires,
      observed_unix_ms: observed,
    }) + "\n",
    { mode: 0o600, flag: "wx" },
  );
}

export async function recordBrowserSessionReadbacks(c, actual) {
  assert.ok(["ftps-metadata", "ftps-operator"].includes(c.collection_phase));
  const bytes = await readFile(c.raw + "/workflow-preview.headers");
  assert.ok(bytes.length <= 16384);
  const fields = new Map();
  for (const line of bytes.toString("utf8").trim().split(/\r?\n/)) {
    const at = line.indexOf(":");
    assert.ok(at > 0);
    const key = line.slice(0, at).toLowerCase();
    assert.ok(!fields.has(key));
    fields.set(key, line.slice(at + 1).trim());
  }
  assert.equal(fields.has("authorization"), false);
  const cookie = JSON.parse(
    await readFile(c.raw + "/browser-session-cookie.json", "utf8"),
  );
  assert.equal(fields.get("cookie"), cookie.name + "=" + cookie.value);
  const headers = {
    cookie: fields.get("cookie"),
    origin: c.url,
    "sec-fetch-site": "same-origin",
  };
  for (const [name, route] of [
    [
      "session-identity",
      `/v1/tenants/${c.tenant}/partners/${c.partner}/identity`,
    ],
    ["session-current", "/v1/browser/session"],
  ]) {
    const target = c.url + route;
    // Independent verified HTTPS reads reuse the observed cookie. They are
    // evidence probes, not additional UI actions or authority to run work.
    const result = await actual(
      {
        request: () => ({
          url: () => target,
          method: () => "GET",
          allHeaders: async () => headers,
          postDataBuffer: () => null,
        }),
      },
      name,
      target,
    );
    assert.equal(result.status, 200);
    assert.equal(result.selection, null);
  }
}
