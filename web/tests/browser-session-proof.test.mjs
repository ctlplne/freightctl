import assert from "node:assert/strict";
import {
  mkdtemp,
  readFile,
  writeFile,
  rm,
  stat,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  recordBrowserSessionCookie,
  recordBrowserSessionReadbacks,
} from "../../scripts/browser-session-proof.mjs";

async function fixture(t) {
  const raw = await mkdtemp(join(tmpdir(), "freightctl-cookie-contract-"));
  t.after(() => rm(raw, { recursive: true }));
  const c = {
    raw,
    url: "https://127.0.0.1:49152",
    collection_phase: "ftps-metadata",
    tenant: "10000000-1111-4111-8111-111111111111",
    partner: "10000001-1111-4111-8111-111111111111",
  };
  const cookie = {
    name: "__Host-freightctl-session",
    value: c.tenant + "." + c.partner + "." + "a".repeat(64),
    domain: "127.0.0.1",
    path: "/",
    secure: true,
    httpOnly: true,
    sameSite: "Strict",
    expires: Math.floor(Date.now() / 1000) + 590,
  };
  const context = {
    cookies: async (url) => {
      assert.equal(url, c.url);
      return [cookie];
    },
  };
  return { c, cookie, context };
}

test("snapshot stays private; two independent HTTPS reads reuse the exact observed cookie", async (t) => {
  for (const phase of ["ftps-metadata", "ftps-operator"]) {
    const { c, cookie, context } = await fixture(t);
    c.collection_phase = phase;
    await recordBrowserSessionCookie(context, c);
    const snapshot = JSON.parse(
      await readFile(c.raw + "/browser-session-cookie.json", "utf8"),
    );
    assert.equal(snapshot.value, cookie.value);
    assert.equal(
      (await stat(c.raw + "/browser-session-cookie.json")).mode & 0o777,
      0o600,
    );
    assert.ok(Number.isSafeInteger(snapshot.expires_unix_ms));
    await writeFile(
      c.raw + "/workflow-preview.headers",
      "cookie: " + cookie.name + "=" + cookie.value + "\n",
    );
    const calls = [];
    await recordBrowserSessionReadbacks(c, async (route, name, target) => {
      const request = route.request();
      assert.equal(request.url(), target);
      assert.equal(request.method(), "GET");
      assert.equal(request.postDataBuffer(), null);
      assert.deepEqual(await request.allHeaders(), {
        cookie: cookie.name + "=" + cookie.value,
        origin: c.url,
        "sec-fetch-site": "same-origin",
      });
      calls.push([name, target]);
      return { status: 200, selection: null };
    });
    assert.deepEqual(calls, [
      [
        "session-identity",
        c.url + `/v1/tenants/${c.tenant}/partners/${c.partner}/identity`,
      ],
      ["session-current", c.url + "/v1/browser/session"],
    ]);
    await assert.rejects(recordBrowserSessionCookie(context, c)); // Never overwrite an original.
  }
});

test("cookie snapshot rejects flags, scope, expiry and multiple identities", async (t) => {
  const { c, cookie } = await fixture(t);
  for (const change of [
    { secure: false },
    { httpOnly: false },
    { sameSite: "Lax" },
    { domain: ".127.0.0.1" },
    { path: "/v1" },
    { value: "other.identity." + "a".repeat(64) },
    { expires: 1 },
    { expires: Date.now() / 1000 + 700 },
  ]) {
    await assert.rejects(
      recordBrowserSessionCookie(
        { cookies: async () => [{ ...cookie, ...change }] },
        c,
      ),
    );
  }
  await assert.rejects(
    recordBrowserSessionCookie({ cookies: async () => [cookie, cookie] }, c),
  );
  await assert.rejects(
    recordBrowserSessionCookie(
      { cookies: async () => [cookie] },
      { ...c, url: "https://other.invalid" },
    ),
  );
});

test("readback refuses bearer or changed/duplicate cookie and failed original response", async (t) => {
  const { c, cookie, context } = await fixture(t);
  await recordBrowserSessionCookie(context, c);
  const original = "cookie: " + cookie.name + "=" + cookie.value + "\n";
  for (const changed of [
    original + "authorization: Bearer canary\n",
    original + original,
    original.replace("a".repeat(64), "b".repeat(64)),
  ]) {
    await writeFile(c.raw + "/workflow-preview.headers", changed);
    await assert.rejects(
      recordBrowserSessionReadbacks(c, () =>
        assert.fail("must refuse before HTTPS probe"),
      ),
    );
  }
  await writeFile(c.raw + "/workflow-preview.headers", original);
  await assert.rejects(
    recordBrowserSessionReadbacks(c, async () => ({
      status: 403,
      selection: null,
    })),
  );
  await assert.rejects(
    recordBrowserSessionReadbacks(c, async () => ({
      status: 200,
      selection: {},
    })),
  );
});
