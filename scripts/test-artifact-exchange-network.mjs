import assert from "node:assert/strict";
import test from "node:test";
import { artifactExchangeRequestAllowed as allowed } from "./artifact-exchange-network.mjs";

const origin = "https://127.0.0.1:25443";
const tenant = "10000000-1111-4111-8111-111111111111";
const partner = "10000001-1111-4111-8111-111111111111";
const checkpoint = "20000000-1111-4111-8111-111111111111";
const base = `/v1/tenants/${tenant}/partners/${partner}`;
const upload = `${base}/uploads/${checkpoint}`;
const check = (path, method = "PATCH", host = origin) =>
  allowed(new URL(host + path), method, origin, tenant, partner);

test("ordinary same-participant upload checkpoint PATCH can reach its real server", () => {
  assert.equal(check(upload), true);
  assert.equal(check("/", "GET"), true);
  assert.equal(check(base + "/exchanges", "POST"), true);
});

test("checkpoint PATCH grants no egress,other scope,path,method or query authority", () => {
  for (const path of [
    upload.replace(tenant, checkpoint),
    upload.replace(partner, checkpoint),
    base + "/files/" + checkpoint,
    base + "/uploads",
    upload + "/complete",
    upload + "/",
    upload + "?path=/another",
    upload + "#another",
    upload.replace(checkpoint, "not-an-id"),
    upload.replace("/uploads/", "/uploads%2F"),
  ]) {
    assert.equal(check(path), false, path);
  }
  for (const method of ["DELETE", "PUT", "OPTIONS", "MOVE"])
    assert.equal(check(upload, method), false);
  assert.equal(check(upload, "PATCH", "https://outside.invalid"), false);
  assert.equal(check("/", "GET", "https://outside.invalid"), false);
  assert.equal(
    allowed(
      new URL(origin.replace("https://", "https://credential@") + upload),
      "PATCH",
      origin,
      tenant,
      partner,
    ),
    false,
  );
});
