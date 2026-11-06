// GitHub-only stock client;never print credentials,paths,URLs or response bodies.
import assert from "node:assert/strict";
import { readFile, lstat, writeFile } from "node:fs/promises";
import { createHash, X509Certificate } from "node:crypto";
import https from "node:https";
import * as tus from "tus-js-client";

assert.equal(process.env.GITHUB_ACTIONS, "true");
assert.equal(process.platform, "linux");
assert.ok(["arm64", "x64"].includes(process.arch));
assert.equal(process.version, "v26.13.0");
const cfg = JSON.parse(await readFile(process.argv[2], "utf8"));
const installed = JSON.parse(
  await readFile(
    new URL("./node_modules/tus-js-client/package.json", import.meta.url),
    "utf8",
  ),
);
assert.equal(installed.version, "4.3.1");
assert.equal(installed.license, "MIT");
const target = new URL(cfg.url);
assert.equal(target.protocol, "https:");
assert.equal(target.hostname, "127.0.0.1");
assert.equal(target.search, "");
assert.equal(target.hash, "");
assert.equal(target.username, "");
assert.equal(target.password, "");
assert.match(
  target.pathname,
  /^\/v1\/tenants\/[0-9a-f-]{36}\/partners\/[0-9a-f-]{36}\/tus\/uploads\/[0-9a-f-]{36}$/,
);
for (const path of [cfg.token_file, cfg.payload_file]) {
  const st = await lstat(path);
  assert.ok(st.isFile() && !st.isSymbolicLink() && (st.mode & 0o077) === 0);
}
const token = await readFile(cfg.token_file),
  payload = await readFile(cfg.payload_file),
  certificate = new X509Certificate(
    Buffer.from(cfg.certificate_der, "base64"),
  ).toString();
assert.equal(token.length, 64);
assert.match(token.toString("ascii"), /^[0-9a-f]{64}$/);
assert.ok(
  Number.isSafeInteger(cfg.size) && cfg.size > 65536 && cfg.size < 1048576,
);
assert.equal(payload.length, cfg.size);
assert.equal(createHash("sha256").update(payload).digest("hex"), cfg.sha256);
const agent = new https.Agent({
  ca: certificate,
  rejectUnauthorized: true,
  minVersion: "TLSv1.3",
  keepAlive: false,
});
const base = new tus.DefaultHttpStack({ agent });
let phase = "stock-client",
  state = "failed",
  heads = 0,
  patches = 0,
  overrides = 0,
  failures = 0,
  lastOffset = 0,
  verified = false,
  failureHash;
const httpStack = {
  getName: () => base.getName(),
  createRequest(method, url) {
    assert.equal(url, target.href);
    assert.ok(["HEAD", "PATCH", "POST"].includes(method));
    const request = base.createRequest(method, url),
      send = request.send.bind(request);
    request.send = (body) => {
      if (method === "POST") {
        assert.equal(request.getHeader("X-HTTP-Method-Override"), "PATCH");
        assert.equal(cfg.override_patch, true);
        overrides++;
      } else if (method === "PATCH") {
        assert.equal(cfg.override_patch, false);
        patches++;
      } else heads++;
      const promise = send(body),
        native = request.getUnderlyingObject();
      assert.ok(native);
      native.setTimeout(15000, () =>
        native.destroy(new Error("loopback request deadline")),
      );
      return promise.catch((error) => {
        failures++;
        throw error;
      });
    };
    return request;
  },
};
try {
  await new Promise((resolve, reject) => {
    const upload = new tus.Upload(payload, {
      uploadUrl: target.href,
      chunkSize: 65536,
      overridePatchMethod: cfg.override_patch,
      headers: { Authorization: "Bearer " + token.toString("ascii") },
      httpStack,
      retryDelays: [0, 100, 250],
      storeFingerprintForResuming: false,
      removeFingerprintOnSuccess: true,
      onAfterResponse(request, response) {
        assert.equal(request.getURL(), target.href);
        const socket = request.getUnderlyingObject().socket;
        assert.equal(socket.authorized, true);
        assert.equal(socket.getProtocol(), "TLSv1.3");
        verified = true;
        assert.equal(response.getHeader("Tus-Resumable"), "1.0.0");
        const offset = response.getHeader("Upload-Offset");
        if (offset !== undefined && offset !== null) {
          assert.match(offset, /^[0-9]+$/);
          lastOffset = Number(offset);
          assert.ok(lastOffset >= 0 && lastOffset <= cfg.size);
        }
        const acceptance = response.getHeader("X-Freightctl-Acceptance");
        if (acceptance) assert.equal(acceptance, "durable-checkpoint-only");
      },
      onError: reject,
      onSuccess: resolve,
    });
    upload.start();
  });
  assert.equal(lastOffset, cfg.size);
  assert.equal(verified, true);
  assert.ok(heads >= 2);
  assert.ok(patches + overrides >= 3);
  if (cfg.expect_lost_response) assert.ok(failures >= 1);
  phase = "complete";
  state = "passed";
} catch (error) {
  failureHash = createHash("sha256").update(String(error)).digest("hex");
} finally {
  token.fill(0);
  payload.fill(0);
  agent.destroy();
  const result = {
    kind: "native-tus-core-stock-client",
    state,
    phase,
    client: "tus-js-client",
    version: "4.3.1",
    node: process.version,
    architecture: process.arch,
    heads,
    patches,
    overrides,
    network_failures: failures,
    checkpoint_offset: lastOffset,
    checkpoint_bytes: cfg.size,
    sha256: cfg.sha256,
    acceptance: "checkpoint-only;ordinary completion required",
    receiver_persistence: "unknown",
    business_processing: "unknown",
    tls_verified: verified,
    creation_endpoint: false,
    model_started: false,
    ...(failureHash ? { failure_sha256: failureHash } : {}),
  };
  await writeFile(cfg.result_file, JSON.stringify(result) + "\n", {
    mode: 0o600,
    flag: "wx",
  });
  console.log(JSON.stringify(result));
  if (state !== "passed") process.exitCode = 1;
}
