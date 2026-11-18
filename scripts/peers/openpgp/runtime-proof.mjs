// Executed only in the actual native candidate image during its offline build
// step. No model, credentials, private keys or cryptographic fixture generation.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createReadStream, existsSync, readFileSync } from "node:fs";
import * as openpgp from "openpgp";

let stage = "runtime-version";
// Only these public runtime scalars can leave the probe. Never print the error,
// environment,process report,filesystem contents or private recipient material.
const publicVersion = (value) =>
  typeof value === "string" && /^[-a-zA-Z0-9.+]{1,64}$/.test(value)
    ? value
    : "unrecognized";
const publicFlag = (value) =>
  typeof value === "boolean" || value === 0 || value === 1
    ? value
    : "unrecognized";
const identity = {
  node_version: publicVersion(process.version),
  architecture: ["arm64", "x64"].includes(process.arch)
    ? process.arch
    : "unrecognized",
  embedded_zlib: publicVersion(process.versions.zlib),
  embedded_openssl: publicVersion(process.versions.openssl),
  shared_openssl: publicFlag(process.config.variables.node_shared_openssl),
  shared_zlib: publicFlag(process.config.variables.node_shared_zlib),
};
try {
  assert.equal(process.version, "v26.13.0");
  stage = "runtime-platform";
  assert.equal(process.platform, "linux");
  stage = "runtime-architecture";
  assert.ok(["arm64", "x64"].includes(process.arch));
  stage = "runtime-entrypoint";
  assert.equal(process.execPath, "/nodejs/bin/node");
  stage = "runtime-uid";
  assert.equal(process.getuid(), 65532);
  stage = "runtime-gid";
  assert.equal(process.getgid(), 65532);
  stage = "runtime-shared-openssl";
  assert.equal(process.config.variables.node_shared_openssl, false);
  stage = "runtime-shared-zlib";
  assert.equal(process.config.variables.node_shared_zlib, false);
  stage = "runtime-embedded-zlib";
  assert.equal(process.versions.zlib, "1.3.2.1-motley-456ae73");
  stage = "runtime-embedded-openssl";
  assert.equal(process.versions.openssl, "3.5.9");
  stage = "runtime-dependencies";
  assert.equal(
    JSON.parse(readFileSync("/peer/node_modules/openpgp/package.json", "utf8"))
      .version,
    "6.3.2",
  );
  assert.equal(typeof openpgp.decrypt, "function");
  assert.equal(typeof openpgp.generateKey, "function");
  stage = "runtime-contents";
  for (const path of [
    "/bin/sh",
    "/bin/bash",
    "/bin/busybox",
    "/sbin/apk",
    "/usr/bin/ldd",
    "/usr/bin/apt",
    "/usr/bin/apt-get",
    "/usr/bin/perl",
    "/usr/bin/sqlite3",
    "/usr/bin/mount",
    "/usr/local/bin/npm",
    "/usr/local/lib/node_modules/npm",
    "/usr/local/lib/node_modules/corepack",
    "/usr/lib/libz.so.1",
    "/usr/lib/libssl.so.3",
    "/usr/lib/libcrypto.so.3",
    "/var/lib/dpkg/status.d",
  ])
    assert.equal(existsSync(path), false);
  stage = "runtime-provenance";
  const raw = readFileSync("/peer/runtime-dependencies.json");
  assert.equal(createHash("sha256").update(raw).digest("hex"),
    "c652d44fc2093ec5b790d7796ddf787c269ad53eff42e38cfeebb8c41e5c8033");
  const manifest = JSON.parse(raw);
  const x86 = process.arch === "x64";
  const native = manifest.architectures[x86 ? "amd64" : "arm64"];
  assert.equal(readFileSync("/etc/alpine-release", "utf8").trim(), manifest.alpine_release);
  const database = readFileSync("/lib/apk/db/installed");
  assert.equal(createHash("sha256").update(database).digest("hex"), native.apk_database_sha256);
  const executable = createHash("sha256");
  for await (const chunk of createReadStream(process.execPath)) executable.update(chunk);
  assert.equal(executable.digest("hex"), native.node_sha256);
  stage = "runtime-mapped-libraries";
  const expected = [
    `/lib/ld-musl-${native.apk_architecture}.so.1`,
    "/usr/lib/libgcc_s.so.1",
    "/usr/lib/libstdc++.so.6",
  ];
  if (x86) expected.push("/usr/lib/libatomic.so.1");
  const mapped = process.report.getReport().sharedObjects.filter(
    path => path.startsWith("/") && path !== process.execPath,
  );
  assert.deepEqual(mapped.sort(), expected.sort());
  console.log(
    JSON.stringify({
      kind: "independent-peer-runtime",
      state: "passed",
      node_version: process.version,
      architecture: process.arch,
      uid: process.getuid(),
      gid: process.getgid(),
      openpgp_version: "6.3.2",
      profile: "stock-node26-musl-alpine3.24-v1",
      embedded_openssl: process.versions.openssl,
      embedded_zlib: process.versions.zlib,
      shared_openssl: process.config.variables.node_shared_openssl,
      shared_zlib: process.config.variables.node_shared_zlib,
      stock_manifest_digest: native.manifest_digest,
      node_sha256: native.node_sha256,
      apk_database_sha256: native.apk_database_sha256,
    }),
  );
} catch {
  console.log(
    JSON.stringify({
      kind: "independent-peer-runtime",
      state: "failed",
      stage,
      identity,
    }),
  );
  process.exitCode = 1;
}
