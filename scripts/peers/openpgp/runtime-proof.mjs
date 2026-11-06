// Executed only in the actual native candidate image during its offline build
// step. No model, credentials, private keys or cryptographic fixture generation.
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
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
    "/usr/bin/apt",
    "/usr/bin/apt-get",
    "/usr/bin/perl",
    "/usr/bin/sqlite3",
    "/usr/bin/mount",
    "/usr/local/bin/npm",
    "/usr/local/lib/node_modules/npm",
    "/usr/local/lib/node_modules/corepack",
  ])
    assert.equal(existsSync(path), false);
  assert.equal(existsSync("/var/lib/dpkg/status.d"), true);
  const triplet =
    process.arch === "x64" ? "x86_64-linux-gnu" : "aarch64-linux-gnu";
  for (const path of [
    `/usr/lib/${triplet}/libz.so.1`,
    `/usr/lib/${triplet}/libssl.so.3`,
    `/usr/lib/${triplet}/libcrypto.so.3`,
    "/var/lib/dpkg/status.d/zlib1g",
    "/var/lib/dpkg/status.d/libssl3t64",
  ])
    assert.equal(existsSync(path), false);
  for (const library of process.report.getReport().sharedObjects)
    assert.equal(/\/lib(?:z|ssl|crypto|zstd|gomp)\./.test(library), false);
  console.log(
    JSON.stringify({
      kind: "independent-peer-runtime",
      state: "passed",
      node_version: process.version,
      architecture: process.arch,
      uid: process.getuid(),
      gid: process.getgid(),
      openpgp_version: "6.3.2",
      profile: "distroless-node26-nossl-debian13-v1",
      embedded_zlib: process.versions.zlib,
      shared_openssl: process.config.variables.node_shared_openssl,
      shared_zlib: process.config.variables.node_shared_zlib,
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
