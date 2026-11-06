import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import {
  runtimePackages,
  installRuntime,
  RUNTIME_DEPENDENCIES_SHA256,
} from "./assemble-runtime.mjs";
const rawManifest = await readFile(
  new URL("runtime-dependencies.json", import.meta.url),
);
const manifest = JSON.parse(rawManifest.toString("utf8"));
test("native package selection preserves complete exact architecture inputs and refuses substitutions", () => {
  assert.equal(
    createHash("sha256").update(rawManifest).digest("hex"),
    RUNTIME_DEPENDENCIES_SHA256,
  );
  for (const arch of ["amd64", "arm64"]) {
    const packages = runtimePackages(manifest, arch);
    assert.equal(packages.length, 4);
    assert.ok(packages.every((p) => p.arch === arch));
  }
  for (const change of [
    (m) => m.packages.pop(),
    (m) => (m.packages[0].sha256 = "unknown"),
    (m) => (m.packages[0].version = "unstable"),
    (m) => (m.packages[0].urls = ["https://unapproved.invalid/package.deb"]),
    (m) => m.packages.push(m.packages[0]),
  ]) {
    const value = structuredClone(manifest);
    change(value);
    assert.throws(() => {
      runtimePackages(value, "amd64");
      runtimePackages(value, "arm64");
    });
  }
  assert.throws(() => runtimePackages(manifest, "x86-emulated"));
});
test("digest mismatch refuses before package extraction or metadata registration", async () => {
  const packages = runtimePackages(manifest, "amd64"),
    unpacked = [];
  await assert.rejects(() =>
    installRuntime(packages, {
      acquire: async () => ({ file: "stand-in", sha256: "0".repeat(64) }),
      unpack: async (p) => unpacked.push(p.name),
    }),
  );
  assert.deepEqual(unpacked, []);
  await installRuntime(packages, {
    acquire: async (p) => ({ file: "stand-in", sha256: p.sha256 }),
    unpack: async (p) => unpacked.push(p.name),
  });
  assert.deepEqual(
    unpacked,
    packages.map((p) => p.name),
  );
});
