// Build-only assembly from complete pinned Debian packages. Never installed or
// run in the recipient. No package maintainer scripts are executed.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createWriteStream, createReadStream } from "node:fs";
import { mkdir, readFile, writeFile, copyFile } from "node:fs/promises";
import { pipeline } from "node:stream/promises";
import { Readable } from "node:stream";
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const names = ["gcc-14-base", "libatomic1", "libgcc-s1", "libstdc++6"];
export const RUNTIME_DEPENDENCIES_SHA256 =
  "4524cf640952a468917a6df0e0fe426f0a85040b4fb6f7f12ddf6829c61b8627";
export function runtimePackages(manifest, arch) {
  assert.equal(manifest.schema_version, 1);
  assert.ok(["amd64", "arm64"].includes(arch));
  assert.ok(Array.isArray(manifest.packages));
  const packages = manifest.packages.filter((p) => p.arch === arch);
  assert.deepEqual(packages.map((p) => p.name).sort(), names);
  for (const p of packages) {
    assert.equal(p.version, "14.2.0-19");
    assert.match(p.sha256, /^[0-9a-f]{64}$/);
    assert.ok(Array.isArray(p.urls) && p.urls.length > 0);
    for (const text of p.urls) {
      const url = new URL(text);
      assert.equal(url.protocol, "https:");
      assert.ok(
        ["snapshot.debian.org", "deb.debian.org"].includes(url.hostname),
      );
      assert.equal(url.username, "");
      assert.equal(url.password, "");
      assert.equal(url.search, "");
      assert.equal(url.hash, "");
      assert.ok(url.pathname.endsWith(`/${p.name}_${p.version}_${arch}.deb`));
    }
  }
  return structuredClone(packages);
}
export async function installRuntime(packages, operations) {
  for (const p of packages) {
    const actual = await operations.acquire(p);
    assert.equal(actual.sha256, p.sha256, "runtime package digest differs");
    await operations.unpack(p, actual.file);
  }
}
async function download(p) {
  const file = `/build/downloads/${p.name}.deb`;
  let completed = false;
  for (const initial of p.urls) {
    try {
      let url = new URL(initial),
        response;
      for (let redirects = 0; redirects < 5; redirects++) {
        response = await fetch(url, { redirect: "manual" });
        if (![301, 302, 303, 307, 308].includes(response.status)) break;
        const next = new URL(response.headers.get("location"), url);
        await response.body?.cancel();
        assert.equal(next.protocol, "https:");
        assert.ok(
          ["snapshot.debian.org", "deb.debian.org"].includes(next.hostname),
        );
        assert.equal(next.username, "");
        assert.equal(next.password, "");
        url = next;
      }
      assert.ok(response?.ok && response.body);
      await pipeline(
        Readable.fromWeb(response.body),
        createWriteStream(file, { flags: "w", mode: 0o600 }),
      );
      completed = true;
      break;
    } catch {}
  }
  assert.equal(completed, true, "pinned package acquisition failed");
  const hash = createHash("sha256");
  let bytes = 0;
  for await (const chunk of createReadStream(file)) {
    hash.update(chunk);
    bytes += chunk.length;
  }
  return { file, sha256: hash.digest("hex"), bytes };
}
async function unpack(p, file) {
  const control = `/build/controls/${p.name}`,
    root = "/runtime",
    status = root + "/var/lib/dpkg/status.d";
  await mkdir(control, { recursive: true });
  await mkdir(root, { recursive: true });
  await mkdir(status, { recursive: true });
  // Extract complete data and control archives. Do not cherry-pick library bytes
  // or edit package versions;retain licenses,metadata and installed file hashes.
  execFileSync("dpkg-deb", ["--control", file, control], { stdio: "pipe" });
  const raw = await readFile(control + "/control", "utf8");
  const field = (name) => new RegExp(`^${name}: (.+)$`, "m").exec(raw)?.[1];
  assert.equal(field("Package"), p.name);
  assert.equal(field("Version"), p.version);
  assert.equal(field("Architecture"), p.arch);
  execFileSync("dpkg-deb", ["--extract", file, root], { stdio: "pipe" });
  await writeFile(status + "/" + p.name, raw.endsWith("\n") ? raw : raw + "\n");
  await copyFile(control + "/md5sums", status + "/" + p.name + ".md5sums");
}
async function main() {
  assert.equal(process.platform, "linux");
  const arch = process.arch === "x64" ? "amd64" : process.arch;
  const rawManifest = await readFile("/build/runtime-dependencies.json");
  assert.equal(
    createHash("sha256").update(rawManifest).digest("hex"),
    RUNTIME_DEPENDENCIES_SHA256,
  );
  const manifest = JSON.parse(rawManifest.toString("utf8"));
  const packages = runtimePackages(manifest, arch);
  await mkdir("/build/downloads", { recursive: true });
  await installRuntime(packages, { acquire: download, unpack });
  console.log(
    JSON.stringify({
      kind: "independent-peer-runtime-assembly",
      state: "passed",
      architecture: arch,
      packages: packages.map((p) => ({
        name: p.name,
        version: p.version,
        sha256: p.sha256,
      })),
    }),
  );
}
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  main().catch(() => {
    console.error("Pinned runtime assembly failed;no image qualification");
    process.exitCode = 1;
  });
}
