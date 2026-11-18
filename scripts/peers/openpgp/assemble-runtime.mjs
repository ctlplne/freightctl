// The pinned stock image supplies the Node executable and complete Alpine
// package records and payloads. The build stage performs no package install.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { copyFile, lstat, mkdir, readFile, readlink, symlink, writeFile } from "node:fs/promises";
import { posix } from "node:path";
import { pathToFileURL } from "node:url";

export const RUNTIME_DEPENDENCIES_SHA256 =
  "c652d44fc2093ec5b790d7796ddf787c269ad53eff42e38cfeebb8c41e5c8033";
const apkDirectory = "lib/apk/db";
const relativePath = /^(?:[a-zA-Z0-9_+-][a-zA-Z0-9_.+-]*\/)*[a-zA-Z0-9_+-][a-zA-Z0-9_.+-]*$/;
const apkField = (lines, key) => lines.filter(line => line.startsWith(key + ":")).map(line => line.slice(2));

async function fileDigest(path, algorithm, encoding) {
  const hash = createHash(algorithm);
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest(encoding);
}

export function selectedDatabase(raw, profile) {
  const records = new Map();
  for (const block of raw.split("\n\n")) {
    const lines = block.split("\n"), names = apkField(lines, "P");
    if (!names.some(name => Object.hasOwn(profile.packages, name))) continue;
    assert.equal(names.length, 1);
    const [name] = names;
    assert.ok(!records.has(name));
    assert.deepEqual(apkField(lines, "V"), [profile.packages[name]]);
    assert.deepEqual(apkField(lines, "A"), [profile.apk_architecture]);
    records.set(name, block);
  }
  const names = Object.keys(profile.packages);
  assert.equal(records.size, names.length);
  return names.map(name => records.get(name)).join("\n\n") + "\n\n";
}

export function packageFiles(database) {
  const files = new Map();
  for (const block of database.trimEnd().split("\n\n")) {
    let dir, path;
    for (const line of block.split("\n")) {
      const value = line.slice(2);
      switch (line.slice(0, 2)) {
        case "F:":
          assert.equal(path, undefined);
          assert.match(value, relativePath);
          dir = value;
          break;
        case "R:":
          assert.ok(dir && !path && !value.includes("/"));
          assert.match(value, relativePath);
          path = `${dir}/${value}`;
          assert.ok(!files.has(path));
          break;
        case "Z:":
          assert.ok(path);
          assert.match(value, /^Q1[A-Za-z0-9+/]{27}=$/);
          files.set(path, value.slice(2));
          path = undefined;
          break;
      }
    }
    assert.equal(path, undefined);
  }
  return files;
}

async function copyPackageFiles(source, output, files) {
  for (const [path, checksum] of files) {
    const input = posix.join(source, path), target = posix.join(output, path);
    await mkdir(posix.dirname(target), { recursive: true });
    const info = await lstat(input);
    // APK records carry SHA-1 payload checksums, including the bytes of relative
    // symlink targets. The source OCI index, Node binary and records use SHA-256.
    if (info.isSymbolicLink()) {
      const link = await readlink(input);
      const resolved = posix.join(posix.dirname(path), link);
      assert.ok(!posix.isAbsolute(link) && files.has(resolved));
      assert.equal(createHash("sha1").update(link).digest("base64"), checksum);
      await symlink(link, target);
    } else {
      assert.ok(info.isFile());
      assert.equal(await fileDigest(input, "sha1", "base64"), checksum);
      await copyFile(input, target);
    }
  }
}

async function main() {
  assert.equal(process.platform, "linux");
  const architecture = process.arch === "x64" ? "amd64" : process.arch;
  const raw = await readFile(new URL("runtime-dependencies.json", import.meta.url));
  assert.equal(createHash("sha256").update(raw).digest("hex"), RUNTIME_DEPENDENCIES_SHA256);
  const manifest = JSON.parse(raw);
  assert.equal(manifest.schema_version, 2);
  const profile = manifest.architectures[architecture];
  assert.ok(profile);

  assert.equal(process.argv.length, 4);
  const [, , source, output] = process.argv;
  const apk = await readFile(posix.join(source, apkDirectory, "installed"), "utf8");
  const database = selectedDatabase(apk, profile);
  assert.equal(createHash("sha256").update(database).digest("hex"), profile.apk_database_sha256);
  const files = packageFiles(database);
  const inputNode = posix.join(source, "usr/local/bin/node");
  assert.equal(await fileDigest(inputNode, "sha256", "hex"), profile.node_sha256);

  await mkdir(output);
  await copyPackageFiles(source, output, files);
  await mkdir(posix.join(output, apkDirectory), { recursive: true });
  await writeFile(posix.join(output, apkDirectory, "installed"), database, { mode: 0o644 });
  await mkdir(posix.join(output, "nodejs/bin"), { recursive: true });
  await copyFile(inputNode, posix.join(output, "nodejs/bin/node"));
  console.log(JSON.stringify({
    kind: "independent-peer-runtime-assembly", state: "passed", architecture,
    stock_manifest_digest: profile.manifest_digest, node_sha256: profile.node_sha256,
    apk_database_sha256: profile.apk_database_sha256, packages: profile.packages,
    package_payload_files: files.size,
  }));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => {
    console.error("Pinned runtime assembly failed;no image qualification");
    process.exitCode = 1;
  });
}
