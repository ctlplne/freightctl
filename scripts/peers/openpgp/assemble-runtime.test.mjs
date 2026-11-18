import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { packageFiles, RUNTIME_DEPENDENCIES_SHA256, selectedDatabase } from "./assemble-runtime.mjs";

const raw = await readFile(new URL("runtime-dependencies.json", import.meta.url));
const { architectures } = JSON.parse(raw);
const fieldChecksum = "Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA=";

test("the pinned manifest includes the x86-only library and the correct APK architectures", () => {
  assert.equal(createHash("sha256").update(raw).digest("hex"), RUNTIME_DEPENDENCIES_SHA256);
  assert.deepEqual(Object.keys(architectures.arm64.packages), ["alpine-release", "musl", "libgcc", "libstdc++"]);
  assert.deepEqual(Object.keys(architectures.amd64.packages), [...Object.keys(architectures.arm64.packages), "libatomic"]);
  assert.equal(architectures.arm64.apk_architecture, "aarch64");
  assert.equal(architectures.amd64.apk_architecture, "x86_64");
});

test("package selection preserves full records and rejects duplicates, omissions, and substitutions", () => {
  for (const profile of Object.values(architectures)) {
    const records = Object.entries(profile.packages).map(([name, version]) =>
      `P:${name}\nV:${version}\nA:${profile.apk_architecture}\no:origin\nF:lib\nR:${name}\nZ:${fieldChecksum}`);
    const database = records.join("\n\n") + "\n\n";
    assert.equal(selectedDatabase(database + "P:other\nV:1\n\n", profile), database);
    for (const mutation of [database + database, database.replace("1.2.6-r3", "1.2.6-r2"),
      database.replace(profile.apk_architecture, "armv7"), records.slice(1).join("\n\n")]) {
      assert.throws(() => selectedDatabase(mutation, profile));
    }
  }
});

test("every declared file needs a safe name and exactly one checksum", () => {
  const record = `F:usr/lib\nR:library.so\na:0:0:755\nZ:${fieldChecksum}`;
  assert.deepEqual([...packageFiles(record)], [["usr/lib/library.so", fieldChecksum.slice(2)]]);
  for (const text of [record + "\n" + record, record.replace("usr/lib", "../lib"),
    record.replace("library.so", "../library.so"), record.replace("Q1", "Q9"),
    record.replace(`Z:${fieldChecksum}`, ""), record + `\nZ:${fieldChecksum}`]) {
    assert.throws(() => packageFiles(text));
  }
});
