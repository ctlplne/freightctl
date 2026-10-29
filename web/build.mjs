import * as esbuild from "esbuild";
import { createHash } from "node:crypto";
import { readFile, readdir, mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const hash = (b) => createHash("sha256").update(b).digest("hex");
const result = await esbuild.build({
  absWorkingDir: path.join(root, "web"),
  entryPoints: { app: "src/app.tsx", "hash-worker": "src/hash-worker.ts" },
  outdir: path.join(root, "internal/browser/assets"),
  bundle: true,
  write: false,
  minify: true,
  format: "esm",
  platform: "browser",
  target: ["es2022"],
  define: { "process.env.NODE_ENV": '"production"' },
  legalComments: "linked",
  metafile: true,
});
const outputs = new Map(
  result.outputFiles.map((f) => [path.basename(f.path), f.contents]),
);
outputs.set(
  "index.html",
  new TextEncoder().encode(
    '<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><meta name="referrer" content="no-referrer"><title>freightctl · File exchange</title><link rel="stylesheet" href="/assets/app.css"><script type="module" src="/assets/app.js"></script></head><body><div id="root"></div><noscript>This workspace requires JavaScript. Ordinary CLI and API transfers remain available.</noscript></body></html>\n',
  ),
);
const sourceFiles = [
  "web/package.json",
  "web/package-lock.json",
  "web/tsconfig.json",
  "web/build.mjs",
  "web/THIRD_PARTY_NOTICES.txt",
  ...(await readdir(path.join(root, "web/src")))
    .filter((x) => /\.(ts|tsx|css)$/.test(x))
    .map((x) => "web/src/" + x),
].sort();
outputs.set(
  "third-party-notices.txt",
  new Uint8Array(
    await readFile(path.join(root, "web/THIRD_PARTY_NOTICES.txt")),
  ),
);
const sources = [];
for (const p of sourceFiles)
  sources.push({ path: p, sha256: hash(await readFile(path.join(root, p))) });
const manifest = {
  schema_version: 1,
  sources,
  outputs: [...outputs]
    .map(([name, bytes]) => ({ name, sha256: hash(bytes), size: bytes.length }))
    .sort((a, b) => a.name.localeCompare(b.name)),
  bundled_packages: Object.keys(result.metafile.inputs)
    .filter((x) => x.startsWith("node_modules/"))
    .sort(),
};
outputs.set(
  "manifest.json",
  new TextEncoder().encode(JSON.stringify(manifest, null, 2) + "\n"),
);
const check = process.argv.includes("--check");
const dest = path.join(root, "internal/browser/assets");
if (!check) await mkdir(dest, { recursive: true });
for (const [name, bytes] of outputs) {
  const p = path.join(dest, name);
  if (check) {
    const actual = await readFile(p);
    if (!actual.equals(Buffer.from(bytes)))
      throw new Error("Stale browser artifact: " + name);
  } else await writeFile(p, bytes);
}
const extras = (await readdir(dest)).filter((x) => !outputs.has(x));
if (extras.length)
  throw new Error("Unexpected browser artifacts: " + extras.join(","));
console.log(
  (check ? "Verified" : "Built") +
    " browser artifacts: " +
    manifest.outputs.map((x) => x.name + " " + x.size + " bytes").join(", "),
);
