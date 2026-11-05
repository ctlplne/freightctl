import assert from "node:assert/strict";
import { test } from "node:test";
import { build } from "esbuild";
const bundle = await build({
  entryPoints: ["src/types.ts"],
  absWorkingDir: new URL("..", import.meta.url).pathname,
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const { asUpload } = await import(
  "data:text/javascript;base64," +
    Buffer.from(bundle.outputFiles[0].contents).toString("base64")
);
const id = "11111111-1111-4111-8111-111111111111";
const base = {
  id,
  path: "/report.csv",
  expected_size: 210019,
  expected_sha256: "a".repeat(64),
  committed_offset: 65536,
  chunk_count: 1,
  state: "open",
  revision: 2,
};
test("transfer paths bind to the same owned ticket ID without inventing historical fields", () => {
  const path = `/.freightctl/uploads/${id}`;
  assert.deepEqual(asUpload(base), base);
  assert.deepEqual(asUpload({ ...base, sftp_path: "", ftps_path: "" }), base);
  assert.deepEqual(asUpload({ ...base, sftp_path: path, ftps_path: path }), {
    ...base,
    sftp_path: path,
    ftps_path: path,
  });
  for (const field of ["sftp_path", "ftps_path"])
    for (const path of [
      null,
      "/report.csv",
      `/.freightctl/uploads/${id}/extra`,
      "/.freightctl/uploads/22222222-2222-4222-8222-222222222222",
      "ftp://untrusted.invalid/file",
      "../secret",
      `/.freightctl/uploads/${id}\n`,
    ])
      assert.throws(() => asUpload({ ...base, [field]: path }));
});
test("saved acceptance preserves the exact immutable file identity and bounded progress", () => {
  const file = "22222222-2222-4222-8222-222222222222";
  const completed = {
    ...base,
    committed_offset: base.expected_size,
    state: "completed",
    file_id: file,
    acceptance: "durable-held-pending-checks-and-release",
  };
  assert.deepEqual(asUpload(completed), completed);
  for (const changes of [
    { committed_offset: base.expected_size + 1 },
    { expected_sha256: "invalid" },
    { file_id: "other" },
  ])
    assert.throws(() => asUpload({ ...completed, ...changes }));
});
test("status cannot substitute the inspected upload identity or frozen intent", () => {
  const expected = {
    id: base.id,
    path: base.path,
    expected_size: base.expected_size,
    expected_sha256: base.expected_sha256,
  };
  assert.deepEqual(asUpload(base, expected), base);
  for (const changed of [
    { id: "22222222-2222-4222-8222-222222222222" },
    { path: "/other.csv" },
    { expected_size: base.expected_size + 1 },
    { expected_sha256: "b".repeat(64) },
  ])
    assert.throws(() => asUpload({ ...base, ...changed }, expected));
});

const ui = await build({
  entryPoints: ["src/upload-ticket.tsx"],
  absWorkingDir: new URL("..", import.meta.url).pathname,
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const { UploadTicket } = await import(
  "data:text/javascript;base64," +
    Buffer.from(ui.outputFiles[0].contents).toString("base64")
);
const { createElement } = await import("react");
const { renderToStaticMarkup } = await import("react-dom/server");
test("accepted upload enters artifact review with its exact saved identity and integrity", () => {
  const complete = {
    ...base,
    state: "completed",
    committed_offset: base.expected_size,
    file_id: "22222222-2222-4222-8222-222222222222",
    acceptance: "durable-local-integrity-only",
  };
  const calls = [];
  const tree = UploadTicket({
    upload: complete,
    onReview: (hint) => calls.push(hint),
  });
  assert.match(
    renderToStaticMarkup(
      createElement(UploadTicket, { upload: complete, onReview: () => {} }),
    ),
    /Review accepted artifact/,
  );
  assert.equal(calls.length, 0, "rendering published an offer");
  const find = (node) => {
    if (!node || typeof node !== "object") return null;
    if (
      node.type === "button" &&
      node.props.children === "Review accepted artifact"
    )
      return node;
    for (const child of [node.props?.children].flat(3)) {
      const found = find(child);
      if (found) return found;
    }
    return null;
  };
  const action = find(tree);
  assert.ok(action);
  action.props.onClick();
  assert.deepEqual(calls, [
    {
      file_revision_id: complete.file_id,
      size_bytes: complete.expected_size,
      sha256: complete.expected_sha256,
    },
  ]);
  for (const upload of [
    base,
    { ...complete, committed_offset: 1 },
    { ...complete, file_id: undefined },
    { ...complete, state: "aborted" },
  ])
    assert.doesNotMatch(
      renderToStaticMarkup(
        createElement(UploadTicket, { upload, onReview: () => {} }),
      ),
      /Review accepted artifact/,
    );
  assert.doesNotMatch(
    renderToStaticMarkup(createElement(UploadTicket, { upload: complete })),
    /Review accepted artifact/,
  );
  assert.match(
    renderToStaticMarkup(
      createElement(UploadTicket, {
        upload: {
          ...complete,
          acceptance: "durable-held-pending-checks-and-release",
        },
        onReview: () => {},
      }),
    ),
    /Review accepted artifact/,
  );
});
