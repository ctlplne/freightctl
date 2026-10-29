import assert from "node:assert/strict";
import { test } from "node:test";
import { build } from "esbuild";
import path from "node:path";
import { fileURLToPath } from "node:url";
const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const bundle = await build({
  absWorkingDir: web,
  entryPoints: ["src/onboarding-types.ts"],
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const {
  asOnboardingDefinition,
  asOnboardingResult,
  asOnboardingPlan,
  onboardingFingerprint,
} = await import(
  "data:text/javascript;base64," +
    Buffer.from(bundle.outputFiles[0].contents).toString("base64")
);
const id = "11111111-1111-4111-8111-111111111111",
  contact = "22222222-2222-4222-8222-222222222222",
  requirement = "33333333-3333-4333-8333-333333333333",
  actor = "44444444-4444-4444-8444-444444444444",
  event = "55555555-5555-4555-8555-555555555555";
function definition() {
  return {
    schema_version: 1,
    name: "Payroll <A> & B",
    contacts: [
      {
        id: contact,
        name: "José",
        role: "Operations",
        email: "ops@freightctl.invalid",
        phone: "",
      },
    ],
    requirements: [
      {
        id: requirement,
        name: "Settlement",
        contact_id: contact,
        direction: "send",
        protocol: "sftp",
        required_receipt: "business",
        receipt_contract: "ACK-v1",
        notes: "\nReceiver > note\u2028second\tline\r\n",
      },
    ],
  };
}
function command() {
  return {
    plan_id: id,
    expected_version: 0,
    expected_authority_revision: 1,
    definition: definition(),
  };
}
function plan() {
  const d = definition();
  return {
    id,
    version: 1,
    definition_hash: onboardingFingerprint(d),
    state: "draft",
    name: d.name,
    author_id: actor,
    event_id: event,
    created_at: "2026-10-29T16:00:00Z",
    definition: d,
  };
}
test("onboarding fingerprint matches independent Go encoding including HTML, NFC and line endings", () => {
  assert.equal(
    onboardingFingerprint(definition()),
    "718145463a3ffecc6e54e2bd41cac37e08a1371512b81c02f430703859918179",
  );
  const reordered = Object.fromEntries(Object.entries(definition()).reverse());
  assert.equal(
    onboardingFingerprint(reordered),
    onboardingFingerprint(definition()),
  );
});
test("a draft receipt joins exact reviewed content, author, identity and version", () => {
  assert.equal(
    asOnboardingResult({ plan: plan(), replayed: true }, command(), actor).id,
    id,
  );
  for (const change of [
    { id: contact },
    { version: 2 },
    { author_id: contact },
    { state: "active" },
    { definition_hash: "0".repeat(64) },
    { event_id: undefined },
  ])
    assert.throws(() =>
      asOnboardingResult(
        { plan: { ...plan(), ...change }, replayed: false },
        command(),
        actor,
      ),
    );
  const changed = definition();
  changed.requirements[0].required_receipt = "transport";
  const wrong = {
    ...plan(),
    definition: changed,
    definition_hash: onboardingFingerprint(changed),
  };
  assert.throws(() =>
    asOnboardingResult({ plan: wrong, replayed: false }, command(), actor),
  );
});
test("contact references, Unicode and document budgets cannot change or escape the reviewed plan", () => {
  const transforms = [
    (d) => {
      d.requirements[0].contact_id = id;
    },
    (d) => {
      d.contacts.push({ ...d.contacts[0] });
    },
    (d) => {
      d.contacts[0].name = "Jose\u0301";
    },
    (d) => {
      d.contacts[0].name = "Bad\nname";
    },
    (d) => {
      d.contacts[0].name = "\ud800";
    },
    (d) => {
      d.requirements[0].notes = "x".repeat(2049);
    },
    (d) => {
      d.requirements[0].required_receipt = "exactly_once";
    },
  ];
  for (const transform of transforms) {
    const d = definition();
    transform(d);
    assert.throws(() => asOnboardingDefinition(d));
  }
  const d = definition();
  d.endpoint = "https://untrusted.invalid";
  d.permissions = ["admin"];
  const parsed = asOnboardingDefinition(d);
  assert.equal(parsed.endpoint, undefined);
  assert.equal(parsed.permissions, undefined);
  assert.equal(asOnboardingPlan(plan()).state, "draft");
});
