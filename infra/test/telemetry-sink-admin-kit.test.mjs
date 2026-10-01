import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

// Phase F kit (founder-applied). Lints the drafted JSON so a later edit cannot
// quietly widen the admin role or open a plaintext ingest path.
const dir = new URL("../clockchain-mcp/telemetry-sink/admin/", import.meta.url);
const json = async (name) => JSON.parse(await readFile(new URL(name, dir), "utf8"));
const BOX = "arn:aws:ec2:us-west-2:570035913370:instance/i-0d6765d143da7e1ea";

test("trust: only IAM user Yang, only with fresh MFA", async () => {
  const doc = await json("trust-policy.json");
  assert.equal(doc.Statement.length, 1);
  const [s] = doc.Statement;
  assert.equal(s.Effect, "Allow");
  assert.deepEqual(s.Principal, { AWS: "arn:aws:iam::570035913370:user/Yang" });
  assert.equal(s.Action, "sts:AssumeRole");
  assert.equal(s.Condition.Bool["aws:MultiFactorAuthPresent"], "true");
  assert.ok(Number(s.Condition.NumericLessThan["aws:MultiFactorAuthAge"]) <= 3600);
});

test("permissions: SendCommand only MintIngest on the box; StartSession only MintQuery with doc check", async () => {
  const doc = await json("permissions-policy.json");
  const actions = doc.Statement.flatMap((s) => [].concat(s.Action));
  assert.ok(!actions.some((a) => a.includes("*")), "no wildcard actions");
  for (const s of doc.Statement) assert.equal(s.Effect, "Allow");
  const send = doc.Statement.filter((s) => [].concat(s.Action).includes("ssm:SendCommand"));
  assert.equal(send.length, 1);
  assert.deepEqual([...send[0].Resource].sort(), [
    "arn:aws:ec2:us-west-2:570035913370:instance/i-0d6765d143da7e1ea",
    "arn:aws:ssm:us-west-2:570035913370:document/ClockchainSinkAdmin-MintIngest",
  ]);
  const start = doc.Statement.filter((s) => [].concat(s.Action).includes("ssm:StartSession"));
  assert.equal(start.length, 1);
  assert.deepEqual([...start[0].Resource].sort(), [
    BOX, "arn:aws:ssm:us-west-2:570035913370:document/ClockchainSinkAdmin-MintQuery",
  ]);
  assert.equal(start[0].Condition.BoolIfExists["ssm:SessionDocumentAccessCheck"], "true");
  const starRes = doc.Statement.filter((s) => s.Resource === "*").flatMap((s) => [].concat(s.Action));
  for (const a of starRes) assert.match(a, /^ssm:(Get|List)/, `only read actions on *: ${a}`);
  assert.ok(!actions.some((a) => /^(iam|sts|ec2|s3):/.test(a)));
});

test("MintIngest: sealTo required, strict params, ciphertext-only output", async () => {
  const doc = await json("ClockchainSinkAdmin-MintIngest.json");
  const p = doc.parameters;
  assert.deepEqual(Object.keys(p).sort(), ["role", "runId", "sealTo"]);
  for (const v of Object.values(p)) assert.equal(v.default, undefined, "no defaults: every value explicit");
  assert.equal(p.runId.allowedPattern, "^[A-Za-z0-9_-]{1,64}$");
  assert.deepEqual(p.role.allowedValues, ["buyer", "provider"]);
  assert.equal(p.sealTo.allowedPattern, "^0x[0-9a-f]{64}$");
  const script = doc.mainSteps[0].inputs.runCommand.join("\n");
  assert.match(script, /mint-cli\.js ingest --runId '\{\{runId\}\}' --role '\{\{role\}\}' --seal-to '\{\{sealTo\}\}'/);
  assert.match(script, /has\("token"\)/, "plaintext output refused");
  assert.match(script, /\{runId: \.record\.runId, role: \.record\.role, sealed: \.sealed\}/);
});

test("MintQuery: interactive session doc, elevated, query kinds only", async () => {
  const doc = await json("ClockchainSinkAdmin-MintQuery.json");
  assert.equal(doc.schemaVersion, "1.0");
  assert.equal(doc.sessionType, "InteractiveCommands");
  assert.deepEqual(doc.parameters.kind.allowedValues, ["query", "global-query"]);
  assert.equal(doc.parameters.runId.allowedPattern, "^([A-Za-z0-9_-]{1,64})?$");
  assert.equal(doc.properties.linux.runAsElevated, true);
  assert.doesNotMatch(doc.properties.linux.commands, /\bingest\b/);
});

test("alert: SendCommand/StartSession to the box by anyone but the admin role", async () => {
  const doc = await json("alert-event-pattern.json");
  assert.deepEqual(doc.detail.eventName, ["SendCommand", "StartSession"]);
  assert.match(JSON.stringify(doc.detail.userIdentity), /anything-but.*assumed-role\/clockchain-telemetry-sink-admin\//);
  assert.match(JSON.stringify(doc.detail.$or), /i-0d6765d143da7e1ea/);
});
