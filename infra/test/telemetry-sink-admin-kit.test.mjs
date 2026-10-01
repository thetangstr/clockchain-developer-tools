import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

// Phase F kit (founder-applied). Lints the drafted JSON so a later edit cannot
// quietly widen the admin role, open a plaintext ingest path, or drop an alert.
const dir = new URL("../clockchain-mcp/telemetry-sink/admin/", import.meta.url);
const json = async (name) => JSON.parse(await readFile(new URL(name, dir), "utf8"));
const BOX_ID = "i-0d6765d143da7e1ea";
const BOX = `arn:aws:ec2:us-west-2:570035913370:instance/${BOX_ID}`;
const ADMIN_ROLE = "arn:aws:iam::570035913370:role/clockchain-telemetry-sink-admin";
const docArn = (n) => `arn:aws:ssm:us-west-2:570035913370:document/ClockchainSinkAdmin-${n}`;
const RUN_ID = "^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$";
const OPT_RUN_ID = "^([A-Za-z0-9][A-Za-z0-9_-]{0,63})?$";

test("trust: exactly one principal (IAM user Yang), only with fresh MFA", async () => {
  const doc = await json("trust-policy.json");
  assert.equal(doc.Statement.length, 1);
  const [s] = doc.Statement;
  assert.equal(s.Effect, "Allow");
  assert.deepEqual(s.Principal, { AWS: "arn:aws:iam::570035913370:user/Yang" });
  assert.equal(typeof s.Principal.AWS, "string", "exactly one principal ARN, not a list");
  assert.equal(s.Action, "sts:AssumeRole");
  assert.equal(s.Condition.Bool["aws:MultiFactorAuthPresent"], "true");
  assert.ok(Number(s.Condition.NumericLessThan["aws:MultiFactorAuthAge"]) <= 3600);
});

test("permissions: only the ClockchainSinkAdmin docs on the box; no AWS-*/SSM-* docs", async () => {
  const doc = await json("permissions-policy.json");
  const text = JSON.stringify(doc);
  assert.doesNotMatch(text, /document\/AWS-|document\/SSM-|SSM-SessionManagerRunShell/);
  const actions = doc.Statement.flatMap((s) => [].concat(s.Action));
  assert.ok(!actions.some((a) => a.includes("*")), "no wildcard actions");
  for (const s of doc.Statement) assert.equal(s.Effect, "Allow");
  const send = doc.Statement.filter((s) => [].concat(s.Action).includes("ssm:SendCommand"));
  assert.equal(send.length, 1);
  assert.deepEqual([...send[0].Resource].sort(), [
    BOX, docArn("ListTokens"), docArn("MintIngest"), docArn("SessionCleanup"),
  ].sort());
  const start = doc.Statement.filter((s) => [].concat(s.Action).includes("ssm:StartSession"));
  assert.equal(start.length, 1);
  assert.deepEqual([...start[0].Resource].sort(), [BOX, docArn("MintQuery")].sort());
  assert.equal(start[0].Condition.BoolIfExists["ssm:SessionDocumentAccessCheck"], "true");
  const starRes = doc.Statement.filter((s) => s.Resource === "*").flatMap((s) => [].concat(s.Action));
  for (const a of starRes) assert.match(a, /^ssm:(Get|List)/, `only read actions on *: ${a}`);
  assert.ok(!actions.some((a) => /^(iam|sts|ec2|s3|events|sns|cloudtrail):/.test(a)));
});

test("runId pattern rejects a leading '-' or '_' (flag injection) and over-long ids", () => {
  const re = new RegExp(RUN_ID);
  for (const ok of ["a", "run-1", "0f3c_A-9", "x".repeat(64)]) assert.ok(re.test(ok), ok);
  for (const bad of ["", "-r", "_r", "--runId", "a b", "a;b", "x".repeat(65), "a/b"]) assert.ok(!re.test(bad), bad);
  const opt = new RegExp(OPT_RUN_ID);
  assert.ok(opt.test(""));
  assert.ok(!opt.test("-r"));
});

test("MintIngest: sealTo required, strict params, sealed-only output", async () => {
  const doc = await json("ClockchainSinkAdmin-MintIngest.json");
  const p = doc.parameters;
  assert.deepEqual(Object.keys(p).sort(), ["role", "runId", "sealTo"]);
  for (const v of Object.values(p)) assert.equal(v.default, undefined, "no defaults: every value explicit");
  assert.equal(p.runId.allowedPattern, RUN_ID);
  assert.deepEqual(p.role.allowedValues, ["buyer", "provider"]);
  assert.equal(p.sealTo.allowedPattern, "^0x[0-9a-f]{64}$");
  const script = doc.mainSteps[0].inputs.runCommand.join("\n");
  assert.match(script, /mint-cli\.js ingest --runId '\{\{runId\}\}' --role '\{\{role\}\}' --seal-to '\{\{sealTo\}\}'/);
  assert.doesNotMatch(script, /\bjq\b/, "no jq dependency on the box");
  assert.match(script, /"token" in o/);
  assert.match(script, /typeof sealed!=="object"\|\|Array\.isArray\(sealed\)/);
  assert.match(script, /\{runId:r\.runId,role:r\.role,tokenId:r\.tokenId,sealed\}/);
});

function runDocScript(script, fakeDockerBody) {
  const temp = mkdtempSync(path.join(tmpdir(), "sink-admin-doc-"));
  const docker = path.join(temp, "docker");
  writeFileSync(docker, `#!/bin/sh\n${fakeDockerBody}\n`);
  chmodSync(docker, 0o755);
  return spawnSync("sh", ["-c", script], { encoding: "utf8", env: { ...process.env, PATH: `${temp}:${process.env.PATH}` } });
}

test("MintIngest output filter: passes a sealed mint, refuses plaintext / array / wrong run", async () => {
  const doc = await json("ClockchainSinkAdmin-MintIngest.json");
  const script = doc.mainSteps[0].inputs.runCommand.join("\n")
    .replaceAll("{{runId}}", "r1").replaceAll("{{role}}", "buyer").replaceAll("{{sealTo}}", `0x${"a".repeat(64)}`);
  const fake = (mintOut) => `case "$1" in ps) echo cid ;; exec) if [ "$2" = -i ]; then shift 3; exec "$@"; fi; echo '${mintOut}' ;; esac`;
  const good = runDocScript(script, fake('{"record":{"runId":"r1","role":"buyer","kind":"ingest","tokenId":"0xab"},"sealed":{"v":3,"ct":"aa"}}'));
  assert.equal(good.status, 0, good.stderr);
  assert.deepEqual(JSON.parse(good.stdout), { runId: "r1", role: "buyer", tokenId: "0xab", sealed: { v: 3, ct: "aa" } });
  for (const bad of [
    '{"record":{"runId":"r1","role":"buyer","kind":"ingest","tokenId":"0xab"},"token":"otlp-plain"}',
    '{"record":{"runId":"r1","role":"buyer","kind":"ingest"},"sealed":["x"]}',
    '{"record":{"runId":"r2","role":"buyer","kind":"ingest"},"sealed":{"v":3}}',
    '{"record":{"runId":"r1","role":"provider","kind":"ingest"},"sealed":{"v":3}}',
    "not json",
  ]) {
    const r = runDocScript(script, fake(bad));
    assert.equal(r.status, 66, `${bad}: ${r.stdout}${r.stderr}`);
    assert.equal(r.stdout, "");
  }
});

test("MintQuery: interactive session doc, elevated, query kinds only", async () => {
  const doc = await json("ClockchainSinkAdmin-MintQuery.json");
  assert.equal(doc.schemaVersion, "1.0");
  assert.equal(doc.sessionType, "InteractiveCommands");
  assert.deepEqual(doc.parameters.kind.allowedValues, ["query", "global-query"]);
  assert.equal(doc.parameters.runId.allowedPattern, OPT_RUN_ID);
  assert.equal(doc.properties.linux.runAsElevated, true);
  assert.doesNotMatch(doc.properties.linux.commands, /\bingest\b/);
  assert.match(doc.description, /ipcTempFile\.log/);
});

test("ListTokens + SessionCleanup: read-only listing; cleanup scoped to the admin's sessions", async () => {
  const list = await json("ClockchainSinkAdmin-ListTokens.json");
  assert.equal(list.parameters.runId.allowedPattern, OPT_RUN_ID);
  const ls = list.mainSteps[0].inputs.runCommand.join("\n");
  assert.match(ls, /node dist\/list-tokens-cli\.js/);
  assert.doesNotMatch(ls, /mint-cli|\brm\b|>\s*[\/\w]/, "no mint, no delete, no file writes");
  const clean = await json("ClockchainSinkAdmin-SessionCleanup.json");
  assert.equal(clean.parameters.sessionId.allowedPattern, "^yang-sink-admin-[A-Za-z0-9]{1,64}$");
  const cs = clean.mainSteps[0].inputs.runCommand.join("\n");
  assert.match(cs, /\/var\/lib\/amazon\/ssm\/\*\/session\/orchestration\/'\{\{sessionId\}\}'/);
  assert.match(cs, /SessionLogsDestination/);
});

const branches = (doc) => doc.detail.$or;
const has = (doc, source, names) => branches(doc).some((b) => b.eventSource?.[0] === source
  && names.every((n) => b.eventName.includes(n)));

test("us-west-2 alert: box access (instanceIds / targets / target) except the admin role, incl. missing arn", async () => {
  const doc = await json("alert-event-pattern.json");
  const notAdmin = [{ "anything-but": { prefix: "arn:aws:sts::570035913370:assumed-role/clockchain-telemetry-sink-admin/" } }, { exists: false }];
  const send = branches(doc).filter((b) => b.eventName.includes("SendCommand"));
  assert.ok(send.some((b) => JSON.stringify(b.requestParameters.instanceIds) === JSON.stringify([BOX_ID])), "instanceIds branch");
  assert.ok(send.some((b) => b.requestParameters.targets?.key?.[0]?.exists === true), "tag-targets branch");
  const start = branches(doc).find((b) => b.eventName.includes("StartSession"));
  assert.deepEqual(start.requestParameters.target, [BOX_ID]);
  for (const b of [...send, start]) assert.deepEqual(b.userIdentity.arn, notAdmin);
});

test("us-west-2 alert: associations, docs, instance connect, instance attrs, SG, alerting + trail tamper, role use", async () => {
  const doc = await json("alert-event-pattern.json");
  assert.ok(has(doc, "ssm.amazonaws.com", ["CreateAssociation", "UpdateAssociation", "StartAssociationsOnce"]));
  const docs = branches(doc).find((b) => b.eventName.includes("UpdateDocument"));
  for (const n of ["DeleteDocument", "UpdateDocumentDefaultVersion", "ModifyDocumentPermission"]) assert.ok(docs.eventName.includes(n), n);
  assert.deepEqual(docs.requestParameters.name, [{ prefix: "ClockchainSinkAdmin-" }]);
  assert.ok(has(doc, "ec2-instance-connect.amazonaws.com", ["SendSSHPublicKey", "SendSerialConsoleSSHPublicKey"]));
  const attr = branches(doc).find((b) => b.eventName.includes("ModifyInstanceAttribute"));
  assert.deepEqual(attr.requestParameters.instanceId, [BOX_ID]);
  assert.ok(has(doc, "ec2.amazonaws.com", ["AuthorizeSecurityGroupIngress"]));
  assert.ok(has(doc, "events.amazonaws.com", ["DisableRule", "DeleteRule", "PutRule", "RemoveTargets", "PutTargets"]));
  assert.ok(has(doc, "sns.amazonaws.com", ["Unsubscribe", "SetTopicAttributes", "DeleteTopic", "Subscribe"]));
  assert.ok(has(doc, "cloudtrail.amazonaws.com", ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"]));
  const assume = branches(doc).find((b) => b.eventSource[0] === "sts.amazonaws.com");
  assert.deepEqual(assume.requestParameters.roleArn, [ADMIN_ROLE]);
});

test("us-east-1 alert: IAM changes on the role and on user Yang, plus role assumption", async () => {
  const doc = await json("alert-iam-event-pattern.json");
  const role = branches(doc).find((b) => b.requestParameters?.roleName);
  assert.deepEqual(role.requestParameters.roleName, ["clockchain-telemetry-sink-admin"]);
  for (const n of ["UpdateAssumeRolePolicy", "PutRolePolicy", "AttachRolePolicy", "DetachRolePolicy", "DeleteRolePolicy", "DeleteRole"]) {
    assert.ok(role.eventName.includes(n), n);
  }
  const user = branches(doc).find((b) => b.requestParameters?.userName);
  assert.deepEqual(user.requestParameters.userName, ["Yang"]);
  for (const n of ["EnableMFADevice", "DeactivateMFADevice", "CreateAccessKey", "UpdateAccessKey", "DeleteAccessKey", "CreateLoginProfile", "UpdateLoginProfile"]) {
    assert.ok(user.eventName.includes(n), n);
  }
  const assume = branches(doc).find((b) => b.eventSource[0] === "sts.amazonaws.com");
  assert.deepEqual(assume.requestParameters.roleArn, [ADMIN_ROLE]);
});

test("orchestrator scoped role (Tier 2 draft): no root shell, no IAM/doc/alerting write", async () => {
  const doc = await json("orchestrator-scoped-role.json");
  const allow = doc.Statement.filter((s) => s.Effect === "Allow");
  const deny = doc.Statement.filter((s) => s.Effect === "Deny");
  const allowed = allow.flatMap((s) => [].concat(s.Action));
  for (const a of allowed) assert.doesNotMatch(a, /^(iam|events|sns|cloudtrail):|Document$|StartSession|\*/, a);
  const send = allow.find((s) => [].concat(s.Action).includes("ssm:SendCommand"));
  assert.doesNotMatch(JSON.stringify(send.Resource), /AWS-|SSM-|ClockchainSinkAdmin/);
  const denied = deny.flatMap((s) => [].concat(s.Action));
  for (const a of ["iam:*", "events:*", "sns:*", "ssm:CreateDocument", "ssm:UpdateDocument", "ssm:StartSession", "cloudtrail:StopLogging", "ec2:ModifyInstanceAttribute", "ec2-instance-connect:*"]) {
    assert.ok(denied.includes(a), a);
  }
  const shell = deny.find((s) => s.Sid === "DenyRootShellSessionsAndAssociations");
  assert.ok(shell.Resource.some((r) => r.endsWith("document/AWS-*")));
  const sts = deny.find((s) => [].concat(s.Action).includes("sts:AssumeRole"));
  assert.equal(sts.Resource, ADMIN_ROLE);
  // Every statement is cited in FOUNDER-STEPS.md.
  const steps = readFileSync(new URL("FOUNDER-STEPS.md", dir), "utf8");
  for (const s of doc.Statement) assert.ok(steps.includes(`\`${s.Sid}\``), `FOUNDER-STEPS cites ${s.Sid}`);
});
