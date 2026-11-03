// Hosted packets checked by the Shadow library's own command-line verifiers, TypeScript and Python, exactly as a
// relying party runs them: `shadow-verify packet.json --pin pin.json`, exit 0 for pass.
//
// Needs the clockchain-shadow checkout (SHADOW_LIB_DIR, or ../clockchain-shadow beside this repository or its main
// checkout), a Node that runs TypeScript itself (process.features.typescript, Node 22.18+) for the TypeScript CLI, and
// uv for the Python one. Each check is skipped, saying why, when its tool is missing (CI has neither).
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { ShadowService } from "../dist/shadow/service.js";
import { FakeLedger } from "./helpers/shadow-fake-ledger.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..", "..");

function libraryDir() {
  if (process.env.SHADOW_LIB_DIR) return process.env.SHADOW_LIB_DIR;
  const beside = (root) => path.join(root, "..", "clockchain-shadow");
  if (existsSync(beside(repoRoot))) return beside(repoRoot);
  try {
    const common = execFileSync("git", ["rev-parse", "--path-format=absolute", "--git-common-dir"], { cwd: repoRoot, encoding: "utf8" }).trim();
    return beside(path.dirname(common));
  } catch {
    return beside(repoRoot);
  }
}

const lib = libraryDir();
const tsCli = path.join(lib, "ts", "bin", "shadow-verify.ts");
const pyProject = path.join(lib, "py");
const tsSkip = !existsSync(tsCli) ? `no library at ${lib}` : typeof process.features?.typescript !== "string" ? `Node ${process.version} cannot run TypeScript` : false;
const uvFound = spawnSync("uv", ["--version"], { encoding: "utf8" }).status === 0;
const pySkip = !existsSync(path.join(pyProject, "pyproject.toml")) ? `no library at ${lib}` : !uvFound ? "uv is not installed" : false;

const O = "jti:33333333-3333-4333-8333-333333333333";
const BASE = "https://mcp.example.test";

/** Three hosted sessions as files: a full one, one with anchors still pending, and one whose ledger speaks the gateway's old time form. */
async function writePackets() {
  const dir = mkdtempSync(path.join(tmpdir(), "shadow-cli-"));
  const out = [];
  const save = async (svc, name, closed) => {
    const cap = new URL(closed.links.packet).pathname.split("/").pop().replace(/\.json$/, "");
    const doc = JSON.parse(await svc.packetForCap(cap));
    const packet = path.join(dir, `${name}.packet.json`), pin = path.join(dir, `${name}.pin.json`);
    writeFileSync(packet, JSON.stringify(doc.packet, null, 1));
    writeFileSync(pin, JSON.stringify(closed.pin, null, 2));
    out.push({ name, packet, pin, doc });
  };
  for (const variant of ["full", "pending", "gateway-times"]) {
    const fake = new FakeLedger();
    if (variant === "gateway-times") fake.gatewayTimes = true;
    const svc = new ShadowService({ stateDir: mkdtempSync(path.join(tmpdir(), "shadow-cli-state-")), ledger: () => fake, sleep: async () => {}, log: () => {} });
    svc.sweep();
    if (variant === "pending") fake.down = true;
    const s = await svc.startSession(O, { title: variant, agents: [{ id: "researcher" }, { id: "writer" }] }, BASE);
    const id = s.session_id;
    await svc.record(O, { session_id: id, agent: "researcher", kind: "task", content: "Collect three sources" });
    await svc.record(O, { session_id: id, agent: "researcher", kind: "prompt", content: "Find sources on tide clocks" });
    await svc.record(O, { session_id: id, agent: "researcher", kind: "tool_call", content: { tool: "web_search", args: { q: "tide clock", n: 3, score: 0.75 } } });
    await svc.record(O, { session_id: id, agent: "researcher", kind: "tool_result", content: { tool: "web_search", result: ["a", "b", "c"] } });
    await svc.record(O, { session_id: id, agent: "researcher", kind: "message", content: "Three sources found." });
    await svc.checkpoint(O, { session_id: id });
    await svc.record(O, { session_id: id, agent: "writer", kind: "task", content: "Draft the note" });
    await svc.record(O, { session_id: id, agent: "writer", kind: "file", content: { path: "note.md", content: "# Tide clocks\n" } });
    await svc.record(O, { session_id: id, agent: "writer", kind: "note", content: "Kept it to one page." });
    const closed = await svc.close(O, { session_id: id, status: "succeeded" }, BASE);
    await save(svc, variant, closed);
  }
  // A negative control: one step's content changed after signing.
  const tampered = structuredClone(out[0].doc.packet);
  tampered.events[4].body.payload.content.text = "Four sources found.";
  const tp = path.join(dir, "tampered.packet.json");
  writeFileSync(tp, JSON.stringify(tampered));
  return { packets: out, tampered: { packet: tp, pin: out[0].pin } };
}

const files = await writePackets();

function run(cmd, args) {
  const r = spawnSync(cmd, args, { encoding: "utf8", timeout: 120_000 });
  let report;
  try {
    report = JSON.parse(r.stdout);
  } catch {
    report = undefined;
  }
  return { status: r.status, report, stderr: r.stderr };
}

test("the library's TypeScript shadow-verify passes hosted packets (exit 0) and fails a tampered one", { skip: tsSkip }, () => {
  for (const p of files.packets) {
    const r = run(process.execPath, [tsCli, p.packet, "--pin", p.pin, "--json"]);
    assert.equal(r.report?.result, "pass", `${p.name}: ${r.stderr}\n${JSON.stringify(r.report?.checks, null, 1)}`);
    assert.equal(r.status, 0, p.name);
  }
  const bad = run(process.execPath, [tsCli, files.tampered.packet, "--pin", files.tampered.pin, "--json"]);
  assert.equal(bad.status, 1);
  assert.ok(bad.report.failed.includes("content"));
});

test("the library's Python shadow-verify passes hosted packets (exit 0) and fails a tampered one", { skip: pySkip }, () => {
  for (const p of files.packets) {
    const r = run("uv", ["run", "--quiet", "--project", pyProject, "shadow-verify", p.packet, "--pin", p.pin, "--json"]);
    assert.equal(r.report?.result, "pass", `${p.name}: ${r.stderr}\n${JSON.stringify(r.report?.checks, null, 1)}`);
    assert.equal(r.status, 0, p.name);
  }
  const bad = run("uv", ["run", "--quiet", "--project", pyProject, "shadow-verify", files.tampered.packet, "--pin", files.tampered.pin, "--json"]);
  assert.equal(bad.status, 1);
  assert.ok(bad.report.failed.includes("content"));
});
