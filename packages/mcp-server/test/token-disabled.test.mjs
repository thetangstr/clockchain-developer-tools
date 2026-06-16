// When no signing secret is configured, self-serve is OFF: POST /token must
// return 503 (and never mint), so the feature fails closed.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const PORT = 39518;
const BASE = `http://127.0.0.1:${PORT}`;
const entry = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.js");

let proc;

before(async () => {
  proc = spawn("node", [entry], {
    env: {
      ...process.env,
      MCP_TRANSPORT: "http",
      PORT: String(PORT),
      MCP_AUTH_TOKENS: "team-tok",
      MCP_REQUIRE_AUTH: "1",
      // NOTE: MCP_TOKEN_SIGNING_SECRET intentionally unset.
      MCP_TOKEN_SIGNING_SECRET: "",
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("server did not start in time")), 10_000);
    proc.stderr.on("data", (d) => {
      if (String(d).includes("listening on")) { clearTimeout(t); resolve(); }
    });
    proc.on("exit", (code) => reject(new Error(`server exited early (${code})`)));
  });
});

after(() => { if (proc && !proc.killed) proc.kill(); });

test("POST /token → 503 when self-serve is disabled (no signing secret)", async () => {
  const res = await fetch(`${BASE}/token`, { method: "POST" });
  assert.equal(res.status, 503);
  const body = await res.json();
  assert.equal(body.error, "self_serve_disabled");
});
