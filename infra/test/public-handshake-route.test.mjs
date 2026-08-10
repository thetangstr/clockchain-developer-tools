import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const repoRoot = path.resolve(new URL("../..", import.meta.url).pathname);

test("the dedicated handshake path stays public while health remains unauthenticated", async () => {
  const source = await readFile(
    path.join(repoRoot, "packages", "mcp-server", "src", "http.ts"),
    "utf8",
  );
  const health = source.indexOf("if (isHealthCheck(req.method, req.url))");
  const route = source.indexOf('if (pathOf(req.url) === "/handshake/mcp")');
  const auth = source.indexOf("const auth: AuthOutcome");
  assert.ok(health >= 0 && route > health && auth > route);
  assert.match(source.slice(route, auth), /getPublicHandshakeHandler/);
  assert.match(source.slice(route, auth), /agent_handshake_unavailable/);
});

test("the public endpoint remains isolated from the authenticated MCP inventory", async () => {
  const source = await readFile(
    path.join(repoRoot, "packages", "mcp-server", "src", "agent-handshake", "v2", "public-tools.ts"),
    "utf8",
  );
  for (const name of [
    "agent_handshake_invite",
    "agent_handshake_accept_invitation",
    "agent_handshake_join",
    "agent_handshake_status",
    "agent_handshake_next",
    "agent_handshake_submit",
    "agent_handshake_get_certificate",
  ]) assert.match(source, new RegExp(`"${name}"`));
  assert.doesNotMatch(source, /clockchain_get_time|clockchain_log|["']handshake_join["']/);
});
