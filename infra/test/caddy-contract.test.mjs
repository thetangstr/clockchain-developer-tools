import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const caddyFile = path.resolve(new URL("../clockchain-mcp/Caddyfile", import.meta.url).pathname);

test("both public hostnames proxy the unchanged handshake path to the existing MCP service", async () => {
  const source = await readFile(caddyFile, "utf8");
  for (const host of ["mcp-aws.clockchain.network", "mcp.clockchain.network"]) {
    const match = source.match(new RegExp(`${host.replaceAll(".", "\\.")}\\s*\\{([\\s\\S]*?)\\n\\}`));
    assert.ok(match, `${host} site block exists`);
    assert.match(match[1], /reverse_proxy\s+mcp:8080/);
    assert.doesNotMatch(match[1], /handle_path|uri\s+(?:strip_prefix|replace)|rewrite/);
  }
  assert.doesNotMatch(source, /role-access|responderAccess|initiatorAccess|capability/i);
});
