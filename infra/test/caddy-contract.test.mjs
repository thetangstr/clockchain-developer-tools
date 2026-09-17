import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const caddyFile = path.resolve(new URL("../clockchain-mcp/Caddyfile", import.meta.url).pathname);

test("the plain AWS hostname proxies unchanged to the production MCP service", async () => {
  const source = await readFile(caddyFile, "utf8");
  const match = source.match(/mcp-aws\.clockchain\.network\s*\{([\s\S]*?)\n\}/);
  assert.ok(match, "mcp-aws site block exists");
  assert.match(match[1], /reverse_proxy\s+mcp:8080/);
  assert.doesNotMatch(match[1], /handle_path|uri\s+(?:strip_prefix|replace)|rewrite/);
});

test("the public hostname keeps production untouched and isolates the staging prefix", async () => {
  const source = await readFile(caddyFile, "utf8");
  const match = source.match(/mcp\.clockchain\.network\s*\{([\s\S]*?)\n\}/);
  assert.ok(match, "mcp.clockchain.network site block exists");
  const block = match[1];
  // Staging lives only inside a prefix-stripping handle_path routed at the staging
  // container — never at production's service.
  const staging = block.match(/handle_path\s+\/staging\/\*\s*\{([\s\S]*?)\n\t\}/);
  assert.ok(staging, "handle_path /staging/* block exists");
  assert.match(staging[1], /reverse_proxy\s+mcp-staging:8080/);
  assert.match(staging[1], /header_up\s+X-Forwarded-Prefix\s+\/staging/);
  // Everything outside the staging block must proxy unchanged to production.
  const rest = block.replace(staging[0], "");
  assert.match(rest, /reverse_proxy\s+mcp:8080/);
  assert.doesNotMatch(rest, /handle_path|uri\s+(?:strip_prefix|replace)|rewrite|mcp-staging/);
  assert.doesNotMatch(source, /role-access|responderAccess|initiatorAccess|capability/i);
});
