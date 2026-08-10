import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const composeFile = path.resolve(new URL("../clockchain-mcp/docker-compose.yml", import.meta.url).pathname);

test("compose carries only server-side v2 configuration into persistent services", async () => {
  const source = await readFile(composeFile, "utf8");
  for (const name of [
    "AGENT_HANDSHAKE_RELEASE_PIN",
    "AGENT_HANDSHAKE_ROLE_ACCESS_ACTIVE",
    "AGENT_HANDSHAKE_ROLE_ACCESS_PREVIOUS",
    "AGENT_HANDSHAKE_V2_INVITATION_FILE",
    "AGENT_HANDSHAKE_V2_STATE_FILE",
    "AGENT_HANDSHAKE_INVITES_PER_HOUR",
    "AGENT_HANDSHAKE_CALLS_PER_MINUTE",
    "AGENT_HANDSHAKE_TRUSTED_PROXY",
  ]) assert.match(source, new RegExp(`${name}:`));
  assert.match(source, /AGENT_HANDSHAKE_V2_INVITATION_FILE:\s*\/app\/state\/agent-handshake-v2-invitations\.json/);
  assert.match(source, /AGENT_HANDSHAKE_V2_STATE_FILE:\s*\/app\/state\/agent-handshake-v2-state\.json/);
  assert.match(source, /AGENT_HANDSHAKE_INVITES_PER_HOUR:\s*"5"/);
  assert.match(source, /AGENT_HANDSHAKE_CALLS_PER_MINUTE:\s*"120"/);
  assert.match(source, /AGENT_HANDSHAKE_TRUSTED_PROXY:\s*"172\.30\.0\.3"/);
  assert.doesNotMatch(source, /responderAccess|initiatorAccess|rawInvitation|privateKeyPem/);
});

test("the v2 host uses a private root file and restart-safe bounded funding state", async () => {
  const source = await readFile(composeFile, "utf8");
  assert.match(source, /command:\s*\["node",\s*"bin\/agent-handshake-host\.mjs"\]/);
  assert.match(source, /AGENT_HANDSHAKE_PROTOCOL:\s*"clockchain\.agent-handshake\/v2"/);
  assert.match(source, /CLOCKCHAIN_HOST_ROOT_KEY_FILE:\s*\/app\/keys\/agent-handshake-v2-host-root\.pem/);
  assert.match(source, /CLOCKCHAIN_HOST_ROOT_KEY_ID:/);
  assert.match(source, /AGENT_HANDSHAKE_V2_FUNDING_LEDGER:\s*\/app\/runs\/private\/v2-funding-ledger\.jsonl/);
  assert.match(source, /AGENT_HANDSHAKE_V2_FUNDING_QUEUE_LIMIT:\s*"16"/);
  assert.match(source, /AGENT_HANDSHAKE_V2_FUNDING_ALERT_HOURLY_ETH:\s*"0\.16"/);
  assert.match(source, /AGENT_HANDSHAKE_V2_FUNDING_ALERT_DAILY_ETH:\s*"0\.80"/);
  assert.match(source, /host_runs:\/app\/runs/);
  assert.match(source, /\/app\/keys:ro/);
});

test("Caddy is the only ingress and has the one trusted internal address", async () => {
  const source = await readFile(composeFile, "utf8");
  assert.doesNotMatch(source, /-\s*"8080:8080"/);
  assert.match(source, /subnet:\s*172\.30\.0\.0\/24/);
  assert.match(source, /ipv4_address:\s*172\.30\.0\.2/);
  assert.match(source, /ipv4_address:\s*172\.30\.0\.3/);
});
