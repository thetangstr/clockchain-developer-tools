import { existsSync } from "node:fs";
import path from "node:path";

import { readTokenFile } from "./tokens.js";

/**
 * Sink-admin reconciliation listing (D22, Phase F). READ-ONLY: prints one
 * JSON line per minted-token record so the founder can diff the sink's mint
 * history against their own mint log after each run:
 *
 *   docker exec <sink> node dist/list-tokens-cli.js [--runId <id>] [--state-dir /telemetry/state]
 *
 * Fields: runId, role, kind, tokenId (sha256 digest — public identifier, never
 * the token), createdAt, revokedAt. It never prints plaintext (tokens.json
 * holds none), never writes or creates state files, and takes no lock — a
 * listing racing a mint simply shows the earlier snapshot.
 */

const USAGE = "usage: node dist/list-tokens-cli.js [--runId <id>] [--state-dir /telemetry/state]";
const RUN_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

export function runListTokensCli(argv: string[], env: NodeJS.ProcessEnv = process.env): number {
  let runId: string | undefined;
  let stateDir = env.TELEMETRY_STATE_DIR ?? "/telemetry/state";
  for (let i = 0; i < argv.length; i += 2) {
    const [flag, value] = [argv[i], argv[i + 1]];
    if (value === undefined) { process.stderr.write(`${USAGE}\n`); return 64; }
    if (flag === "--runId") runId = value;
    else if (flag === "--state-dir") stateDir = value;
    else { process.stderr.write(`${USAGE}\n`); return 64; }
  }
  if (runId !== undefined && !RUN_ID.test(runId)) {
    process.stderr.write("--runId must match ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$\n");
    return 64;
  }
  const file = path.join(stateDir, "tokens.json");
  if (!existsSync(file)) return 0;
  try {
    const doc = readTokenFile(file);
    const iso = (ms: number | null) => (ms === null ? null : new Date(ms).toISOString());
    const rows = doc.records
      .filter((r) => runId === undefined || r.runId === runId)
      .sort((a, b) => a.createdAtMs - b.createdAtMs);
    for (const r of rows) {
      process.stdout.write(`${JSON.stringify({
        runId: r.runId,
        role: r.role,
        kind: r.kind,
        tokenId: r.tokenId,
        createdAt: iso(r.createdAtMs),
        revokedAt: iso(r.revokedAtMs),
      })}\n`);
    }
    return 0;
  } catch (err) {
    process.stderr.write(`list refused: ${String(err)}\n`);
    return 65;
  }
}

const isMain = process.argv[1] !== undefined
  && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) process.exit(runListTokensCli(process.argv.slice(2)));
