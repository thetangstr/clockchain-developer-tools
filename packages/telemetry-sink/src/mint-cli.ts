import { existsSync } from "node:fs";
import path from "node:path";

import { createRunLedger } from "./run-ledger.js";
import { createTokenStore, sealToken } from "./tokens.js";
import type { ContractRole, TokenKind } from "./tokens.js";

/**
 * Sink-admin token mint (N7a). Runs INSIDE the sink container against the
 * state volume — the sink admin is a separate authority from the harness
 * operator, so minting never happens over HTTP and never touches the
 * business server:
 *
 *   docker compose exec telemetry-sink \
 *     node dist/mint-cli.js ingest --runId <run> --role buyer \
 *       --seal-to 0x<64-hex x25519 services pubkey>
 *
 *   ... query    --runId <run>                      (post-seal verifier token)
 *   ... global-query                                (verifier-wide; --runId must be omitted)
 *
 * With --seal-to the plaintext token is printed as a sealed box bound to
 * (runId, role); without it the plaintext prints once to stdout (operator
 * hand-off). The records file stores only sha256 tokenIds — never plaintext.
 *
 * The server re-reads this file on mtime change, so minted authority is live
 * without a restart.
 */

const USAGE = `usage: node dist/mint-cli.js <ingest|query|global-query> --runId <id> [--role buyer|provider] [--seal-to 0x<x25519-pub>] [--state-dir /telemetry/state]`;

export async function runMintCli(argv: string[], env: NodeJS.ProcessEnv = process.env): Promise<number> {
  const kind = argv[0] as TokenKind | undefined;
  if (kind !== "ingest" && kind !== "query" && kind !== "global-query") {
    process.stderr.write(`${USAGE}\n`);
    return 64;
  }
  const flag = (name: string): string | undefined => {
    const i = argv.indexOf(name);
    return i === -1 ? undefined : argv[i + 1];
  };
  const runId = flag("--runId");
  const role = flag("--role") as ContractRole | undefined;
  const sealTo = flag("--seal-to");
  const stateDir = flag("--state-dir") ?? env.TELEMETRY_STATE_DIR ?? "/telemetry/state";

  if (kind !== "global-query" && (runId === undefined || runId === "")) {
    process.stderr.write(`--runId is required for ${kind}\n`);
    return 64;
  }
  if (kind === "ingest" && role !== "buyer" && role !== "provider") {
    process.stderr.write("--role buyer|provider is required for ingest\n");
    return 64;
  }
  if (kind === "query" && role !== undefined) {
    process.stderr.write("--role is not valid for query tokens\n");
    return 64;
  }
  if (sealTo !== undefined && kind !== "ingest") {
    // Sealing binds a (runId, role) services endpoint — only ingest tokens
    // are delivered to forwarders; query tokens hand off to the verifier.
    process.stderr.write("--seal-to is only valid for ingest tokens\n");
    return 64;
  }

  // N4b-8 (F8): durably initialize the empty run ledger BEFORE writing
  // tokens.json — mint on a fresh volume must never leave tokens.json
  // without runs.json, or the next boot reads it as a lost ledger.
  createRunLedger({ file: path.join(stateDir, "runs.json") });
  const tokens = createTokenStore({ recordsFile: path.join(stateDir, "tokens.json") });
  try {
    const minted = kind === "ingest"
      ? tokens.mintIngest({ runId: runId as string, role: role as ContractRole })
      : kind === "query"
        ? tokens.mintQuery({ runId: runId as string })
        : tokens.mintGlobalQuery();
    // Writes land through the async lock queue — flush BEFORE printing the
    // token so a failed persist can never hand out phantom authority.
    await tokens.flush();
    const out: Record<string, unknown> = { record: minted.record };
    if (sealTo !== undefined) {
      out.sealed = sealToken(sealTo as `0x${string}`, minted.token, {
        runId: minted.record.runId,
        role: minted.record.role as string,
      });
    } else {
      // Plaintext hand-off — operator console only, printed exactly once.
      out.token = minted.token;
    }
    process.stdout.write(`${JSON.stringify(out)}\n`);
    return 0;
  } catch (err) {
    process.stderr.write(`mint refused: ${String(err)}\n`);
    return 65;
  }
}

const isMain = process.argv[1] !== undefined
  && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  runMintCli(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err) => { process.stderr.write(`${String(err)}\n`); process.exit(70); },
  );
}
