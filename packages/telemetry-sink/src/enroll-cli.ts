import path from "node:path";

import { enrollParty } from "./enrollments.js";
import type { ContractRole } from "./tokens.js";

/**
 * Sink-admin party enrollment (O-1, WP9b). Runs INSIDE the sink container
 * against the state volume — the same position as the mint CLI; there is no
 * HTTP route that writes an enrollment:
 *
 *   docker compose exec telemetry-sink \
 *     node dist/enroll-cli.js --keyId <principal keyId> --role buyer \
 *       --x25519 0x<64-hex party services public key>
 *
 * The party sends only its public key; no secret moves. The running server
 * picks the entry up by mtime, without a restart. Write-once per keyId.
 */

const USAGE = "usage: node dist/enroll-cli.js --keyId <id> --role buyer|provider --x25519 0x<64-hex> [--state-dir /telemetry/state]";

export async function runEnrollCli(argv: string[], env: NodeJS.ProcessEnv = process.env): Promise<number> {
  const flag = (name: string): string | undefined => {
    const i = argv.indexOf(name);
    return i === -1 ? undefined : argv[i + 1];
  };
  const keyId = flag("--keyId");
  const role = flag("--role");
  const x25519 = flag("--x25519");
  const stateDir = flag("--state-dir") ?? env.TELEMETRY_STATE_DIR ?? "/telemetry/state";
  if (keyId === undefined || x25519 === undefined || (role !== "buyer" && role !== "provider")) {
    process.stderr.write(`${USAGE}\n`);
    return 64;
  }
  try {
    const out = await enrollParty({
      file: path.join(stateDir, "enrollments.json"),
      keyId,
      role: role as ContractRole,
      x25519,
    });
    // Public material only — the entry is a keyId, a role, and a public key.
    process.stdout.write(`${JSON.stringify(out)}\n`);
    return 0;
  } catch (err) {
    process.stderr.write(`enroll refused: ${String(err)}\n`);
    return 65;
  }
}

const isMain = process.argv[1] !== undefined
  && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  runEnrollCli(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err) => { process.stderr.write(`${String(err)}\n`); process.exit(70); },
  );
}
