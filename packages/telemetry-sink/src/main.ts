import { createPublicKey, type JsonWebKey, type KeyObject } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

import { createEnrollmentRegistry } from "./enrollments.js";
import { createLaneService } from "./lanes.js";
import { createTelemetrySink } from "./sink.js";
import { createTelemetrySinkServer } from "./server.js";
import { createMcpTsaAnchor } from "./mcp-anchor.js";
import { createRunLedger } from "./run-ledger.js";
import { loadOrCreateSinkKey, sinkKeysDoc } from "./sink-key.js";
import { createTokenStore } from "./tokens.js";

/**
 * Container entrypoint for the deployed telemetry sink (N7a).
 *
 * Process shape:
 *   - state dir   TELEMETRY_STATE_DIR   (default /telemetry/state — the named volume)
 *   - write port  TELEMETRY_WRITE_PORT  (default 8081 — public /telemetry/v1/*)
 *   - read port   TELEMETRY_READ_PORT   (default 8082 — public /telemetry/query/* + /telemetry/keys)
 *   - close port  TELEMETRY_CLOSE_PORT  (default 8083 — compose-network only, NEVER routed by Caddy)
 *   - contract keys  TELEMETRY_CONTRACT_KEYS  (JSON {keyId: pem-or-jwk PUBLIC key} — close authority)
 *   - windows        TELEMETRY_RUN_WINDOW_MS / TELEMETRY_FLUSH_GRACE_MS (optional)
 *   - anchor         TELEMETRY_ANCHOR_MCP_URL + (TELEMETRY_ANCHOR_TOKEN_FILE — a
 *                    mounted secret file; the plaintext TELEMETRY_ANCHOR_TOKEN
 *                    is accepted only with TELEMETRY_ENV=staging — CDT-SEC L7)
 *   - O-1 lanes      enrollments.json (admin-written by enroll-cli) and
 *                    lanes.json (server-written) on the state volume
 *
 * There is deliberately NO env var that supplies the sink signing key — the
 * key is generated on first boot inside this process and persisted to the
 * state volume (see sink-key.ts); any env that smells like injected key
 * material refuses the boot.
 */

function intEnv(env: NodeJS.ProcessEnv, name: string, fallback: number): number {
  const raw = env[name];
  if (raw === undefined || raw === "") return fallback;
  const v = Number.parseInt(raw, 10);
  // 0 is allowed — an ephemeral port for tests; a container env would never set it.
  if (!Number.isSafeInteger(v) || v < 0) throw new Error(`bad ${name}: ${raw}`);
  return v;
}

/** Public contract-server keys only — PEM string or JWK without `d`. */
export function parseContractKeys(
  raw: string | undefined,
  name = "TELEMETRY_CONTRACT_KEYS",
): Record<string, KeyObject> | undefined {
  if (raw === undefined || raw === "") return undefined;
  const doc: unknown = JSON.parse(raw);
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
    throw new Error(`${name} must be a JSON object {keyId: publicKey}`);
  }
  const out: Record<string, KeyObject> = {};
  for (const [keyId, material] of Object.entries(doc)) {
    if (typeof material === "object" && material !== null
      && typeof (material as JsonWebKey).d === "string") {
      throw new Error(`${name}[${keyId}]: private key material is not allowed`);
    }
    const key = typeof material === "string"
      ? createPublicKey(material)
      : createPublicKey({ key: material as JsonWebKey, format: "jwk" });
    if (key.asymmetricKeyType !== "ed25519") {
      throw new Error(`${name}[${keyId}]: not an ed25519 public key`);
    }
    out[keyId] = key;
  }
  return out;
}

/** The raw public key bytes — the overlap check compares material, not keyIds. */
function publicKeyBytes(key: KeyObject): string {
  return key.export({ format: "jwk" }).x as string;
}

/**
 * The anchor bearer, from TELEMETRY_ANCHOR_TOKEN_FILE (a mounted secret file;
 * the value never appears in the container env or `docker inspect`) or the
 * legacy TELEMETRY_ANCHOR_TOKEN. Both set is ambiguous and refuses boot; an
 * empty or unreadable file refuses boot. The token is never logged.
 * CDT-SEC L7: in production (TELEMETRY_ENV unset or "production") the
 * plaintext env refuses boot whatever its value — only _FILE is accepted,
 * so the token never sits in `docker inspect` or a process environment.
 * Staging keeps the legacy form.
 */
export function resolveAnchorToken(env: NodeJS.ProcessEnv): string | undefined {
  const file = env.TELEMETRY_ANCHOR_TOKEN_FILE;
  const plain = env.TELEMETRY_ANCHOR_TOKEN;
  if (file !== undefined && plain !== undefined) {
    throw new Error("set TELEMETRY_ANCHOR_TOKEN_FILE or TELEMETRY_ANCHOR_TOKEN, not both");
  }
  if (plain !== undefined && (env.TELEMETRY_ENV ?? "production") !== "staging") {
    throw new Error("TELEMETRY_ANCHOR_TOKEN (plaintext env) is refused in production; use TELEMETRY_ANCHOR_TOKEN_FILE");
  }
  if (file === undefined) return plain;
  if (file === "") throw new Error("TELEMETRY_ANCHOR_TOKEN_FILE is empty");
  let st;
  try {
    st = statSync(file);
  } catch {
    throw new Error(`TELEMETRY_ANCHOR_TOKEN_FILE is not readable: ${file}`);
  }
  if (!st.isFile()) throw new Error(`TELEMETRY_ANCHOR_TOKEN_FILE is not a regular file: ${file}`);
  const token = readFileSync(file, "utf8").trim();
  if (token === "" || /\s/.test(token)) {
    throw new Error(`TELEMETRY_ANCHOR_TOKEN_FILE must hold exactly one non-empty token: ${file}`);
  }
  return token;
}

export function startFromEnv(env: NodeJS.ProcessEnv = process.env): {
  write: import("node:http").Server;
  read: import("node:http").Server;
  close: import("node:http").Server;
} {
  const stateDir = env.TELEMETRY_STATE_DIR ?? "/telemetry/state";
  // TELEMETRY_ENV: "production" (default) | "staging". Production REQUIRES a
  // configured contract-key set (LOW-10) — a prod sink without close
  // authority is a misconfiguration, not a degraded mode.
  const environment = env.TELEMETRY_ENV ?? "production";
  if (environment !== "production" && environment !== "staging") {
    throw new Error(`TELEMETRY_ENV must be "production" or "staging", got ${environment}`);
  }
  // MED + N4b-8 (F8): the run ledger is durably initialized BEFORE the
  // token store — a fresh volume writes the versioned empty runs.json first,
  // so the normal sequence (boot → provision tokens → restart before any
  // ingest) always leaves both files present. tokens.json WITHOUT runs.json
  // then can only mean the initialized ledger was deleted (or the volume is
  // hand-assembled) — lost-run markers would silently reset. Refuse to
  // boot; an operator must reconcile state.
  const tokensPath = path.join(stateDir, "tokens.json");
  const runsPath = path.join(stateDir, "runs.json");
  if (existsSync(tokensPath) && !existsSync(runsPath)) {
    throw new Error(
      `state volume has ${tokensPath} but no runs.json — refusing to boot (lost initialized ledger would silently un-lose runs)`,
    );
  }
  // Durably initialize the empty ledger before ANY provisioning path can
  // write tokens.json — this write is the initialization marker.
  const runLedger = createRunLedger({ file: runsPath });
  const sinkKey = loadOrCreateSinkKey(stateDir, { env });
  const tokens = createTokenStore({ recordsFile: tokensPath });
  const contractKeys = parseContractKeys(env.TELEMETRY_CONTRACT_KEYS);
  if (environment === "production"
    && (contractKeys === undefined || Object.keys(contractKeys).length === 0)) {
    throw new Error("TELEMETRY_CONTRACT_KEYS is required in production — refused to boot");
  }
  // MED-6: prod and staging contract-key sets must be disjoint — a shared
  // key would let a staging receipt close a production run. Each service
  // carries the OTHER environment's set in TELEMETRY_PEER_CONTRACT_KEYS so
  // the overlap check runs locally on both boxes.
  const peerKeys = parseContractKeys(env.TELEMETRY_PEER_CONTRACT_KEYS, "TELEMETRY_PEER_CONTRACT_KEYS");
  const peerKeyCount = peerKeys === undefined ? 0 : Object.keys(peerKeys).length;
  // TELEMETRY_PEER_ENV="none" (D22): the explicit, literal statement that no
  // peer environment (staging sink / staging contract server) exists, so the
  // disjoint-key check has nothing to compare against. It is the ONLY way a
  // production sink boots with an empty peer set; it never relaxes the
  // TELEMETRY_CONTRACT_KEYS requirement and contradicts a non-empty peer set.
  const peerEnv = env.TELEMETRY_PEER_ENV;
  if (peerEnv !== undefined && peerEnv !== "" && peerEnv !== "none") {
    throw new Error(`TELEMETRY_PEER_ENV must be unset or "none", got ${peerEnv}`);
  }
  const noPeerEnv = peerEnv === "none";
  if (noPeerEnv && peerKeyCount > 0) {
    throw new Error(
      "TELEMETRY_PEER_ENV=none contradicts a non-empty TELEMETRY_PEER_CONTRACT_KEYS — refused to boot",
    );
  }
  // Production must carry the peer set — an empty compose default would
  // otherwise disable the disjoint-key check silently.
  if (environment === "production" && peerKeyCount === 0 && !noPeerEnv) {
    throw new Error(
      "TELEMETRY_PEER_CONTRACT_KEYS is required in production (or TELEMETRY_PEER_ENV=none when no peer environment exists) — refused to boot",
    );
  }
  if (contractKeys !== undefined && peerKeys !== undefined) {
    const mine = new Set(Object.values(contractKeys).map(publicKeyBytes));
    const overlap = Object.values(peerKeys).filter((k) => mine.has(publicKeyBytes(k)));
    if (overlap.length > 0) {
      throw new Error(
        `contract-key overlap between this service and its peer environment (${overlap.length} key(s)) — refused to boot`,
      );
    }
  }
  // N4b-8 (Part B): the head anchor — tsa_issue on the MCP endpoint with
  // the sink's own Clockchain key. Both-or-neither: a URL without a token
  // (or vice versa) is a misconfiguration. Unset entirely → heads carry no
  // anchor block; the `anchor` flag in the ready line makes that visible.
  const anchorUrl = env.TELEMETRY_ANCHOR_MCP_URL;
  const anchorToken = resolveAnchorToken(env);
  if ((anchorUrl === undefined) !== (anchorToken === undefined)
    || anchorUrl === "" || anchorToken === "") {
    throw new Error(
      "TELEMETRY_ANCHOR_MCP_URL and TELEMETRY_ANCHOR_TOKEN(_FILE) must both be set or both unset",
    );
  }
  const anchorBackoff = (env.TELEMETRY_ANCHOR_BACKOFF_MS ?? "")
    .split(",").map((s) => s.trim()).filter((s) => s.length > 0)
    .map((s) => {
      const v = Number.parseInt(s, 10);
      if (!Number.isSafeInteger(v) || v < 0 || v > 120_000) {
        throw new Error(`bad TELEMETRY_ANCHOR_BACKOFF_MS entry: ${s}`);
      }
      return v;
    });
  // O-1: the enrollment registry is admin-written (enroll-cli) and read-only
  // here; lanes.json is server-written. Neither ever carries a secret.
  const enrollments = createEnrollmentRegistry({ file: path.join(stateDir, "enrollments.json") });
  const lanes = createLaneService({
    // L5: signed lane bodies name this sink by its signing keyId.
    audience: sinkKey.keyId,
    tokens,
    enrollments,
    ...(contractKeys === undefined ? {} : { contractKeys }),
    file: path.join(stateDir, "lanes.json"),
  });
  const sink = createTelemetrySink({
    signer: { keyId: sinkKey.keyId, privateKey: sinkKey.privateKey },
    tokens,
    runLedger,
    lanes,
    ...(contractKeys === undefined ? {} : { contractKeys }),
    ...(anchorUrl === undefined ? {} : {
      anchor: createMcpTsaAnchor({
        url: anchorUrl,
        token: anchorToken as string,
        agentId: env.TELEMETRY_ANCHOR_AGENT_ID,
        ...(anchorBackoff.length > 0 ? { backoffMs: anchorBackoff } : {}),
      }),
    }),
    runWindowMs: intEnv(env, "TELEMETRY_RUN_WINDOW_MS", 6 * 60 * 60 * 1000),
    flushGraceMs: intEnv(env, "TELEMETRY_FLUSH_GRACE_MS", 30_000),
  });
  const keysDoc = sinkKeysDoc(sinkKey);
  const servers = createTelemetrySinkServer({ sink, tokens, keys: () => keysDoc, lanes });

  const host = env.TELEMETRY_BIND_HOST ?? "0.0.0.0";
  const writePort = intEnv(env, "TELEMETRY_WRITE_PORT", 8081);
  const readPort = intEnv(env, "TELEMETRY_READ_PORT", 8082);
  const closePort = intEnv(env, "TELEMETRY_CLOSE_PORT", 8083);
  servers.write.listen(writePort, host);
  servers.read.listen(readPort, host);
  // The close listener binds the compose network like the others — isolation
  // is that Caddy never routes to it; the receipt signature is the authority.
  servers.close.listen(closePort, host);

  process.stdout.write(JSON.stringify({
    event: "telemetry-sink-ready",
    keyId: sinkKey.keyId,
    keyCreated: sinkKey.created,
    ports: { write: writePort, read: readPort, close: closePort },
    anchor: anchorUrl !== undefined,
    environment,
    contractKeyIds: Object.keys(contractKeys ?? {}),
    peerKeyIds: Object.keys(peerKeys ?? {}),
    peerEnv: noPeerEnv ? "none" : "present",
  }) + "\n");
  return servers;
}

const isMain = process.argv[1] !== undefined
  && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  try {
    startFromEnv();
  } catch (err) {
    process.stderr.write(`telemetry-sink boot refused: ${String(err)}\n`);
    process.exit(86);
  }
}
