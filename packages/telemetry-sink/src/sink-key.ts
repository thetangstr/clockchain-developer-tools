import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  type JsonWebKey,
  type KeyObject,
} from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";

/**
 * The sink's own ed25519 signing key (N7a deploy package, LLD §9 / D2).
 *
 * The key is GENERATED inside the container on first boot and written to the
 * `telemetry_state` volume — it never leaves the container as private
 * material (only the public JWK is published via GET /v1/keys). Two defenses:
 *
 *   1. Env injection is refused outright: any TELEMETRY_* / SINK_* / AC_*
 *      variable carrying key material (PRIVATE, SIGNING, SECRET, JWK, SEED,
 *      or a *_KEY_FILE pointer) fails boot. There is deliberately no env or
 *      argv path that can supply the private key.
 *   2. The key file itself must carry our own schema marker — a file that
 *      merely contains an ed25519 JWK (e.g. an operator bind-mount supplying
 *      a pre-made key) is refused, because only a file THIS process wrote
 *      proves the key was generated inside the container. Mode must be
 *      exactly 0600 and (on POSIX) owned by the running uid — a bind-mounted
 *      secret lands root-owned and fails the same check.
 */

export const SINK_KEY_FILE_NAME = "sink-key.json";
export const SINK_KEY_SCHEMA = "ac-telemetry.sink-key/v1" as const;
export const SINK_KEYS_DOC_SCHEMA = "ac-telemetry.sink-keys/v1" as const;

export interface SinkKeyFile {
  schema: typeof SINK_KEY_SCHEMA;
  keyId: string;
  generatedAtMs: number;
  /** ed25519 PRIVATE JWK — contains `d`; never leaves the volume. */
  jwk: JsonWebKey;
}

export interface SinkKey {
  keyId: string;
  privateKey: KeyObject;
  /** Public JWK — the ONLY key material allowed off the volume. */
  publicKeyJwk: JsonWebKey;
  /** true when this boot generated the key (first boot of a fresh volume). */
  created: boolean;
}

/** Published at GET /telemetry/keys (read listener /v1/keys). */
export interface SinkKeysDoc {
  schema: typeof SINK_KEYS_DOC_SCHEMA;
  keys: { keyId: string; alg: "ed25519"; publicKeyJwk: JsonWebKey }[];
}

const ENV_PREFIX = /^(TELEMETRY_|SINK_|AC_)/;
const KEY_MATERIAL_HINT =
  /(PRIVATE|SECRET|SIGNING)[A-Z_]*KEY|PRIVATE_?KEY|_KEY_?FILE|JWK|SEED|MNEMONIC/i;

/** Throws if the env carries anything that looks like injected key material. */
export function refuseInjectedKeyEnv(env: NodeJS.ProcessEnv): void {
  for (const name of Object.keys(env)) {
    if (!ENV_PREFIX.test(name)) continue;
    if (KEY_MATERIAL_HINT.test(name)) {
      throw new Error(
        `refusing to boot: ${name} looks like injected key material — ` +
        `the sink generates its own key inside the container`,
      );
    }
  }
}

function isPrivateEd25519Jwk(jwk: unknown): jwk is JsonWebKey {
  if (typeof jwk !== "object" || jwk === null) return false;
  const j = jwk as JsonWebKey;
  return j.kty === "OKP" && j.crv === "Ed25519" && typeof j.d === "string" && typeof j.x === "string";
}

/** sha256 of the canonical public JWK — the stable public keyId. */
export function sinkKeyId(publicKeyJwk: JsonWebKey): string {
  const canonical = JSON.stringify({ crv: publicKeyJwk.crv, kty: publicKeyJwk.kty, x: publicKeyJwk.x });
  return `sink-ed25519-${createHash("sha256").update(canonical, "utf8").digest("hex").slice(0, 32)}`;
}

function validateKeyFile(raw: unknown, file: string): SinkKeyFile {
  const f = raw as Partial<SinkKeyFile>;
  if (
    typeof f !== "object" || f === null ||
    f.schema !== SINK_KEY_SCHEMA ||
    typeof f.keyId !== "string" ||
    typeof f.generatedAtMs !== "number" ||
    !isPrivateEd25519Jwk(f.jwk)
  ) {
    throw new Error(
      `refusing ${file}: not a ${SINK_KEY_SCHEMA} document — ` +
      `the sink only trusts a key file it generated itself`,
    );
  }
  return f as SinkKeyFile;
}

export function loadOrCreateSinkKey(
  stateDir: string,
  opts: { env?: NodeJS.ProcessEnv; now?: () => number } = {},
): SinkKey {
  const env = opts.env ?? process.env;
  const now = opts.now ?? Date.now;
  refuseInjectedKeyEnv(env);

  const file = path.join(stateDir, SINK_KEY_FILE_NAME);
  if (existsSync(file)) {
    const stat = statSync(file);
    if (!stat.isFile()) throw new Error(`refusing ${file}: not a regular file`);
    const mode = stat.mode & 0o777;
    if (mode !== 0o600) {
      throw new Error(`refusing ${file}: mode ${mode.toString(8)} (expected 0600)`);
    }
    const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
    if (uid !== undefined && stat.uid !== uid) {
      // A bind-mounted or shared key would land under another uid — the key
      // must belong to the sink uid alone.
      throw new Error(`refusing ${file}: owned by uid ${stat.uid}, process uid ${uid}`);
    }
    const doc = validateKeyFile(JSON.parse(readFileSync(file, "utf8")), file);
    const privateKey = createPrivateKey({ key: doc.jwk, format: "jwk" });
    const publicKeyJwk = createPublicKey(privateKey).export({ format: "jwk" }) as JsonWebKey;
    const keyId = sinkKeyId(publicKeyJwk);
    if (keyId !== doc.keyId) throw new Error(`refusing ${file}: keyId does not match its public key`);
    return { keyId, privateKey, publicKeyJwk, created: false };
  }

  // First boot: generate inside the container, write 0600 atomically.
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const { privateKey } = generateKeyPairSync("ed25519");
  const jwk = privateKey.export({ format: "jwk" }) as JsonWebKey;
  const publicKeyJwk = createPublicKey(privateKey).export({ format: "jwk" }) as JsonWebKey;
  const keyId = sinkKeyId(publicKeyJwk);
  const doc: SinkKeyFile = { schema: SINK_KEY_SCHEMA, keyId, generatedAtMs: now(), jwk };

  const tmp = `${file}.${process.pid}.tmp`;
  const fd = openSync(tmp, "w", 0o600);
  try {
    writeFileSync(fd, JSON.stringify(doc));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  chmodSync(tmp, 0o600);
  renameSync(tmp, file);
  return { keyId, privateKey, publicKeyJwk, created: true };
}

export function sinkKeysDoc(key: SinkKey): SinkKeysDoc {
  return {
    schema: SINK_KEYS_DOC_SCHEMA,
    keys: [{ keyId: key.keyId, alg: "ed25519", publicKeyJwk: key.publicKeyJwk }],
  };
}
