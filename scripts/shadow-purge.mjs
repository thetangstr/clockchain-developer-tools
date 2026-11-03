#!/usr/bin/env node
// Hosted Shadow operator purge: removes sessions by owner and/or age from the Shadow state directory. Dry run by
// default; nothing is deleted without --apply. Node built-ins only, so it runs on the host against the volume or
// inside the mcp container:
//
//   node scripts/shadow-purge.mjs --state-dir /path/to/shadow --owner acct_XXXXXXXXXXXXXXXXXXXXXX
//   node scripts/shadow-purge.mjs --state-dir /path/to/shadow --older-than 7d --apply
//   docker compose exec -T mcp node --input-type=module - --older-than 7d < scripts/shadow-purge.mjs
//
// --state-dir   default $SHADOW_STATE_DIR, else /app/state/shadow
// --owner       the owner id Shadow keys sessions by: an account id (acct_...), or jti:<jti> / tok:<sha256>
// --older-than  a duration measured from each session's createdAt: 90m, 12h, 7d
// --apply       delete (without it: list what would be deleted)
// At least one of --owner / --older-than is required. Both together select sessions matching both.
//
// Session titles and content are never printed: only owner keys, session ids, dates, state and sizes. Deleting a
// session also removes its link capability file, so its viewer and packet links stop working. A running server
// refreshes its storage totals at its hourly sweep (and at boot): restart the mcp container, or wait for the sweep,
// before new sessions see the freed space.
import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

/** Must match ownerKeyOf in packages/mcp-server/src/shadow/store.ts (a test pins the two together). */
export function ownerKeyOf(ownerId) {
  return createHash("sha256").update(`shadow-owner:v1\0${ownerId}`).digest("hex").slice(0, 32);
}

const OWNER_KEY = /^[0-9a-f]{32}$/;
const SESSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CAP = /^[A-Za-z0-9_-]{22}$/;

/** "90m" / "12h" / "7d" -> milliseconds, or undefined. */
export function parseDuration(text) {
  const m = /^([1-9][0-9]{0,5})([mhd])$/.exec(String(text ?? "").trim());
  return m ? Number(m[1]) * { m: 60_000, h: 3_600_000, d: 86_400_000 }[m[2]] : undefined;
}

function bytesUnder(path) {
  let total = 0;
  for (const name of readdirSync(path)) {
    const p = join(path, name);
    const st = lstatSync(p);
    total += st.isDirectory() ? bytesUnder(p) : st.size;
  }
  return total;
}

function readMeta(sessionDir) {
  for (const name of ["meta.json", "meta.json.bak"]) {
    try {
      const parsed = JSON.parse(readFileSync(join(sessionDir, name), "utf8"));
      if (parsed?.value?.sessionId) return parsed.value;
    } catch {
      // try the backup
    }
  }
  return undefined;
}

/** Sessions matching the selectors, with what deleting them would free. */
export function findSessions(stateDir, { owner, olderThanMs, nowMs = Date.now() }) {
  const wanted = owner === undefined ? undefined : ownerKeyOf(owner);
  const found = [];
  const ownersDir = join(stateDir, "owners");
  if (!existsSync(ownersDir)) return found;
  for (const ownerKey of readdirSync(ownersDir)) {
    if (!OWNER_KEY.test(ownerKey) || (wanted && ownerKey !== wanted)) continue;
    const sessionsDir = join(ownersDir, ownerKey, "sessions");
    if (!existsSync(sessionsDir)) continue;
    for (const sessionId of readdirSync(sessionsDir)) {
      if (!SESSION_ID.test(sessionId)) continue;
      const dir = join(sessionsDir, sessionId);
      const meta = readMeta(dir);
      const createdMs = meta ? Date.parse(meta.createdAt) : lstatSync(dir).mtimeMs;
      if (olderThanMs !== undefined && !(nowMs - createdMs > olderThanMs)) continue;
      found.push({
        ownerKey,
        sessionId,
        dir,
        createdAt: new Date(createdMs).toISOString(),
        state: meta?.state ?? "unreadable",
        bytes: bytesUnder(dir),
        cap: meta && CAP.test(meta.cap) ? meta.cap : undefined,
      });
    }
  }
  return found;
}

/** Deletes the sessions (and their link capability files). */
export function purge(stateDir, sessions) {
  for (const s of sessions) {
    rmSync(s.dir, { recursive: true, force: true });
    if (s.cap) {
      const capFile = join(stateDir, "caps", `${createHash("sha256").update(s.cap).digest("hex")}.json`);
      rmSync(capFile, { force: true });
      rmSync(`${capFile}.bak`, { force: true });
    }
  }
}

function usage(message) {
  process.stderr.write(`${message}\nusage: shadow-purge.mjs [--state-dir DIR] [--owner ID] [--older-than 90m|12h|7d] [--apply]\n`);
  process.exit(2);
}

export function main(argv, env = process.env, out = (line) => process.stdout.write(`${line}\n`)) {
  const args = { stateDir: env.SHADOW_STATE_DIR || "/app/state/shadow", apply: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--apply") args.apply = true;
    else if (a === "--state-dir") args.stateDir = argv[++i];
    else if (a === "--owner") args.owner = argv[++i];
    else if (a === "--older-than") {
      args.olderThanMs = parseDuration(argv[++i]);
      if (args.olderThanMs === undefined) usage("--older-than takes a duration such as 90m, 12h or 7d");
    } else usage(`unknown argument: ${a}`);
  }
  if (args.owner === undefined && args.olderThanMs === undefined) usage("give --owner, --older-than, or both");
  if (args.owner !== undefined && !/^[\x21-\x7e]{1,200}$/.test(args.owner)) usage("--owner must be an owner id such as acct_...");
  if (!args.stateDir || !existsSync(resolve(args.stateDir))) usage(`no Shadow state directory at ${args.stateDir}`);
  const sessions = findSessions(resolve(args.stateDir), args);
  const total = sessions.reduce((n, s) => n + s.bytes, 0);
  for (const s of sessions) out(`${args.apply ? "delete" : "would delete"} owner=${s.ownerKey} session=${s.sessionId} created=${s.createdAt} state=${s.state} bytes=${s.bytes}`);
  if (args.apply) purge(resolve(args.stateDir), sessions);
  out(`${args.apply ? "deleted" : "dry run: would delete"} ${sessions.length} session(s), ${total} bytes${args.apply ? "" : " (add --apply to delete)"}`);
  return { sessions, total };
}

const invokedAsScript = !process.argv[1] || process.argv[1] === "-" || import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (invokedAsScript) main(process.argv.slice(2));
