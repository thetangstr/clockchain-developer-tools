#!/usr/bin/env node
// Vendors the pure Shadow modules from the clockchain-shadow library into the MCP server, so hosted Shadow
// (packages/mcp-server/src/shadow) hashes, signs and verifies exactly as the library does.
//
//   node scripts/sync-shadow-lib.mjs [--from <clockchain-shadow/ts/src>] [--check]
//
// The source defaults to ../clockchain-shadow/ts/src next to this repository, or next to its main checkout when run
// from a git worktree (override with --from or SHADOW_LIB_SRC). Each file is copied byte for byte apart from a provenance header and its relative `.ts` import
// extensions, which become `.js` for tsc's NodeNext resolution. --check compares instead of writing and exits 1 on
// any difference.
//
// Not vendored: store.ts (node:sqlite, newer than the production image's Node 20), clockchain.ts (the library's HTTP
// client; hosted Shadow anchors in-process, src/shadow/ledger.ts) and recorder.ts (imports store.ts; mirrored by
// src/shadow/recorder.ts, which this script checks against). A vendored file that starts importing one of them fails
// the sync, so the change is looked at rather than copied.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const FILES = ["profile.ts", "types.ts", "kinds.ts", "keys.ts", "identity.ts", "anchors.ts", "windows.ts", "verify.ts", "summary.ts"];
const SHIMS = [];
// Files to mark @ts-nocheck (type-checked upstream only), each with its reason, for a library typing that does not hold
// under this repo's @types/node 20. Empty: every vendored file type-checks here.
const NOCHECK = {};

const args = process.argv.slice(2);
const flag = (name) => args.includes(name);
const value = (name) => {
  const i = args.indexOf(name);
  if (i < 0) return undefined;
  const v = args[i + 1];
  if (!v || v.startsWith("--")) throw new Error(`${name} needs a value`);
  return v;
};

const repoRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
// Default: ../clockchain-shadow next to this checkout or, from a git worktree, next to the main checkout.
function defaultSource() {
  const beside = (root) => path.join(root, "..", "clockchain-shadow", "ts", "src");
  if (existsSync(beside(repoRoot))) return beside(repoRoot);
  try {
    const common = execFileSync("git", ["rev-parse", "--path-format=absolute", "--git-common-dir"], { cwd: repoRoot, encoding: "utf8" }).trim();
    return beside(path.dirname(common));
  } catch {
    return beside(repoRoot);
  }
}
const from = path.resolve(value("--from") ?? process.env.SHADOW_LIB_SRC ?? defaultSource());
const to = path.join(repoRoot, "packages", "mcp-server", "src", "shadow", "lib");
const check = flag("--check");

const allowed = new Set([...FILES, ...SHIMS]);
const importRe = /(\bfrom\s+|\bimport\s*\(\s*|\bimport\s+)(['"])(\.\/[^'"]+)\2/g;

function vendor(file) {
  const source = readFileSync(path.join(from, file), "utf8");
  const sha = createHash("sha256").update(source).digest("hex");
  const body = source.replace(importRe, (match, lead, quote, spec) => {
    const target = spec.slice(2);
    if (!allowed.has(target)) throw new Error(`${file} imports ${spec}, which is not vendored; add it to FILES or a shim`);
    return `${lead}${quote}./${target.replace(/\.ts$/, ".js")}${quote}`;
  });
  if (/from\s+['"]\.\.\//.test(body)) throw new Error(`${file} imports from outside src/; not vendorable`);
  const header =
    (NOCHECK[file] ? `// @ts-nocheck -- ${NOCHECK[file]}\n` : "") +
    `// Vendored from clockchain-shadow/ts/src/${file} (source sha256 ${sha}) by scripts/sync-shadow-lib.mjs.\n` +
    `// Do not edit here: change the library, then re-run the script.\n`;
  return header + body;
}

if (!existsSync(from)) {
  console.error(`sync-shadow-lib: source not found: ${from} (pass --from <clockchain-shadow/ts/src>)`);
  process.exit(2);
}
for (const shim of SHIMS) {
  if (!existsSync(path.join(to, shim))) {
    console.error(`sync-shadow-lib: missing hand-written shim ${path.join(to, shim)}`);
    process.exit(2);
  }
}
mkdirSync(to, { recursive: true });
let drift = 0;
for (const file of FILES) {
  const next = vendor(file);
  const dest = path.join(to, file);
  const current = existsSync(dest) ? readFileSync(dest, "utf8") : null;
  if (current === next) continue;
  if (check) {
    console.error(`sync-shadow-lib: ${file} differs from ${path.join(from, file)}`);
    drift++;
  } else {
    writeFileSync(dest, next);
    console.log(`sync-shadow-lib: wrote ${path.relative(repoRoot, dest)}`);
  }
}
// recorder.ts cannot be vendored (node:sqlite), so src/shadow/recorder.ts mirrors it and names the source hash it was
// last reviewed against. A different hash means the hosted recorder needs a look before this sync ships.
const mirror = path.join(repoRoot, "packages", "mcp-server", "src", "shadow", "recorder.ts");
const reviewed = /recorder\.ts, source sha256 ([0-9a-f]{64})/.exec(readFileSync(mirror, "utf8"))?.[1];
const recorderSha = createHash("sha256").update(readFileSync(path.join(from, "recorder.ts"))).digest("hex");
if (reviewed !== recorderSha) {
  console.error(
    `sync-shadow-lib: the library's recorder.ts is now sha256 ${recorderSha}; src/shadow/recorder.ts was reviewed against ` +
      `${reviewed ?? "(none)"}. Review its append, checkpoint, close and packet rules (and the copied normalize and ` +
      `hidden-reasoning helpers), then update the hash in its header.`,
  );
  drift++;
}
if (check && drift) process.exit(1);
console.log(`sync-shadow-lib: ${check ? "checked" : "synced"} ${FILES.length} files from ${from}`);
