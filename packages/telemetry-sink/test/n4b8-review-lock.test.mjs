import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { createTokenStore } from "../dist/index.js";

// The lock helpers are new exports — resolved lazily so a red-run against
// pre-fix code fails at call time, not import time.
const lockFns = await import("../dist/index.js");
const acquireTokenFileLock = lockFns.acquireTokenFileLock;
const releaseTokenFileLock = lockFns.releaseTokenFileLock;

function tmpStateDir() {
  return mkdtempSync(path.join(tmpdir(), "n4b8-review-"));
}

// ---------------------------------------------------------------------------
// F9 — ownership-aware cross-process token-file lock
// ---------------------------------------------------------------------------

test("F9: simultaneous writers lose no updates", async () => {
  const file = path.join(tmpStateDir(), "tokens.json");
  const a = createTokenStore({ recordsFile: file });
  const b = createTokenStore({ recordsFile: file });
  for (let i = 0; i < 8; i += 1) {
    a.markRunUsed(`a-${i}`);
    b.markRunUsed(`b-${i}`);
  }
  await Promise.all([a.flush(), b.flush()]);
  const doc = JSON.parse(readFileSync(file, "utf8"));
  assert.equal(doc.usedRunIds.length, 16);
  assert.ok(!existsSync(`${file}.lock`), "lock released after the writes");
});

test("F9: dead owner's lock is stolen by pid+nonce — not age", async () => {
  const file = path.join(tmpStateDir(), "tokens.json");
  // A dead pid with a parseable nonce: stealable IMMEDIATELY (no 8s wait).
  writeFileSync(`${file}.lock`, `999999 ${"a".repeat(16)} ${Date.now()}`);
  const t0 = Date.now();
  const nonce = await acquireTokenFileLock(file, 5_000);
  assert.ok(Date.now() - t0 < 2_000, "dead owner detected by pid, not age");
  assert.match(readFileSync(`${file}.lock`, "utf8"), new RegExp(` ${nonce} `));
  releaseTokenFileLock(file, nonce);
  assert.ok(!existsSync(`${file}.lock`));
});

test("F9: a live owner is never stolen by age alone", async () => {
  const file = path.join(tmpStateDir(), "tokens.json");
  // A REAL live pid owns the lock — even with an ancient mtime, a waiter
  // must fail closed at its timeout rather than steal a live holder.
  const child = spawn(process.execPath, ["-e", "setTimeout(() => {}, 30000)"], { stdio: "ignore" });
  try {
    writeFileSync(`${file}.lock`, `${child.pid} ${"b".repeat(16)} ${Date.now()}`);
    const old = new Date(Date.now() - 60_000);
    utimesSync(`${file}.lock`, old, old);
    await assert.rejects(() => acquireTokenFileLock(file, 300), /lock timeout/);
    assert.match(readFileSync(`${file}.lock`, "utf8"), / b{16} /, "live owner's lock intact");
  } finally {
    child.kill("SIGKILL");
    rmSync(`${file}.lock`, { force: true });
  }
});

test("F9: fresh replacement during recovery survives — racers serialize", async () => {
  const file = path.join(tmpStateDir(), "tokens.json");
  // Dead-owner lock: two racers both decide to steal. The winner recreates
  // the lock mid-recovery; the loser's confirm re-read must see a different
  // file (or a gap) and leave the fresh lock alone.
  writeFileSync(`${file}.lock`, `999999 ${"c".repeat(16)} ${Date.now()}`);
  const pA = acquireTokenFileLock(file, 3_000).then((n) => ({ who: "A", n }));
  const pB = acquireTokenFileLock(file, 3_000).then((n) => ({ who: "B", n }));
  const winner = await Promise.race([pA, pB]);
  const loser = winner.who === "A" ? pB : pA;
  // While the winner holds, the file carries ONLY the winner's nonce.
  assert.match(readFileSync(`${file}.lock`, "utf8"), new RegExp(` ${winner.n} `));
  // The loser is still waiting — a wrongful steal would have resolved it.
  const settled = await Promise.race([loser.then(() => "resolved"), new Promise((r) => setTimeout(() => r("pending"), 120))]);
  assert.equal(settled, "pending", "loser waits on the live replacement");
  releaseTokenFileLock(file, winner.n);
  const loserResult = await loser;
  assert.match(readFileSync(`${file}.lock`, "utf8"), new RegExp(` ${loserResult.n} `));
  releaseTokenFileLock(file, loserResult.n);
  assert.ok(!existsSync(`${file}.lock`));
});

test("F9: owner-checked release — a resumed former holder deletes nothing", async () => {
  const file = path.join(tmpStateDir(), "tokens.json");
  const nonceA = await acquireTokenFileLock(file, 1_000);
  // A stalls (simulated): its lock is stolen by recovery, B owns the path.
  rmSync(`${file}.lock`);
  const nonceB = await acquireTokenFileLock(file, 1_000);
  // A resumes and releases — must NOT unlink B's live lock.
  releaseTokenFileLock(file, nonceA);
  assert.ok(existsSync(`${file}.lock`), "former holder's release is a no-op on a foreign lock");
  assert.match(readFileSync(`${file}.lock`, "utf8"), new RegExp(` ${nonceB} `));
  // B releases its own — the file goes away.
  releaseTokenFileLock(file, nonceB);
  assert.ok(!existsSync(`${file}.lock`));
  // Releasing a missing/unparseable lock is a safe no-op.
  releaseTokenFileLock(file, nonceB);
  writeFileSync(`${file}.lock`, "garbage");
  releaseTokenFileLock(file, "f".repeat(16));
  assert.ok(existsSync(`${file}.lock`), "ambiguous content is never unlinked by release");
  rmSync(`${file}.lock`);
});

test("F9: ambiguous lock file — fresh waits, stat-identical stale is stolen", async () => {
  const file = path.join(tmpStateDir(), "tokens.json");
  // Fresh unparseable body (owner mid-write or foreign format): ambiguous —
  // never stolen, the waiter fails closed.
  writeFileSync(`${file}.lock`, "held");
  await assert.rejects(() => acquireTokenFileLock(file, 250), /lock timeout/);
  assert.equal(readFileSync(`${file}.lock`, "utf8"), "held");
  // Same body past the stale threshold, unchanged between checks → stealable.
  const old = new Date(Date.now() - 20_000);
  utimesSync(`${file}.lock`, old, old);
  const nonce = await acquireTokenFileLock(file, 3_000);
  releaseTokenFileLock(file, nonce);
  assert.ok(!existsSync(`${file}.lock`));
});

test("F9: store persist still fails closed under a held lock", async () => {
  const file = path.join(tmpStateDir(), "tokens.json");
  const seed = createTokenStore({ recordsFile: file });
  seed.mintIngest({ runId: "seed2", role: "buyer" });
  await seed.flush();
  const nonce = await acquireTokenFileLock(file, 1_000); // live holder
  const contender = createTokenStore({ recordsFile: file, lockTimeoutMs: 250 });
  contender.markRunUsed("blocked");
  await assert.rejects(() => contender.flush(), /lock timeout/);
  assert.equal(JSON.parse(readFileSync(file, "utf8")).usedRunIds.includes("blocked"), false);
  releaseTokenFileLock(file, nonce);
});

