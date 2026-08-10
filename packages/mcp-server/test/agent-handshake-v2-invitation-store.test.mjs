import assert from "node:assert/strict";
import { mkdtemp, readFile, stat } from "node:fs/promises";
import { randomBytes, randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  createV2InvitationService,
  createV2InvitationStore,
} from "../dist/agent-handshake/v2/invitation-store.js";

const key = { kid: "role-2026-08", secret: randomBytes(32) };
const sessionId = randomUUID();
const statementDigest = "c".repeat(64);
const nbfMs = 1786337000000;
const expMs = 1786337600000;

test("one copied invitation creates distinct, role-scoped principals and is claimed once", async () => {
  const store = createV2InvitationStore();
  let id = 0;
  const service = createV2InvitationService({
    activeKey: key,
    verificationKeys: [key],
    store,
    nowMs: () => nbfMs + 1,
    randomUUID: () => `00000000-0000-4000-8000-${String(++id).padStart(12, "0")}`,
  });
  const created = await service.create({ sessionId, statementDigest, nbfMs, expMs });
  assert.notEqual(created.initiatorAccess, created.responderInvitation);
  const accepted = await service.accept({
    invitation: created.responderInvitation,
    sessionId,
    statementDigest,
    expMs,
  });
  assert.equal(accepted.claimedAtMs, String(nbfMs + 1));
  assert.notEqual(accepted.responderAccess, created.initiatorAccess);
  await assert.rejects(() => service.accept({
    invitation: created.responderInvitation,
    sessionId,
    statementDigest,
    expMs,
  }));
});

test("concurrent invitation claims have exactly one winner", async () => {
  const store = createV2InvitationStore();
  const service = createV2InvitationService({ activeKey: key, verificationKeys: [key], store, nowMs: () => nbfMs + 1 });
  const created = await service.create({ sessionId, statementDigest, nbfMs, expMs });
  const results = await Promise.allSettled(Array.from({ length: 12 }, () => service.accept({
    invitation: created.responderInvitation,
    sessionId,
    statementDigest,
    expMs,
  })));
  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
  assert.equal(results.filter((result) => result.status === "rejected").length, 11);
});

test("persistent invitation state is private, digest-only, and restart-safe", async () => {
  const directory = await mkdtemp(join(tmpdir(), "clockchain-v2-invite-"));
  const path = join(directory, "state.json");
  const service = createV2InvitationService({
    activeKey: key,
    verificationKeys: [key],
    store: createV2InvitationStore({ path }),
    nowMs: () => nbfMs + 1,
  });
  const created = await service.create({ sessionId, statementDigest, nbfMs, expMs });
  const text = await readFile(path, "utf8");
  assert.equal(text.includes(created.responderInvitation), false);
  assert.equal(text.includes(key.secret.toString("hex")), false);
  assert.match(text, /invitationDigest/);
  assert.equal((await stat(path)).mode & 0o077, 0);
  const restarted = createV2InvitationService({
    activeKey: key,
    verificationKeys: [key],
    store: createV2InvitationStore({ path }),
    nowMs: () => nbfMs + 1,
  });
  await restarted.accept({ invitation: created.responderInvitation, sessionId, statementDigest, expMs });
  await assert.rejects(() => restarted.accept({ invitation: created.responderInvitation, sessionId, statementDigest, expMs }));
});
