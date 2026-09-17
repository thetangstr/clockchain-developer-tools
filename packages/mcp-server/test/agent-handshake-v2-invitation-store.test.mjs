import assert from "node:assert/strict";
import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  createV2InvitationService,
  createV2InvitationStore,
} from "../dist/agent-handshake/v2/invitation-store.js";
import { __runtimeV2KeyConfig } from "../dist/agent-handshake/v2/coordinator.js";
import { readV2RoleAccessPayload } from "../dist/agent-handshake/v2/access.js";
import { v2CanonicalRecord } from "../dist/agent-handshake/v2/protocol.js";

const key = { kid: "role-2026-08", secret: randomBytes(32) };
const sessionId = randomUUID();
const statementDigest = "c".repeat(64);
const nbfMs = 1786337000000;
const expMs = 1786337600000;
const invitationDigest = (value) => createHash("sha256").update(value, "utf8").digest("hex");
const encodedSecret = (char) => Buffer.alloc(32, char).toString("base64");
const terms = Object.freeze({
  reference: "durable invitation retry",
  statement: "Retry the same accepted invitation without issuing a different responder principal.",
  validForSeconds: "60",
  identityPolicy: Object.freeze({ erc8004: "not_required", chainId: null, registryAddress: null }),
});

test("runtime key config keeps role signing and acceptance HMAC keys independent", () => {
  const config = __runtimeV2KeyConfig({
    AGENT_HANDSHAKE_ROLE_ACCESS_ACTIVE: JSON.stringify({ kid: "role-active", secretBase64: encodedSecret("a") }),
    AGENT_HANDSHAKE_ROLE_ACCESS_PREVIOUS: JSON.stringify({ kid: "role-previous", secretBase64: encodedSecret("b") }),
    AGENT_HANDSHAKE_ACCEPTANCE_HMAC_ACTIVE: JSON.stringify({ kid: "accept-active", secretBase64: encodedSecret("c") }),
    AGENT_HANDSHAKE_ACCEPTANCE_HMAC_PREVIOUS: JSON.stringify({ kid: "accept-previous", secretBase64: encodedSecret("d") }),
  });

  assert.equal(config.activeAccessKey.kid, "role-active");
  assert.deepEqual(config.accessKeys.map((entry) => entry.kid), ["role-active", "role-previous"]);
  assert.deepEqual(config.acceptanceHmacKeys.map((entry) => entry.kid), ["accept-active", "accept-previous"]);
  assert.notDeepEqual(config.activeAccessKey.secret, config.acceptanceHmacKeys[0].secret);
});

test("runtime key config rejects malformed base64 and cross-purpose key reuse", () => {
  const valid = {
    AGENT_HANDSHAKE_ROLE_ACCESS_ACTIVE: JSON.stringify({ kid: "role-active", secretBase64: encodedSecret("a") }),
    AGENT_HANDSHAKE_ACCEPTANCE_HMAC_ACTIVE: JSON.stringify({ kid: "accept-active", secretBase64: encodedSecret("b") }),
  };

  for (const env of [
    { ...valid, AGENT_HANDSHAKE_ACCEPTANCE_HMAC_ACTIVE: JSON.stringify({ kid: "accept-active", secretBase64: "not-base64" }) },
    { ...valid, AGENT_HANDSHAKE_ACCEPTANCE_HMAC_ACTIVE: JSON.stringify({ kid: "accept-active", secretBase64: Buffer.alloc(31, "b").toString("base64") }) },
    { ...valid, AGENT_HANDSHAKE_ACCEPTANCE_HMAC_PREVIOUS: JSON.stringify({ kid: "accept-active", secretBase64: encodedSecret("c") }) },
    { ...valid, AGENT_HANDSHAKE_ACCEPTANCE_HMAC_ACTIVE: JSON.stringify({ kid: "accept-active", secretBase64: encodedSecret("a") }) },
    { ...valid, AGENT_HANDSHAKE_ACCEPTANCE_HMAC_ACTIVE: JSON.stringify({ kid: "role-active", secretBase64: encodedSecret("b") }) },
  ]) {
    assert.throws(() => __runtimeV2KeyConfig(env));
  }
});

test("copied invitation expires at rendezvous close", async () => {
  const invitationExpMs = nbfMs + 120000;
  let currentMs = nbfMs + 1;
  const service = createV2InvitationService({
    activeKey: key,
    verificationKeys: [key],
    store: createV2InvitationStore(),
    nowMs: () => currentMs,
  });
  const acceptedInvite = await service.create({ sessionId, statementDigest, nbfMs, expMs, invitationExpMs });

  assert.equal(readV2RoleAccessPayload(acceptedInvite.initiatorAccess).expMs, String(expMs));
  assert.equal(readV2RoleAccessPayload(acceptedInvite.responderInvitation).expMs, String(invitationExpMs));
  await service.accept({ invitation: acceptedInvite.responderInvitation });

  const expiredInvite = await service.create({ sessionId, statementDigest, nbfMs, expMs, invitationExpMs });
  currentMs = invitationExpMs;
  await assert.rejects(() => service.accept({ invitation: expiredInvite.responderInvitation }));
});

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

test("the same invitation and idempotency key resume durably with byte-identical responder access", async () => {
  const acceptanceHmacKeys = [{ kid: "accept-2026-08", secret: randomBytes(32) }];
  const service = createV2InvitationService({
    activeKey: key,
    verificationKeys: [key],
    acceptanceHmacKeys,
    store: createV2InvitationStore(),
    nowMs: () => nbfMs + 1,
  });
  const created = await service.create({ sessionId, statementDigest, nbfMs, expMs });
  const acceptanceIdempotencyKey = randomUUID();

  const first = await service.accept({ invitation: created.responderInvitation, acceptanceIdempotencyKey });
  const second = await service.accept({ invitation: created.responderInvitation, acceptanceIdempotencyKey });

  assert.equal(second.responderAccess, first.responderAccess);
  assert.equal(second.claimedAtMs, first.claimedAtMs);
});

test("accept begins a durable claim but leaves coordinator advancement incomplete", async () => {
  const acceptanceHmacKeys = [{ kid: "accept-2026-08", secret: randomBytes(32) }];
  const store = createV2InvitationStore();
  const service = createV2InvitationService({
    activeKey: key,
    verificationKeys: [key],
    acceptanceHmacKeys,
    store,
    nowMs: () => nbfMs + 1,
  });
  const created = await service.create({ sessionId, statementDigest, nbfMs, expMs });
  const invitationJti = readV2RoleAccessPayload(created.responderInvitation).jti;

  const accepted = await service.accept({ invitation: created.responderInvitation, acceptanceIdempotencyKey: randomUUID() });
  const stored = await store.get(invitationJti);

  assert.equal(accepted.claim.phase, "claimed");
  assert.equal(stored.claim.phase, "claimed");
  assert.equal(stored.claim.completedAtMs, null);
});

test("a different idempotency key is rejected after a durable keyed claim", async () => {
  const acceptanceHmacKeys = [{ kid: "accept-2026-08", secret: randomBytes(32) }];
  const service = createV2InvitationService({
    activeKey: key,
    verificationKeys: [key],
    acceptanceHmacKeys,
    store: createV2InvitationStore(),
    nowMs: () => nbfMs + 1,
  });
  const created = await service.create({ sessionId, statementDigest, nbfMs, expMs });

  await service.accept({ invitation: created.responderInvitation, acceptanceIdempotencyKey: randomUUID() });
  await assert.rejects(() => service.accept({
    invitation: created.responderInvitation,
    acceptanceIdempotencyKey: randomUUID(),
  }));
});

test("a missing idempotency key is rejected after a durable keyed claim", async () => {
  const acceptanceHmacKeys = [{ kid: "accept-2026-08", secret: randomBytes(32) }];
  const service = createV2InvitationService({
    activeKey: key,
    verificationKeys: [key],
    acceptanceHmacKeys,
    store: createV2InvitationStore(),
    nowMs: () => nbfMs + 1,
  });
  const created = await service.create({ sessionId, statementDigest, nbfMs, expMs });

  await service.accept({ invitation: created.responderInvitation, acceptanceIdempotencyKey: randomUUID() });
  await assert.rejects(() => service.accept({ invitation: created.responderInvitation }));
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

test("v1 unclaimed and claimed records load as v2 claim states", async () => {
  const directory = await mkdtemp(join(tmpdir(), "clockchain-v2-invite-"));
  const path = join(directory, "state.json");
  const unclaimedJti = randomUUID();
  const claimedJti = randomUUID();
  await writeFile(path, JSON.stringify({
    schema: "clockchain.agent-handshake-v2-invitations/v1",
    records: {
      [unclaimedJti]: {
        invitationDigest: "a".repeat(64),
        jti: unclaimedJti,
        sessionId,
        statementDigest,
        expMs: String(expMs),
        claimedAtMs: null,
        metadata: null,
      },
      [claimedJti]: {
        invitationDigest: "b".repeat(64),
        jti: claimedJti,
        sessionId,
        statementDigest,
        expMs: String(expMs),
        claimedAtMs: String(nbfMs + 1),
        metadata: null,
      },
    },
  }) + "\n", { mode: 0o600 });

  const store = createV2InvitationStore({ path });

  assert.equal((await store.get(unclaimedJti)).claim, null);
  assert.equal((await store.get(claimedJti)).claim.phase, "legacy_terminal");
});

test("missing idempotency key remains a terminal one-shot claim", async () => {
  const acceptanceHmacKeys = [{ kid: "accept-2026-08", secret: randomBytes(32) }];
  const service = createV2InvitationService({
    activeKey: key,
    verificationKeys: [key],
    acceptanceHmacKeys,
    store: createV2InvitationStore(),
    nowMs: () => nbfMs + 1,
  });
  const created = await service.create({ sessionId, statementDigest, nbfMs, expMs });

  await service.accept({ invitation: created.responderInvitation });
  await assert.rejects(() => service.accept({
    invitation: created.responderInvitation,
    acceptanceIdempotencyKey: randomUUID(),
  }));
});

test("present idempotency keys must be UUIDv4 or at least 128-bit base64url", async () => {
  const acceptanceHmacKeys = [{ kid: "accept-2026-08", secret: randomBytes(32) }];
  const service = createV2InvitationService({
    activeKey: key,
    verificationKeys: [key],
    acceptanceHmacKeys,
    store: createV2InvitationStore(),
    nowMs: () => nbfMs + 1,
  });
  const created = await service.create({ sessionId, statementDigest, nbfMs, expMs });

  await assert.rejects(() => service.accept({ invitation: created.responderInvitation, acceptanceIdempotencyKey: "not-random" }));
  await assert.rejects(() => service.accept({ invitation: created.responderInvitation, acceptanceIdempotencyKey: randomBytes(15).toString("base64url") }));
  await service.accept({ invitation: created.responderInvitation, acceptanceIdempotencyKey: randomBytes(16).toString("base64url") });
});

test("keyed persistent state stores HMAC material only", async () => {
  const directory = await mkdtemp(join(tmpdir(), "clockchain-v2-invite-"));
  const path = join(directory, "state.json");
  const acceptanceIdempotencyKey = randomUUID();
  const acceptanceHmacKeys = [{ kid: "accept-2026-08", secret: randomBytes(32) }];
  const service = createV2InvitationService({
    activeKey: key,
    verificationKeys: [key],
    acceptanceHmacKeys,
    store: createV2InvitationStore({ path }),
    nowMs: () => nbfMs + 1,
  });
  const created = await service.create({ sessionId, statementDigest, nbfMs, expMs });

  const accepted = await service.accept({ invitation: created.responderInvitation, acceptanceIdempotencyKey });
  const text = await readFile(path, "utf8");

  assert.equal(text.includes(created.responderInvitation), false);
  assert.equal(text.includes(acceptanceIdempotencyKey), false);
  assert.equal(text.includes(accepted.responderAccess), false);
  assert.equal(text.includes(acceptanceHmacKeys[0].secret.toString("hex")), false);
  assert.match(text, /acceptanceKeyDigest/);
});

test("keyed claims retry byte-identically after restart", async () => {
  const directory = await mkdtemp(join(tmpdir(), "clockchain-v2-invite-"));
  const path = join(directory, "state.json");
  const acceptanceIdempotencyKey = randomUUID();
  const acceptanceHmacKeys = [{ kid: "accept-2026-08", secret: randomBytes(32) }];
  const firstService = createV2InvitationService({
    activeKey: key,
    verificationKeys: [key],
    acceptanceHmacKeys,
    store: createV2InvitationStore({ path }),
    nowMs: () => nbfMs + 1,
  });
  const created = await firstService.create({ sessionId, statementDigest, nbfMs, expMs });
  const first = await firstService.accept({ invitation: created.responderInvitation, acceptanceIdempotencyKey });
  const restarted = createV2InvitationService({
    activeKey: key,
    verificationKeys: [key],
    acceptanceHmacKeys,
    store: createV2InvitationStore({ path }),
    nowMs: () => nbfMs + 2,
  });

  const second = await restarted.accept({ invitation: created.responderInvitation, acceptanceIdempotencyKey });

  assert.equal(second.responderAccess, first.responderAccess);
  assert.equal(second.claimedAtMs, first.claimedAtMs);
});

test("responder signing key rotation retries with the original retained signing key", async () => {
  const directory = await mkdtemp(join(tmpdir(), "clockchain-v2-invite-"));
  const path = join(directory, "state.json");
  const oldSigningKey = { kid: "role-2026-08", secret: randomBytes(32) };
  const newSigningKey = { kid: "role-2026-09", secret: randomBytes(32) };
  const acceptanceIdempotencyKey = randomUUID();
  const acceptanceHmacKeys = [{ kid: "accept-2026-08", secret: randomBytes(32) }];
  const firstService = createV2InvitationService({
    activeKey: oldSigningKey,
    verificationKeys: [oldSigningKey],
    acceptanceHmacKeys,
    store: createV2InvitationStore({ path }),
    nowMs: () => nbfMs + 1,
  });
  const created = await firstService.create({ sessionId, statementDigest, nbfMs, expMs });
  const first = await firstService.accept({ invitation: created.responderInvitation, acceptanceIdempotencyKey });
  const restarted = createV2InvitationService({
    activeKey: newSigningKey,
    verificationKeys: [newSigningKey, oldSigningKey],
    acceptanceHmacKeys,
    store: createV2InvitationStore({ path }),
    nowMs: () => nbfMs + 2,
  });

  const second = await restarted.accept({ invitation: created.responderInvitation, acceptanceIdempotencyKey });

  assert.equal(second.responderAccess, first.responderAccess);
  assert.equal(readV2RoleAccessPayload(second.responderAccess).kid, oldSigningKey.kid);
});

test("acceptance HMAC rotation retries with retained old keys", async () => {
  const directory = await mkdtemp(join(tmpdir(), "clockchain-v2-invite-"));
  const path = join(directory, "state.json");
  const oldHmacKey = { kid: "accept-2026-08", secret: randomBytes(32) };
  const newHmacKey = { kid: "accept-2026-09", secret: randomBytes(32) };
  const acceptanceIdempotencyKey = randomUUID();
  const firstService = createV2InvitationService({
    activeKey: key,
    verificationKeys: [key],
    acceptanceHmacKeys: [oldHmacKey],
    store: createV2InvitationStore({ path }),
    nowMs: () => nbfMs + 1,
  });
  const created = await firstService.create({ sessionId, statementDigest, nbfMs, expMs });
  const first = await firstService.accept({ invitation: created.responderInvitation, acceptanceIdempotencyKey });
  const restarted = createV2InvitationService({
    activeKey: key,
    verificationKeys: [key],
    acceptanceHmacKeys: [newHmacKey, oldHmacKey],
    store: createV2InvitationStore({ path }),
    nowMs: () => nbfMs + 2,
  });

  const second = await restarted.accept({ invitation: created.responderInvitation, acceptanceIdempotencyKey });

  assert.equal(second.responderAccess, first.responderAccess);
});

test("missing retained acceptance HMAC key fails safely", async () => {
  const directory = await mkdtemp(join(tmpdir(), "clockchain-v2-invite-"));
  const path = join(directory, "state.json");
  const acceptanceIdempotencyKey = randomUUID();
  const firstService = createV2InvitationService({
    activeKey: key,
    verificationKeys: [key],
    acceptanceHmacKeys: [{ kid: "accept-2026-08", secret: randomBytes(32) }],
    store: createV2InvitationStore({ path }),
    nowMs: () => nbfMs + 1,
  });
  const created = await firstService.create({ sessionId, statementDigest, nbfMs, expMs });
  await firstService.accept({ invitation: created.responderInvitation, acceptanceIdempotencyKey });
  const restarted = createV2InvitationService({
    activeKey: key,
    verificationKeys: [key],
    acceptanceHmacKeys: [{ kid: "accept-2026-09", secret: randomBytes(32) }],
    store: createV2InvitationStore({ path }),
    nowMs: () => nbfMs + 2,
  });

  await assert.rejects(() => restarted.accept({ invitation: created.responderInvitation, acceptanceIdempotencyKey }));
});

test("existing durable same-key retry after invitation expiry succeeds before responder access expiry", async () => {
  const acceptanceHmacKeys = [{ kid: "accept-2026-08", secret: randomBytes(32) }];
  const invitationExpMs = nbfMs + 120000;
  const metadataStatementDigest = v2CanonicalRecord(terms).digest;
  let currentMs = nbfMs + 1;
  const service = createV2InvitationService({
    activeKey: key,
    verificationKeys: [key],
    acceptanceHmacKeys,
    store: createV2InvitationStore(),
    nowMs: () => currentMs,
  });
  const created = await service.create({
    sessionId,
    statementDigest: metadataStatementDigest,
    nbfMs,
    expMs,
    invitationExpMs,
    metadata: {
      terms,
      repositorySha: "a".repeat(40),
      hostSessionKeyCertificate: { certificate: "host" },
      invitationExpiresAtMs: String(invitationExpMs),
      sessionDeadlineMs: String(expMs),
      createdAtMs: String(nbfMs),
      sessionOpenedBlock: "1",
    },
  });
  const acceptanceIdempotencyKey = randomUUID();
  const first = await service.accept({ invitation: created.responderInvitation, acceptanceIdempotencyKey });

  currentMs = invitationExpMs;

  const second = await service.accept({ invitation: created.responderInvitation, acceptanceIdempotencyKey });

  assert.equal(second.responderAccess, first.responderAccess);
  assert.equal(second.claimedAtMs, first.claimedAtMs);
});

test("first keyed claim at invitation expiry is rejected", async () => {
  const acceptanceHmacKeys = [{ kid: "accept-2026-08", secret: randomBytes(32) }];
  const service = createV2InvitationService({
    activeKey: key,
    verificationKeys: [key],
    acceptanceHmacKeys,
    store: createV2InvitationStore(),
    nowMs: () => expMs,
  });
  const created = await service.create({ sessionId, statementDigest, nbfMs, expMs });

  await assert.rejects(() => service.accept({ invitation: created.responderInvitation, acceptanceIdempotencyKey: randomUUID() }));
});

test("existing durable same-key retry is rejected at responder access expiry", async () => {
  const acceptanceHmacKeys = [{ kid: "accept-2026-08", secret: randomBytes(32) }];
  let currentMs = nbfMs + 1;
  const service = createV2InvitationService({
    activeKey: key,
    verificationKeys: [key],
    acceptanceHmacKeys,
    store: createV2InvitationStore(),
    nowMs: () => currentMs,
  });
  const created = await service.create({ sessionId, statementDigest, nbfMs, expMs, invitationExpMs: nbfMs + 120000 });
  const acceptanceIdempotencyKey = randomUUID();
  await service.accept({ invitation: created.responderInvitation, acceptanceIdempotencyKey });

  currentMs = expMs;

  await assert.rejects(() => service.accept({ invitation: created.responderInvitation, acceptanceIdempotencyKey }));
});

test("store advances claim phases with invitation and HMAC binding", async () => {
  const store = createV2InvitationStore();
  const service = createV2InvitationService({
    activeKey: key,
    verificationKeys: [key],
    acceptanceHmacKeys: [{ kid: "accept-2026-08", secret: randomBytes(32) }],
    store,
    nowMs: () => nbfMs + 1,
  });
  const created = await service.create({ sessionId, statementDigest, nbfMs, expMs });
  const invitationJti = readV2RoleAccessPayload(created.responderInvitation).jti;
  const binding = {
    invitationDigest: invitationDigest(created.responderInvitation),
    acceptanceKey: { kid: "accept-2026-08", digest: "d".repeat(64) },
  };

  await store.beginClaim({
    invitationDigest: binding.invitationDigest,
    jti: invitationJti,
    nowMs: String(nbfMs + 1),
    acceptanceKey: binding.acceptanceKey,
    responderAccess: {
      kid: key.kid,
      jti: randomUUID(),
      nbfMs: String(nbfMs),
      expMs: String(expMs),
    },
  });
  await assert.rejects(() => store.advanceClaim({ ...binding, jti: invitationJti, phase: "initialized", acceptanceKey: { kid: "accept-2026-08", digest: "e".repeat(64) } }));
  await assert.rejects(() => store.advanceClaim({ ...binding, jti: invitationJti, phase: "initialized", acceptanceKey: undefined }));
  await assert.rejects(() => store.advanceClaim({ ...binding, invitationDigest: "e".repeat(64), jti: invitationJti, phase: "initialized" }));
  await store.advanceClaim({ ...binding, jti: invitationJti, phase: "initialized" });
  await store.advanceClaim({ ...binding, jti: invitationJti, phase: "posted" });
  const replayedEarlier = await store.advanceClaim({ ...binding, jti: invitationJti, phase: "initialized" });
  const replayedCurrent = await store.advanceClaim({ ...binding, jti: invitationJti, phase: "posted" });
  await store.advanceClaim({ ...binding, jti: invitationJti, phase: "completed", completedAtMs: String(nbfMs + 2) });

  const stored = await store.get(invitationJti);
  assert.equal(replayedEarlier.claim.phase, "posted");
  assert.equal(replayedCurrent.claim.phase, "posted");
  assert.equal(stored.claim.phase, "completed");
  assert.equal(stored.claim.completedAtMs, String(nbfMs + 2));
});
