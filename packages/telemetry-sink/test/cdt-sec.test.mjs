// CDT-SEC (state/ledger/notes/cdt-integration-security-review.md): sink-side
// fixes for L4 (lane store pruning). No network.
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  createEnrollmentRegistry,
  createLaneService,
  createTokenStore,
  enrollParty,
  laneOpenMessage,
  runLinkMessage,
} from "../dist/index.js";

const contract = generateKeyPairSync("ed25519");
const contractPublicKeys = { "contract-server": contract.publicKey };
const buyerX = (() => {
  const jwk = generateKeyPairSync("x25519").privateKey.export({ format: "jwk" });
  return `0x${Buffer.from(jwk.x, "base64url").toString("hex")}`;
})();

const T0 = Date.parse("2030-01-01T00:00:00.000Z");
const HOUR = 3600_000;
const iso = (ms) => new Date(ms).toISOString();

function laneOpen({ keyId = "buyer-key", role = "buyer", mcpSessionId, ts }) {
  const fields = { keyId, role, mcpSessionId, ts: iso(ts) };
  const sig = sign(null, Buffer.from(laneOpenMessage(fields, { alg: "ed25519", keyId: "contract-server" }), "utf8"), contract.privateKey);
  return { schema: "ac-lane-open/v1", ...fields, signature: { alg: "ed25519", keyId: "contract-server", sig: `0x${sig.toString("hex")}` } };
}

function runLink(runId, lanes, ts) {
  const sig = sign(null, Buffer.from(runLinkMessage({ runId, lanes, ts: iso(ts) }, { alg: "ed25519", keyId: "contract-server" }), "utf8"), contract.privateKey);
  return { schema: "ac-run-link/v1", runId, lanes, ts: iso(ts), signature: { alg: "ed25519", keyId: "contract-server", sig: `0x${sig.toString("hex")}` } };
}

async function laneStore() {
  const dir = mkdtempSync(path.join(tmpdir(), "cdt-sec-lanes-"));
  let now = T0;
  const clock = () => now;
  const tokens = createTokenStore({ now: clock, recordsFile: path.join(dir, "tokens.json") });
  await enrollParty({ file: path.join(dir, "enrollments.json"), keyId: "buyer-key", role: "buyer", x25519: buyerX });
  const enrollments = createEnrollmentRegistry({ file: path.join(dir, "enrollments.json") });
  const file = path.join(dir, "lanes.json");
  const make = () => createLaneService({ tokens, enrollments, contractKeys: contractPublicKeys, file, now: clock });
  return { dir, file, make, setNow: (ms) => { now = ms; }, now: () => now };
}

test("L4 sink: an unlinked lane past window + grace is pruned; a linked lane and its link are kept", async () => {
  const s = await laneStore();
  let lanes = s.make();
  const stale = await lanes.open(laneOpen({ mcpSessionId: "sess-stale", ts: T0 }));
  const linked = await lanes.open(laneOpen({ mcpSessionId: "sess-linked", ts: T0 }));
  assert.equal(stale.ok, true);
  assert.equal(linked.ok, true);
  const link = await lanes.link("run-1", runLink("run-1", { buyer: [linked.laneId], provider: [] }, T0));
  assert.equal(link.ok, true);
  assert.equal(statSync(s.file).mode & 0o777, 0o600, "lanes.json is owner-only");

  // Still inside window + grace: nothing is dropped.
  s.setNow(T0 + 7 * HOUR - 1);
  const mid = await lanes.open(laneOpen({ mcpSessionId: "sess-mid", ts: s.now() }));
  assert.equal(mid.ok, true);
  assert.ok(lanes.lane(stale.laneId), "kept until window + grace");

  // Past window (6 h) + grace (1 h): the next write prunes the stale lane.
  s.setNow(T0 + 7 * HOUR + 1);
  const fresh = await lanes.open(laneOpen({ mcpSessionId: "sess-fresh", ts: s.now() }));
  assert.equal(fresh.ok, true);
  assert.equal(lanes.lane(stale.laneId), undefined, "the expired unlinked lane is forgotten");
  assert.equal(lanes.lane(linked.laneId)?.runId, "run-1", "a linked lane is run evidence and is kept");
  assert.equal(lanes.linkFor("run-1")?.lanes.buyer[0], linked.laneId);
  const onDisk = JSON.parse(readFileSync(s.file, "utf8"));
  assert.equal(Object.hasOwn(onDisk.lanes, stale.laneId), false, "pruned from lanes.json too");
  assert.equal(Object.hasOwn(onDisk.lanes, linked.laneId), true);

  // A reload keeps the pruned view, and boot itself prunes what expired while down.
  s.setNow(T0 + 8 * HOUR); // sess-mid (opened at ~7 h) is still inside its window + grace
  lanes = s.make();
  assert.equal(lanes.lane(stale.laneId), undefined);
  assert.ok(lanes.lane(mid.laneId));
  s.setNow(T0 + 14 * HOUR);
  lanes = s.make();
  assert.equal(lanes.lane(mid.laneId), undefined, "boot prunes a lane that expired while the sink was down");
  assert.equal(Object.hasOwn(JSON.parse(readFileSync(s.file, "utf8")).lanes, mid.laneId), false);
  assert.equal(lanes.lane(linked.laneId)?.runId, "run-1");
});

test("L4 sink: a pruned lane's stale signed open cannot be replayed", async () => {
  const s = await laneStore();
  const lanes = s.make();
  const body = laneOpen({ mcpSessionId: "sess-replay", ts: T0 });
  assert.equal((await lanes.open(body)).ok, true);
  s.setNow(T0 + 8 * HOUR);
  await lanes.open(laneOpen({ mcpSessionId: "sess-other", ts: s.now() })); // triggers the prune
  const replay = await lanes.open(body);
  assert.deepEqual(replay, { ok: false, code: "RECEIPT_STALE" }, "the skew check refuses the old signed open");
});
