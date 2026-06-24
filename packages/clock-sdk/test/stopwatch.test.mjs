// Unit tests for the stopwatch. Mock core client returning two known log
// responses. No network, no timers.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  stopwatchStart,
  stopwatchStop,
  elapsed,
  verificationRefs,
  parseGatewayTime,
} from "../dist/index.js";

// Mock client: each log() returns a queued LogResponse (pre-confirmed), and
// waitForConfirmation echoes the same record back keyed by ledgerId.
function mockClient(records) {
  const byId = new Map(records.map((r) => [r.ledgerId, r]));
  let i = 0;
  return {
    logCalls: [],
    async log(entry) {
      this.logCalls.push(entry);
      const rec = records[i++];
      return { ...rec, ...entry };
    },
    async waitForConfirmation(ledgerId) {
      return byId.get(ledgerId);
    },
  };
}

const START = "24-06-2026 22:49:40:000 UTC";
const STOP = "24-06-2026 22:49:48:434 UTC";

function rec(ledgerId, blockHeight, createdTimestamp) {
  return {
    clientId: "c",
    walletId: "w",
    assetReferenceId: "x",
    assetHash: "h",
    hashType: "SHA-256",
    versionNumber: 1,
    additionalInfo: "",
    ledgerId,
    blockHeight,
    createdTimestamp,
    updatedTimestamp: null,
    assetName: null,
    type: null,
  };
}

test("elapsed() = delta of the two confirmed createdTimestamps", async () => {
  const client = mockClient([rec("L_start", "100", START), rec("L_stop", "102", STOP)]);
  const handle = await stopwatchStart(client, "task");
  const measurement = await stopwatchStop(client, handle);

  const expected = parseGatewayTime(STOP) - parseGatewayTime(START); // 8434 ms
  assert.equal(expected, 8434);
  assert.equal(elapsed(measurement), 8434);

  assert.equal(measurement.start.epochMs, parseGatewayTime(START));
  assert.equal(measurement.stop.epochMs, parseGatewayTime(STOP));
  assert.equal(measurement.label, "task");
});

test("markers carry ledgerId + blockHeight for keyless verifyOnChain", async () => {
  const client = mockClient([rec("L_start", "100", START), rec("L_stop", "102", STOP)]);
  const handle = await stopwatchStart(client, "task");
  const measurement = await stopwatchStop(client, handle);

  const refs = verificationRefs(measurement);
  assert.deepEqual(refs.start, { ledgerId: "L_start", blockHeight: "100" });
  assert.deepEqual(refs.stop, { ledgerId: "L_stop", blockHeight: "102" });
});

test("start/stop anchor distinct reference ids via log", async () => {
  const client = mockClient([rec("L_start", "100", START), rec("L_stop", "102", STOP)]);
  const handle = await stopwatchStart(client, "build");
  await stopwatchStop(client, handle);

  assert.equal(client.logCalls[0].assetReferenceId, "stopwatch:build:start");
  assert.equal(client.logCalls[1].assetReferenceId, "stopwatch:build:stop");
  // Distinct content hashes for the two markers.
  assert.notEqual(client.logCalls[0].assetHash, client.logCalls[1].assetHash);
});

test("elapsed() is NaN when a createdTimestamp is unparseable", async () => {
  const client = mockClient([
    rec("L_start", "100", START),
    rec("L_stop", "102", "garbage"),
  ]);
  const handle = await stopwatchStart(client, "task");
  const measurement = await stopwatchStop(client, handle);
  assert.ok(Number.isNaN(elapsed(measurement)));
});
