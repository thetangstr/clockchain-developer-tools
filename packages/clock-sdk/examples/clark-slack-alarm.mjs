// Clark — verified-time alarm daemon for a Slack bot, on an always-on host (the mini).
//
// A small always-on Node service: Clark POSTs an alarm to it; the daemon disciplines
// its clock to Clockchain (NTP-style), fires at the requested time by posting to Slack
// (chat.postMessage), and anchors a tamper-evident receipt that it fired on verified
// time. Alarms persist to a JSON file and re-arm on restart.
//
// Why a daemon (not inside Clark): the mini is always-on, which removes the only
// weakness of a client-side alarm ("fires only while the host runs"). Clark stays the
// Slack conversational layer; this process is the timekeeper. It runs under pm2 just
// like clockchain-mcp.
//
// Run (on the mini):
//   npm run build                                  # from the repo root
//   export CLOCKCHAIN_API_KEY=... CLOCKCHAIN_CLIENT_ID=... CLOCKCHAIN_WALLET_ID=...
//   export SLACK_BOT_TOKEN=xoxb-...                # Clark's bot token (chat:write scope)
//   pm2 start packages/clock-sdk/examples/clark-slack-alarm.mjs --name clark-alarm
//
// Clark registers an alarm (from anywhere on the mini / LAN):
//   curl -s localhost:8787/alarm -d '{"channel":"#ops","text":"standup","inSeconds":600}'
//   curl -s localhost:8787/alarm -d '{"channel":"#ops","text":"deadline","fireAt":1782345600000}'
// List / cancel:
//   curl -s localhost:8787/alarms
//   curl -s localhost:8787/cancel -d '{"id":"<id>"}'

import http from "node:http";
import fs from "node:fs";
import { ClockchainClient, readConfigFromEnv } from "@clockchain/core";
import { ClockchainClock, ClockScheduler } from "@clockchain/clock-sdk";

const SLACK_TOKEN = process.env.SLACK_BOT_TOKEN;
const PORT = Number(process.env.CLARK_ALARM_PORT ?? 8787);
const STORE = process.env.CLARK_ALARM_STORE ?? "./clark-alarms.json";
if (!SLACK_TOKEN) { console.error("Set SLACK_BOT_TOKEN (Clark's bot token)."); process.exit(1); }

const cc = new ClockchainClient(readConfigFromEnv());
const clock = new ClockchainClock(cc);
await clock.sync();
clock.startAutoResync();                 // re-calibrate to Clockchain periodically
const scheduler = new ClockScheduler({ clock, client: cc, confirmSource: cc });

// --- durable store: { [id]: { channel, text, fireAt, state } } ---
const load = () => { try { return JSON.parse(fs.readFileSync(STORE, "utf8")); } catch { return {}; } };
const store = load();
const save = () => fs.writeFileSync(STORE, JSON.stringify(store, null, 2));
let seq = 0;

async function postSlack(channel, text) {
  try {
    const r = await fetch("https://slack.com/api/chat.postMessage", {
      method: "POST",
      headers: { "content-type": "application/json; charset=utf-8", authorization: `Bearer ${SLACK_TOKEN}` },
      body: JSON.stringify({ channel, text }),
    });
    const j = await r.json();
    if (!j.ok) console.error("slack error:", j.error);
    return j;
  } catch (e) { console.error("slack post failed:", e); }
}

function arm(id) {
  const a = store[id];
  scheduler.schedule({
    id,
    fireAt: a.fireAt,
    mode: "confirmed",          // re-check consensus at the boundary before firing
    agentId: "clark",
    action: async (ctx) => {
      await postSlack(a.channel, `⏰ ${a.text} — fired at verified time ${new Date(ctx.epochMs).toISOString()} (±${Math.round(ctx.uncertaintyMs)}ms)`);
      a.state = "fired";
      save();
    },
  });
}

// re-arm everything still pending after a restart (missed-while-down -> marked, not fired)
for (const [id, a] of Object.entries(store)) {
  if (a.state !== "pending") continue;
  if (a.fireAt <= clock.now().epochMs) { a.state = "missed"; save(); }
  else arm(id);
}

// --- tiny HTTP API for Clark ---
const body = (req) => new Promise((res) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => res(b)); });

http.createServer(async (req, res) => {
  const json = (code, obj) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(obj)); };
  try {
    if (req.method === "POST" && req.url === "/alarm") {
      const { channel, text, fireAt, inSeconds } = JSON.parse(await body(req));
      if (!channel || !text) return json(400, { error: "channel and text required" });
      const when = fireAt ?? clock.now().epochMs + (Number(inSeconds) || 0) * 1000;
      const id = `alarm-${when}-${seq++}`;
      store[id] = { channel, text, fireAt: when, state: "pending" };
      save();
      arm(id);
      return json(200, { id, fireAt: when, firesInSeconds: Math.round((when - clock.now().epochMs) / 1000) });
    }
    if (req.method === "GET" && req.url === "/alarms") {
      return json(200, scheduler.list());
    }
    if (req.method === "POST" && req.url === "/cancel") {
      const { id } = JSON.parse(await body(req));
      const ok = scheduler.cancel(id);
      if (store[id]) { store[id].state = "cancelled"; save(); }
      return json(200, { cancelled: ok });
    }
    json(404, { error: "not found" });
  } catch (e) { json(400, { error: String(e) }); }
}).listen(PORT, () => console.log(`clark-alarm listening on :${PORT} (clock synced, ±${Math.round(clock.now().uncertaintyMs)}ms)`));
