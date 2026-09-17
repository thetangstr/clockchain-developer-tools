import { generatePrivateKey, privateKeyToAccount, type PrivateKeyAccount } from "viem/accounts";

import { canonicalBytes } from "@clockchain/mcp-server/handshake/protocol.js";
import {
  buildStandaloneConsentRecord,
  normalizeStandaloneTerms,
  standaloneAuthorityRecord,
  standaloneCanonicalRecord,
} from "@clockchain/mcp-server/standalone-handshake/protocol.js";

/** One visible beat in the theater feed. `pane` routes it to a column. */
export interface DemoEvent {
  ts: number;
  pane: "initiator" | "responder" | "ledger" | "control";
  kind: "info" | "action" | "sign" | "anchor" | "refusal" | "check" | "message" | "error" | "verify";
  label: string;
  detail?: string;
}

export type DemoEmit = (event: DemoEvent) => void;

export interface FaultFlags {
  /** Responder signs its authority statement with a different key. */
  forgedSignature?: boolean;
  /** Responder's capability manifest names a different purpose. */
  mismatchedManifest?: boolean;
  /** After opening, send a kind the terms never consented to. */
  outOfScope?: boolean;
  /** After opening, send a body over the consented byte cap. */
  oversized?: boolean;
  /** Try to send before the channel opens. */
  preOpenSend?: boolean;
  /** Try to re-claim the consumed invitation. */
  replayInvitation?: boolean;
  /** Try to send after revocation. */
  sendAfterRevoke?: boolean;
  /** Poll handshake_status with a forged csha_ handle. */
  forgedHandle?: boolean;
}

export interface DemoRunResult {
  sessionId?: string;
  events: DemoEvent[];
  openingReceipt?: Record<string, unknown>;
  closureReceipt?: Record<string, unknown>;
  refusals: { label: string; code: string }[];
}

const ACCEPT = "application/json, text/event-stream";
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const short = (v: unknown, keep = 10) => {
  const s = String(v ?? "");
  return s.length > keep * 2 + 3 ? `${s.slice(0, keep)}…${s.slice(-keep)}` : s;
};

async function rpc(endpoint: string, method: string, params: Record<string, unknown> = {}): Promise<any> {
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "content-type": "application/json", accept: ACCEPT },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const text = await res.text();
  const dataLine = text.split("\n").find((l) => l.startsWith("data:"));
  const body = JSON.parse(dataLine ? dataLine.slice(5) : text);
  if (body.error) throw new Error(`RPC ${method}: ${JSON.stringify(body.error).slice(0, 200)}`);
  const inner = body.result?.content?.[0]?.text;
  const payload = inner ? JSON.parse(inner) : body.result;
  if (body.result?.isError) {
    const err = new Error(typeof payload === "object" ? JSON.stringify(payload) : String(payload));
    (err as any).payload = payload;
    throw err;
  }
  return payload;
}

/** A refused call still yields its spec'd reason code — that IS the demo. */
async function call(endpoint: string, name: string, args: Record<string, unknown>): Promise<{ ok: boolean; payload: any }> {
  try {
    return { ok: true, payload: await rpc(endpoint, "tools/call", { name, arguments: args }) };
  } catch (e) {
    const payload = (e as any)?.payload;
    return { ok: false, payload: typeof payload === "object" && payload ? payload : { error: String((e as Error).message).slice(0, 160) } };
  }
}

const refusalCode = (payload: any): string => String(payload?.error ?? payload?.refusal ?? "refused");

export async function runHandshake(options: {
  endpoint: string;
  faults?: FaultFlags;
  emit: DemoEmit;
  paceMs?: number;
}): Promise<DemoRunResult> {
  const { endpoint, emit } = options;
  const faults = options.faults ?? {};
  const pace = options.paceMs ?? 450;
  const result: DemoRunResult = { events: [], refusals: [] };
  const say = (pane: DemoEvent["pane"], kind: DemoEvent["kind"], label: string, detail?: string) => {
    const e: DemoEvent = { ts: Date.now(), pane, kind, label, detail };
    result.events.push(e);
    emit(e);
  };
  const refuse = async (pane: DemoEvent["pane"], label: string, toolCall: Promise<{ ok: boolean; payload: any }>) => {
    const r = await toolCall;
    const code = r.ok ? "unexpectedly accepted" : refusalCode(r.payload);
    say(pane, r.ok ? "error" : "refusal", label, code);
    result.refusals.push({ label, code });
    await sleep(pace);
    return r;
  };

  // --- Two strangers: fresh Sepolia keypairs that never leave this process ---
  const initiator = privateKeyToAccount(generatePrivateKey());
  const responder = privateKeyToAccount(generatePrivateKey());
  const forged = privateKeyToAccount(generatePrivateKey());
  const ia = initiator.address.toLowerCase();
  const ra = responder.address.toLowerCase();
  say("initiator", "info", "Agent A generates an ephemeral Sepolia keypair", `address ${ia} — key never leaves the agent`);
  say("responder", "info", "Agent B generates an ephemeral Sepolia keypair", `address ${ra} — key never leaves the agent`);
  say("ledger", "info", "Gateway", endpoint);
  await sleep(pace);

  const terms = {
    reference: `theater-${new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-")}`,
    purpose: "Negotiate a Q3 delivery schedule for component orders",
    channelLimits: { durationSeconds: "3600", messageKinds: ["question", "proposal", "evidence"], maxMessageBytes: "16384" },
    identityPolicy: { erc8004: "not_required", chainId: null, registryAddress: null },
  };
  const termsDigest = standaloneCanonicalRecord(normalizeStandaloneTerms(terms)).digest;
  say("initiator", "info", "Terms", `duration ${terms.channelLimits.durationSeconds}s · kinds ${terms.channelLimits.messageKinds.join("/")} · cap ${terms.channelLimits.maxMessageBytes}B`);

  const readinessFor = async (account: PrivateKeyAccount, address: string, party: string, signer: PrivateKeyAccount = account) => {
    const r: Record<string, any> = {
      sessionKeyAddress: address,
      identity: null,
      authorityStatement: { accountableParty: party, statement: `${party} authorizes its agent to negotiate the Q3 delivery schedule.` },
      capabilityManifest: { dataHandlingClass: "confidential", purpose: terms.purpose },
      authoritySignatureHex: "",
    };
    const bytes = canonicalBytes(standaloneAuthorityRecord({ sessionKeyAddress: address, authorityStatement: r.authorityStatement }));
    r.authoritySignatureHex = await signer.signMessage({ message: { raw: bytes } });
    return r;
  };

  // --- Invite ---
  say("initiator", "sign", "A signs its authority statement (EIP-191, local)", `authorityRecord → ${short(standaloneCanonicalRecord(standaloneAuthorityRecord({ sessionKeyAddress: ia, authorityStatement: { accountableParty: "Acme Buying LLC", statement: "Acme Buying LLC authorizes its agent to negotiate the Q3 delivery schedule." } })).digest, 8)}`);
  const invite = await call(endpoint, "handshake_invite", { ...terms, readiness: await readinessFor(initiator, ia, "Acme Buying LLC") });
  if (!invite.ok) {
    say("initiator", "error", "handshake_invite refused", refusalCode(invite.payload));
    return result;
  }
  result.sessionId = invite.payload.sessionId;
  say("initiator", "action", "handshake_invite", `session ${short(invite.payload.sessionId)} · invitation ${short(invite.payload.invitation, 14)}`);
  await sleep(pace);

  // --- Optional fault: replay the invitation after it has been consumed (run post-accept) ---
  const responderSigner = faults.forgedSignature ? forged : responder;
  if (faults.forgedSignature) say("responder", "error", "FAULT: B signs authority with a DIFFERENT key", "recovered address will not match B's sessionKeyAddress");
  const responderReadiness = await readinessFor(responder, ra, "SupplierCo", responderSigner);
  if (faults.mismatchedManifest) {
    responderReadiness.capabilityManifest = { dataHandlingClass: "confidential", purpose: "Discuss Q4 marketing strategy" };
    say("responder", "error", "FAULT: B's manifest purpose does not match the terms", `"${responderReadiness.capabilityManifest.purpose}"`);
  }

  const accept = await call(endpoint, "handshake_accept_invitation", { invitation: invite.payload.invitation, readiness: responderReadiness });
  if (!accept.ok) {
    say("responder", "error", "handshake_accept_invitation refused", refusalCode(accept.payload));
    return result;
  }
  const checklist = accept.payload.checklist;
  for (const c of checklist.checks as { check: string; passed: boolean; reason?: string }[]) {
    say("ledger", "check", `checklist · ${c.check}`, c.passed ? "passed" : `FAILED — ${c.reason}`);
    await sleep(Math.floor(pace / 2));
  }
  say("responder", "action", "handshake_accept_invitation", `stage ${accept.payload.stage} · checklistDigest ${short(checklist.checklistDigest, 8)}`);

  if (accept.payload.stage !== "ready") {
    say("ledger", "anchor", "session ends — ready_failed", "a failed checklist is terminal; no channel, no consent, no anchors");
    return result;
  }
  await sleep(pace);

  if (faults.replayInvitation) {
    await refuse("responder", "FAULT: replay the consumed invitation", call(endpoint, "handshake_accept_invitation", { invitation: invite.payload.invitation, readiness: responderReadiness }));
  }

  // --- Dual consent over the same digest ---
  const consentSig = (account: PrivateKeyAccount, role: string) =>
    account.signMessage({ message: { raw: canonicalBytes(buildStandaloneConsentRecord({ sessionId: result.sessionId!, role, termsDigest, checklistDigest: checklist.checklistDigest })) } });
  say("initiator", "sign", "A signs the consent record", `sessionId + role + termsDigest + checklistDigest`);
  const c1 = await call(endpoint, "consent_sign", { access: invite.payload.roleAccess, signatureHex: await consentSig(initiator, "initiator") });
  say("initiator", c1.ok ? "action" : "error", "consent_sign (initiator)", c1.ok ? `stage ${c1.payload.stage}` : refusalCode(c1.payload));
  say("responder", "sign", "B signs the identical consent digest", "both signatures must cover the same canonical record");
  const c2 = await call(endpoint, "consent_sign", { access: accept.payload.roleAccess, signatureHex: await consentSig(responder, "responder") });
  say("responder", c2.ok ? "action" : "error", "consent_sign (responder)", c2.ok ? `stage ${c2.payload.stage}` : refusalCode(c2.payload));
  if (!c1.ok || !c2.ok) return result;
  await sleep(pace);

  if (faults.preOpenSend) {
    await refuse("initiator", "FAULT: send before the channel opens", call(endpoint, "channel_send", { access: invite.payload.roleAccess, kind: "question", body: "early?" }));
  }

  // --- Open: three anchors land on-chain before the channel exists ---
  const open = await call(endpoint, "channel_open", { access: invite.payload.roleAccess });
  if (!open.ok) {
    say("ledger", "error", "channel_open refused", refusalCode(open.payload));
    return result;
  }
  result.openingReceipt = open.payload;
  for (const a of open.payload.anchors as { kind: string; digest: string; blockHeight: string; ledgerId: string }[]) {
    say("ledger", "anchor", `anchor · ${a.kind}`, `block ${a.blockHeight} · ${short(a.digest, 8)}`);
    await sleep(Math.floor(pace / 2));
  }
  say("ledger", "info", "channel open", `expires ${new Date(Number(open.payload.expiresAtMs)).toISOString()} · consensus-time enforced`);
  await sleep(pace);

  // --- Bounded exchange ---
  const sends: [DemoEvent["pane"], string, string, string][] = [
    ["responder", accept.payload.roleAccess, "proposal", "Ship Tuesdays from Newark — 14-day lead, $4.20/unit FOB."],
    ["initiator", invite.payload.roleAccess, "question", "Can you hold that price through October 15?"],
    ["responder", accept.payload.roleAccess, "evidence", "Last 3 POs: 98.6% on-time, attached ledger refs."],
  ];
  for (const [pane, access, kind, body] of sends) {
    const s = await call(endpoint, "channel_send", { access, kind, body });
    say(pane, s.ok ? "message" : "refusal", `channel_send · ${kind}`, s.ok ? `seq ${s.payload.seq} — “${body.slice(0, 60)}”` : refusalCode(s.payload));
    await sleep(pace);
  }
  const readI = await call(endpoint, "channel_read", { access: invite.payload.roleAccess });
  say("initiator", "info", "channel_read (A sees only messages addressed to it)", `${(readI.payload?.messages ?? []).length} message(s)`);

  if (faults.outOfScope) {
    await refuse("responder", "FAULT: send 'note' — a kind the terms never consented to", call(endpoint, "channel_send", { access: accept.payload.roleAccess, kind: "note", body: "off scope" }));
  }
  if (faults.oversized) {
    await refuse("initiator", "FAULT: send a body over the 16384-byte cap", call(endpoint, "channel_send", { access: invite.payload.roleAccess, kind: "question", body: "x".repeat(20000) }));
  }
  if (faults.forgedHandle) {
    await refuse("responder", "FAULT: poll status with a forged csha_ handle", call(endpoint, "handshake_status", { access: `csha_${"A".repeat(22)}` }));
  }

  // --- Revoke: the initiator kills the channel; the closure anchors ---
  const revoke = await call(endpoint, "channel_revoke", { access: invite.payload.roleAccess });
  if (revoke.ok) {
    result.closureReceipt = revoke.payload;
    const a = revoke.payload.closureAnchor;
    say("initiator", "action", "channel_revoke", `by ${revoke.payload.byRole}`);
    say("ledger", "anchor", "anchor · closure", `block ${a.blockHeight} · ${short(a.digest, 8)}`);
  } else {
    say("initiator", "error", "channel_revoke refused", refusalCode(revoke.payload));
  }
  await sleep(pace);

  if (faults.sendAfterRevoke) {
    await refuse("responder", "FAULT: send after revocation", call(endpoint, "channel_send", { access: accept.payload.roleAccess, kind: "question", body: "hello?" }));
  }
  const finalStatus = await call(endpoint, "handshake_status", { access: accept.payload.roleAccess });
  say("control", "info", "final stage", `${finalStatus.payload?.stage ?? "?"} · ${result.refusals.length} refusal(s) exercised`);
  return result;
}
