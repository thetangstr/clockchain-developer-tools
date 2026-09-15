import { generatePrivateKey, privateKeyToAccount, type PrivateKeyAccount } from "viem/accounts";

import { canonicalBytes } from "@clockchain/mcp-server/handshake/protocol.js";
import {
  buildStandaloneConsentRecord,
  normalizeStandaloneTerms,
  standaloneAuthorityRecord,
  standaloneCanonicalRecord,
} from "@clockchain/mcp-server/standalone-handshake/protocol.js";

import type { DemoEmit } from "./orchestrator.js";

/**
 * Hosted initiator persona for visitor-as-responder mode: the demo server plays
 * Agent A (its own ephemeral key, its own local EIP-191 signatures) while the
 * visitor's browser plays Agent B with a keypair that never leaves the tab.
 * One visitor session at a time — the theater is single-seat.
 */
export interface VisitorHost {
  sessionId?: string;
  action(step: string, args?: Record<string, unknown>): Promise<unknown>;
}

const ACCEPT = "application/json, text/event-stream";
const short = (v: unknown, keep = 10) => {
  const s = String(v ?? "");
  return s.length > keep * 2 + 3 ? `${s.slice(0, keep)}…${s.slice(-keep)}` : s;
};

async function rpc(endpoint: string, name: string, args: Record<string, unknown>): Promise<any> {
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "content-type": "application/json", accept: ACCEPT },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
  });
  const text = await res.text();
  const dataLine = text.split("\n").find((l) => l.startsWith("data:"));
  const body = JSON.parse(dataLine ? dataLine.slice(5) : text);
  if (body.error) throw new Error(JSON.stringify(body.error).slice(0, 200));
  const inner = body.result?.content?.[0]?.text;
  let payload: any = body.result;
  if (typeof inner === "string") {
    try {
      payload = JSON.parse(inner);
    } catch {
      payload = { error: inner.slice(0, 200) };
    }
  }
  if (body.result?.isError) {
    const err = new Error(typeof payload === "object" ? JSON.stringify(payload) : String(payload));
    (err as any).payload = payload;
    throw err;
  }
  return payload;
}

const TERMS = {
  reference: `visitor-${new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-")}`,
  purpose: "Negotiate a Q3 delivery schedule for component orders",
  channelLimits: { durationSeconds: "3600", messageKinds: ["question", "proposal", "evidence"], maxMessageBytes: "16384" },
  identityPolicy: { erc8004: "not_required", chainId: null, registryAddress: null },
};

export function runVisitorHost(endpoint: string, emit: DemoEmit): VisitorHost {
  let account: PrivateKeyAccount | undefined;
  let roleAccess: string | undefined;
  let sessionId: string | undefined;
  let termsDigest = "";
  let checklistDigest = "";

  const host: VisitorHost = {
    get sessionId() {
      return sessionId;
    },
    async action(step: string, args: Record<string, unknown> = {}) {
      if (step === "invite") {
        account = privateKeyToAccount(generatePrivateKey());
        const address = account.address.toLowerCase();
        termsDigest = standaloneCanonicalRecord(normalizeStandaloneTerms(TERMS)).digest;
        emit({ ts: Date.now(), pane: "initiator", kind: "info", label: "Agent A (hosted) generates an ephemeral keypair", detail: `address ${address}` });
        const authorityStatement = { accountableParty: "Acme Buying LLC", statement: "Acme Buying LLC authorizes its agent to negotiate the Q3 delivery schedule." };
        const signatureHex = await account.signMessage({
          message: { raw: canonicalBytes(standaloneAuthorityRecord({ sessionKeyAddress: address, authorityStatement })) },
        });
        emit({ ts: Date.now(), pane: "initiator", kind: "sign", label: "A signs its authority statement (local)", detail: short(signatureHex, 12) });
        const invite = await rpc(endpoint, "handshake_invite", {
          ...TERMS,
          readiness: {
            sessionKeyAddress: address,
            identity: null,
            authorityStatement,
            authoritySignatureHex: signatureHex,
            capabilityManifest: { dataHandlingClass: "confidential", purpose: TERMS.purpose },
          },
        });
        sessionId = invite.sessionId;
        roleAccess = invite.roleAccess;
        emit({ ts: Date.now(), pane: "initiator", kind: "action", label: "handshake_invite", detail: `session ${short(sessionId)} · invitation issued` });
        return { invitation: invite.invitation, sessionId, terms: TERMS, termsDigest };
      }

      if (!sessionId || !roleAccess || !account) throw new Error("no visitor session — invite first");

      if (step === "consent") {
        checklistDigest = String(args.checklistDigest ?? checklistDigest);
        const record = buildStandaloneConsentRecord({ sessionId, role: "initiator", termsDigest, checklistDigest });
        const signatureHex = await account.signMessage({ message: { raw: canonicalBytes(record) } });
        emit({ ts: Date.now(), pane: "initiator", kind: "sign", label: "A signs the consent record (local)", detail: `consentDigest ${short(standaloneCanonicalRecord(record).digest, 8)}` });
        const c = await rpc(endpoint, "consent_sign", { access: roleAccess, signatureHex });
        emit({ ts: Date.now(), pane: "initiator", kind: "action", label: "consent_sign (initiator)", detail: `stage ${c.stage}` });
        return c;
      }

      if (step === "open") {
        const open = await rpc(endpoint, "channel_open", { access: roleAccess });
        for (const a of open.anchors as { kind: string; digest: string; blockHeight: string }[]) {
          emit({ ts: Date.now(), pane: "ledger", kind: "anchor", label: `anchor · ${a.kind}`, detail: `block ${a.blockHeight} · ${short(a.digest, 8)}` });
        }
        return open;
      }

      if (step === "send") {
        const s = await rpc(endpoint, "channel_send", { access: roleAccess, kind: String(args.kind ?? "question"), body: String(args.body ?? "") });
        emit({ ts: Date.now(), pane: "initiator", kind: "message", label: `channel_send · ${args.kind}`, detail: `seq ${s.seq} — “${String(args.body).slice(0, 60)}”` });
        return s;
      }

      if (step === "read") {
        const r = await rpc(endpoint, "channel_read", { access: roleAccess });
        emit({ ts: Date.now(), pane: "initiator", kind: "info", label: "channel_read (A)", detail: `${(r.messages ?? []).length} message(s) addressed to initiator` });
        return r;
      }

      if (step === "revoke") {
        const revoked = await rpc(endpoint, "channel_revoke", { access: roleAccess });
        emit({ ts: Date.now(), pane: "initiator", kind: "action", label: "channel_revoke", detail: "initiator ends the channel" });
        const a = revoked.closureAnchor;
        emit({ ts: Date.now(), pane: "ledger", kind: "anchor", label: "anchor · closure", detail: `block ${a.blockHeight} · ${short(a.digest, 8)}` });
        return revoked;
      }

      throw new Error(`unknown host step ${step}`);
    },
  };
  return host;
}
