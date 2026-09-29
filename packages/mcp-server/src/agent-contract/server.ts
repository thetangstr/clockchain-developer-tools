import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { z } from "zod";

import { limiter as keyedWindowLimiter } from "../standalone-handshake/public-server.js";
import { canonicalDigest, containsAmountField, isCapBearingCall, saltedCanonicalDigest } from "./canonical.js";
import { toolsListForRole, CONTRACT_SERVER_INSTRUCTIONS } from "./tools-list.js";
import { contractToolDef, toolDefsForRole } from "./schemas.js";
import { contractRefusalSchema, type ContractRefusalCode } from "./refusals.js";
import { newServerNonce, type ReceiptFields, type ServerReceipt } from "./receipts.js";
import type { ContractService, ContractPrincipal, ContractRun } from "./service.js";

/**
 * The `/contract/mcp` MCP server: `contract_bind`/`contract_status` are
 * service-owned; every other catalogued tool dispatches through
 * `service.business`.
 *
 * Built on the low-level `Server`, NOT `McpServer.registerTool`: the
 * `tools/list` result must be the verbatim `toolsListForRole(role)` payload
 * so its canonical digest equals the published `guidanceDigests` (R10), and
 * the SDK's own zod→JSON-Schema rendering would drift from it.
 *
 * The server is constructed per request with the caller's authenticated
 * principal, so `tools/list` is role-scoped by construction.
 *
 * Evidence rules (N4b-2b): every refusal body carries the per-call
 * `serverNonce`; every call that can be tied to a run — INCLUDING refusals —
 * is receipted; and the receipt slot is RESERVED before dispatch so a
 * consequential action can never execute unevidenced.
 */

interface CallOutcome {
  readonly body: Record<string, unknown>;
  readonly isError: boolean;
}

function refusal(code: ContractRefusalCode, serverNonce: string): CallOutcome {
  return {
    body: contractRefusalSchema.parse({ error: code, retryable: false, serverNonce }),
    isError: true,
  };
}

function ok(body: Record<string, unknown>): CallOutcome {
  return { body, isError: false };
}

export function buildContractServer(options: {
  principal: ContractPrincipal;
  service: ContractService;
  sourceIp?: string;
  /**
   * N4b-3: polling tools (`rendezvous_inbox`, `contract_status`) get their
   * own per-principal rate limit — the evidence cap is never the reason a
   * poll is refused (default 60/min; injectable for tests).
   */
  pollsPerMinute?: number;
  /**
   * N4b-4: the poll limiter must be per PRINCIPAL, not per session — a fresh
   * `initialize` must not reset it. The transport injects one shared gate
   * (`(keyId) => allowed`); absent it, a per-server limiter is used (direct
   * in-process construction ≈ one session anyway).
   */
  pollGate?: (principalKeyId: string) => boolean;
  now?: () => number;
  /**
   * Live MCP session evidence (M2): `id` is filled on
   * `onsessioninitialized`, `clientInfo` from `initialize`. Every receipt
   * carries them as EVIDENCE (LLD §9 R9), never proof.
   */
  session?: {
    id?: string;
    clientInfo?: { name: string; version: string };
    /** Per-request peer IP — the handler refreshes it before every call. */
    sourceIp?: string;
  };
}): Server {
  const { principal, service } = options;
  const POLL_TOOLS = new Set(["rendezvous_inbox", "contract_status"]);
  const allowPoll = options.pollGate
    ?? keyedWindowLimiter(options.pollsPerMinute ?? 60, 60_000, options.now ?? Date.now);
  const sessionFields = () => ({
    mcpSessionId: options.session?.id,
    clientInfo: options.session?.clientInfo,
    // The session ctx carries the per-REQUEST ip when live; fall back to the
    // fixed option for direct (non-transport) server construction.
    sourceIp: options.session?.sourceIp ?? options.sourceIp,
  });
  const visible = new Set(toolDefsForRole(principal.role).map((def) => def.name));

  const server = new Server(
    { name: "clockchain-agent-contract", version: "0.1.0" },
    { capabilities: { tools: {} }, instructions: CONTRACT_SERVER_INSTRUCTIONS },
  );

  // Verbatim role-scoped payload — this is what guidanceDigests digests.
  server.setRequestHandler(ListToolsRequestSchema, async () =>
    toolsListForRole(principal.role) as unknown as import("@modelcontextprotocol/sdk/types.js").ListToolsResult,
  );

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const name = request.params.name;
    const serverNonce = newServerNonce();
    const callArgs = request.params.arguments ?? {};
    const runId = service.runIdForPrincipal(principal.keyId);
    const run = runId === undefined ? undefined : service.runFor(runId);

    // M4: cap-bearing calls (mandate_*, any amount-like argument key) carry
    // HMAC-SHA256(scopeSalt, canonicalJson(args)) — the observer feed cannot
    // leak a mandate cap or price to a brute force. The salt is the run's
    // `runSalt`, or the principal's pre-bind salt when no run exists yet;
    // either is disclosed ONLY through the verifier-scoped endpoint.
    const argsScheme = isCapBearingCall(name, callArgs) ? "hmac-sha256" as const : "canonical" as const;
    const argsDigest = argsScheme === "hmac-sha256"
      ? saltedCanonicalDigest(run?.runSalt ?? service.preBindSaltFor(principal.keyId), callArgs)
      : canonicalDigest(callArgs);

    // N4b-3 receipts-first: the receipt is built AND schema-validated BEFORE
    // any dispatch — if it can't be built (bad session evidence, exhausted
    // budget) the action never runs. The refusal carries a generic code +
    // the serverNonce; internals never reach the agent.
    const preflight = service.checkReceiptEvidence(run, principal, {
      tool: name,
      argsDigest,
      argsDigestScheme: argsScheme,
      serverNonce,
      ...sessionFields(),
    });
    if (!preflight.ok) {
      return asResult(refusal(preflight.code, serverNonce));
    }

    const def = contractToolDef(name);
    if (def === undefined) {
      return asResult(withReceipt(run, name, argsDigest, refusal("NOT_FOUND", serverNonce), serverNonce));
    }
    if (!visible.has(name)) {
      return asResult(withReceipt(run, name, argsDigest, refusal("ROLE_REFUSED", serverNonce), serverNonce));
    }

    const parsed = z.object(def.schema).strict().safeParse(request.params.arguments ?? {});
    if (!parsed.success) {
      // Schema-invalid calls are receipted where a principal is known — the
      // malformed call is evidence too — then fail as JSON-RPC -32602.
      if (run !== undefined && service.canReceipt(run, principal.keyId)) {
        service.recordReceipt(run, {
          tool: name,
          argsDigest,
          principal: { role: principal.role, keyId: principal.keyId },
          outcome: "INVALID_PARAMS",
          responseDigest: canonicalDigest({ error: "invalid_params" }),
          argsDigestScheme: argsScheme,
          serverNonce,
          ...sessionFields(),
        });
      } else if (run === undefined) {
        service.recordPreBind(principal, {
          tool: name,
          argsDigest,
          argsDigestScheme: argsScheme,
          outcome: "INVALID_PARAMS",
          responseDigest: canonicalDigest({ error: "invalid_params" }),
          serverNonce,
          ...sessionFields(),
        });
      }
      throw new McpError(ErrorCode.InvalidParams, "invalid tool arguments");
    }

    let outcome: CallOutcome;

    if (name === "contract_bind_challenge") {
      // N4b-7 (P-GAP): a caller takes a single-use nonce into its DRAFT bind
      // statement. The call lands on the pre-bind chain like any other
      // pre-run evidence.
      const issued = service.issueBindChallenge(principal);
      outcome = issued.ok
        ? ok({ challenge: issued.challenge, expiresAt: issued.expiresAt, serverNonce })
        : refusal(issued.code, serverNonce);
      return asResult(recordAny(run, name, argsDigest, outcome, serverNonce, argsScheme));
    }

    if (name === "contract_bind") {
      // P-GAP: the caller proves it holds the bearer token pinned to a party's
      // agentId, but NOT that it possesses that party's handshake session key.
      // N4b-7 closes it behind CONTRACT_REQUIRE_BIND_STATEMENT=1: the DRAFT
      // bindStatement (challenge-bound, EIP-191 over its canonical digest)
      // must recover to the certificate party's sessionKeyAddress.
      const bound = service.bind(
        principal,
        parsed.data as {
          certificate: unknown;
          signerKey: unknown;
          approvalKey: unknown;
          listingId?: unknown;
          bindStatement?: unknown;
          bindStatementSignature?: unknown;
        },
        { argsDigest, serverNonce, tool: name, ...sessionFields() },
      );
      if (!bound.ok) {
        outcome = refusal(bound.code, serverNonce);
        // A refused bind never creates or alters run state — with no run
        // the refusal lands on the principal's pre-bind chain (M1).
        outcome = recordAny(run, name, argsDigest, outcome, serverNonce, argsScheme);
      } else {
        outcome = ok(bound.result);
      }
      return asResult(outcome);
    }

    // N4b-3: polling gets its own limiter — never the evidence cap. A poll
    // that exceeds it is refused RATE_LIMITED (still receipted — the refusal
    // is evidence too).
    if (POLL_TOOLS.has(name) && !allowPoll(principal.keyId)) {
      return asResult(recordAny(run, name, argsDigest, refusal("RATE_LIMITED", serverNonce), serverNonce, argsScheme));
    }

    if (name === "contract_status") {
      if (run === undefined) {
        // No run yet — the caller is still in discovery/handshake. The call
        // lands on the principal's pre-bind chain (M1).
        outcome = ok({ stage: "rendezvous", terminalState: null, telemetryClose: null, serverNonce });
        return asResult(recordAny(run, name, argsDigest, outcome, serverNonce, argsScheme));
      }
      outcome = ok({
        stage: run.stage,
        terminalState: run.terminalState,
        // N4b-8 (gap 3): a permanently failed telemetry close is visible here.
        telemetryClose: run.telemetryClose === undefined ? null : {
          status: run.telemetryClose.status,
          attempts: run.telemetryClose.attempts,
          lastError: run.telemetryClose.lastError ?? null,
          deliveredAt: run.telemetryClose.deliveredAt ?? null,
          receiptDigest: run.telemetryClose.receiptDigest,
        },
        serverNonce,
      });
      outcome = recordCall(run, name, argsDigest, outcome, serverNonce, argsScheme);
      return asResult(outcome);
    }

    // Every other catalogued tool is business semantics — mandate,
    // negotiation, booking, verification, settlement (business.ts).
    const dispatched = service.business.dispatch(
      principal, run, name, parsed.data, serverNonce,
    );
    outcome = dispatched.ok ? ok(dispatched.result) : refusal(dispatched.code, serverNonce);
    // D8: the dispatch may carry extra server-derived receipt fields (e.g.
    // an invitation's senderProof disclosure).
    return asResult(recordAny(run, name, argsDigest, outcome, serverNonce, argsScheme,
      dispatched.ok ? dispatched.receiptFields : undefined));
  });

  function withReceipt(run: ContractRun | undefined, tool: string, argsDigest: string, outcome: CallOutcome, serverNonce: string, scheme?: "canonical" | "hmac-sha256"): CallOutcome {
    return recordAny(run, tool, argsDigest, outcome, serverNonce, scheme);
  }

  /**
   * Receipt the call on the run chain when a run exists for this principal,
   * else on the principal's PRE-BIND chain (M1 — rendezvous, pre-bind status
   * and refused binds are still evidence).
   */
  function recordAny(
    run: ContractRun | undefined, tool: string, argsDigest: string, outcome: CallOutcome,
    serverNonce: string, scheme: "canonical" | "hmac-sha256" = "canonical",
    extra?: Pick<ReceiptFields, "senderProof">,
  ): CallOutcome {
    return run === undefined
      ? recordPreBindCall(tool, argsDigest, outcome, serverNonce, scheme, extra)
      : recordCall(run, tool, argsDigest, outcome, serverNonce, scheme, extra);
  }

  /**
   * N4b-3: a response carrying an amount (`*Minor`, price/fare/total…) gets a
   * salted `responseDigest` under the SAME scope salt as a cap-bearing
   * argsDigest — the observer feed can't brute-force agreed money values;
   * the verifier endpoint discloses the salt.
   */
  function responseEvidence(run: ContractRun | undefined, body: Record<string, unknown>) {
    const responseDigestScheme = containsAmountField(body) ? "hmac-sha256" as const : "canonical" as const;
    const salt = run === undefined ? service.preBindSaltFor(principal.keyId) : run.runSalt;
    return {
      responseDigestScheme,
      responseDigest: responseDigestScheme === "hmac-sha256"
        ? saltedCanonicalDigest(salt, body)
        : canonicalDigest(body),
    };
  }

  // M1/N4b-3: pre-bind receipt — appends to the principal's ACTIVE segment;
  // segments roll by count so capacity never refuses a call, and a build
  // failure is a refusal (unreachable after the pre-dispatch gate).
  function recordPreBindCall(
    tool: string, argsDigest: string, outcome: CallOutcome, serverNonce: string,
    scheme: "canonical" | "hmac-sha256" = "canonical",
    extra?: Pick<ReceiptFields, "senderProof">,
  ): CallOutcome {
    const recorded = service.recordPreBind(principal, {
      tool,
      argsDigest,
      argsDigestScheme: scheme,
      outcome: outcome.isError ? String((outcome.body as { error?: string }).error) : "ok",
      ...responseEvidence(undefined, outcome.body),
      ...extra,
      serverNonce,
      ...sessionFields(),
    });
    return recorded.ok ? outcome : refusal(recorded.code, serverNonce);
  }

  // N3: receipt recording can REFUSE at the per-principal budget — the call's
  // outcome then becomes the RATE_LIMITED refusal (nothing is appended), so
  // one principal can never fill the chain to brick the other.
  function recordCall(
    run: ContractRun, tool: string, argsDigest: string, outcome: CallOutcome,
    serverNonce: string, scheme: "canonical" | "hmac-sha256" = "canonical",
    extra?: Pick<ReceiptFields, "senderProof">,
  ): CallOutcome {
    const recorded = service.recordReceipt(run, {
      tool,
      argsDigest,
      argsDigestScheme: scheme,
      principal: { role: principal.role, keyId: principal.keyId },
      outcome: outcome.isError ? String((outcome.body as { error?: string }).error) : "ok",
      ...responseEvidence(run, outcome.body),
      ...extra,
      serverNonce,
      ...sessionFields(),
    });
    return recorded.ok ? outcome : refusal(recorded.code, serverNonce);
  }

  return server;
}

function asResult(outcome: CallOutcome) {
  const response: Record<string, unknown> = {
    content: [{ type: "text", text: JSON.stringify(outcome.body) }],
    structuredContent: outcome.body,
  };
  if (outcome.isError) response.isError = true;
  return response;
}
