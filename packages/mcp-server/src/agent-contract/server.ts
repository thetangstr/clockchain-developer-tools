import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { z } from "zod";

import { limiter as keyedWindowLimiter } from "../standalone-handshake/public-server.js";
import { canonicalDigest, canonicalJson, containsAmountField, isCapBearingCall, saltedCanonicalDigest } from "./canonical.js";
import { toolsListForRole, CONTRACT_SERVER_INSTRUCTIONS } from "./tools-list.js";
import { contractToolDef, toolDefsForRole, NO_CONTRACT_FEATURES } from "./schemas.js";
import { contractStatusReadView } from "./business.js";
import { contractRefusalSchema, type ContractRefusalCode } from "./refusals.js";
import { newServerNonce, type ReceiptFields, type ServerReceipt } from "./receipts.js";
import type { ContractService, ContractPrincipal, ContractRun } from "./service.js";
import type { CertificateResolver } from "./certificate-resolver.js";
import { renderFinalAnchor, renderServerAnchor } from "./server-anchors.js";
import { TELEMETRY_OPEN_TOOL, type TelemetryLanes } from "./telemetry-lanes.js";

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

function refusal(
  code: ContractRefusalCode,
  serverNonce: string,
  transient?: { retryable: boolean; retryAfterMs?: number },
): CallOutcome {
  return {
    body: contractRefusalSchema.parse({
      error: code,
      retryable: transient?.retryable ?? false,
      ...(transient?.retryable === true && transient.retryAfterMs !== undefined ? { retryAfterMs: transient.retryAfterMs } : {}),
      serverNonce,
    }),
    isError: true,
  };
}

function sameCanonical(a: unknown, b: unknown): boolean {
  try {
    return canonicalJson(a) === canonicalJson(b);
  } catch {
    return false;
  }
}

function ok(body: Record<string, unknown>): CallOutcome {
  return { body, isError: false };
}

export function buildContractServer(options: {
  principal: ContractPrincipal;
  service: ContractService;
  /**
   * contract_bind by reference: resolves a handshake sessionId to its
   * closing certificate envelope (production: the handshake relay). Absent,
   * a bind by session id refuses CONTRACT_UNAVAILABLE.
   */
  resolveCertificate?: CertificateResolver;
  /**
   * O-1: enables the ADAPTER tool `telemetry_open` (absent from tools/list,
   * so guidanceDigests are unchanged). Absent, the name is NOT_FOUND.
   */
  telemetryLanes?: TelemetryLanes;
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
  /**
   * CDT-SEC M2: per-principal limit on `contract_register_policy`, checked
   * BEFORE the (pure-JS, ~150 ms) signature recovery. Shared across sessions
   * by the transport, like `pollGate`; absent → a per-server limiter.
   */
  registerGate?: (principalKeyId: string) => boolean;
  /** Default 6/min when no `registerGate` is injected. */
  registrationsPerMinute?: number;
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
  // M5: the env-gated surface (all off = b04059e). Older test doubles may
  // lack the field — absent means every feature off.
  const features = service.features ?? NO_CONTRACT_FEATURES;
  const serverAnchorsOn = service.serverAnchors === true;
  const POLL_TOOLS = new Set(["rendezvous_inbox", "contract_status"]);
  /**
   * Calls an agent makes BEFORE it binds its next run. When the keyId's
   * resolved run has ended, these are receipted on its pre-bind chain.
   */
  const PRE_BIND_TOOLS = new Set([
    "rendezvous_publish_listing", "rendezvous_search", "rendezvous_send_invitation", "rendezvous_inbox",
    "contract_bind_challenge", "contract_bind", "contract_status",
    // M5: a gated tool is pre-bind only while served — off, its name routes
    // exactly like any unknown name did at b04059e.
    ...(features.directory === true ? ["rendezvous_ack"] : []),
    ...(features.policyRegistration === true ? ["contract_register_policy"] : []),
    ...(features.briefs === true ? ["contract_get_brief"] : []),
    ...(options.telemetryLanes !== undefined ? [TELEMETRY_OPEN_TOOL] : []),
  ]);
  const allowPoll = options.pollGate
    ?? keyedWindowLimiter(options.pollsPerMinute ?? 60, 60_000, options.now ?? Date.now);
  const allowRegister = options.registerGate
    ?? keyedWindowLimiter(options.registrationsPerMinute ?? 6, 60_000, options.now ?? Date.now);
  const sessionFields = () => ({
    mcpSessionId: options.session?.id,
    clientInfo: options.session?.clientInfo,
    // The session ctx carries the per-REQUEST ip when live; fall back to the
    // fixed option for direct (non-transport) server construction.
    sourceIp: options.session?.sourceIp ?? options.sourceIp,
  });
  const visible = new Set(toolDefsForRole(principal.role, features).map((def) => def.name));

  const server = new Server(
    { name: "clockchain-agent-contract", version: "0.1.0" },
    { capabilities: { tools: {} }, instructions: CONTRACT_SERVER_INSTRUCTIONS },
  );

  // Verbatim role-scoped payload — this is what guidanceDigests digests.
  server.setRequestHandler(ListToolsRequestSchema, async () =>
    toolsListForRole(principal.role, features) as unknown as import("@modelcontextprotocol/sdk/types.js").ListToolsResult,
  );

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const name = request.params.name;
    const serverNonce = newServerNonce();
    const callArgs = request.params.arguments ?? {};
    // O-3: routed by (keyId, mcpSessionId) above CONTRACT_MAX_RUNS_PER_KEY=1.
    const runId = service.runIdForPrincipal(principal.keyId, options.session?.id);
    const run = runId === undefined ? undefined : service.runFor(runId);
    // Pre-bind routing (live p6-l-2026-10-03-1): runIdForPrincipal keeps
    // resolving an ENDED run (terminal, or released per #176/#179) until its
    // TTL so contract_status stays observable — but that run must not capture
    // the keyId's PRE-BIND calls for the next run. Those are receipted on the
    // keyId's pre-bind chain (fresh segment after the bind seal), whose head
    // the next run's bind receipt links. The ended run's chain is never
    // appended to by them. Business tools (reads, terminal replays,
    // ALREADY_TERMINAL refusals) keep using the run as before.
    const receiptTargetFor = (r: ContractRun | undefined): ContractRun | undefined =>
      r !== undefined && PRE_BIND_TOOLS.has(name) && service.runEnded(r) ? undefined : r;
    let receiptRun = receiptTargetFor(run);

    // M4: cap-bearing calls (mandate_*, any amount-like argument key) carry
    // HMAC-SHA256(scopeSalt, canonicalJson(args)) — the observer feed cannot
    // leak a mandate cap or price to a brute force. The salt is the run's
    // `runSalt`, or the principal's pre-bind salt when no run exists yet;
    // either is disclosed ONLY through the verifier-scoped endpoint.
    const argsScheme = isCapBearingCall(name, callArgs) ? "hmac-sha256" as const : "canonical" as const;
    const argsDigestFor = (target: ContractRun | undefined): string => argsScheme === "hmac-sha256"
      ? saltedCanonicalDigest(target?.runSalt ?? service.preBindSaltFor(principal.keyId, options.session?.id), callArgs)
      : canonicalDigest(callArgs);
    let argsDigest = argsDigestFor(receiptRun);

    // N4b-3 receipts-first: the receipt is built AND schema-validated BEFORE
    // any dispatch — if it can't be built (bad session evidence, exhausted
    // budget) the action never runs. The refusal carries a generic code +
    // the serverNonce; internals never reach the agent.
    const preflight = service.checkReceiptEvidence(receiptRun, principal, {
      tool: name,
      argsDigest,
      argsDigestScheme: argsScheme,
      serverNonce,
      ...sessionFields(),
    });
    if (!preflight.ok) {
      return asResult(refusal(preflight.code, serverNonce));
    }

    // O-1: the local adapter (never the model) opens this session's sealed
    // telemetry lane. Arguments must be exactly {} — a public key or any
    // other field is invalid params (the sink seals only to the key its
    // admin enrolled). The result is the laneId plus CIPHERTEXT; the call is
    // receipted like every other.
    if (name === TELEMETRY_OPEN_TOOL && options.telemetryLanes !== undefined) {
      if (!z.object({}).strict().safeParse(callArgs).success) {
        // Same evidence as a schema-invalid catalogued call (below).
        const invalidEvidence = {
          tool: name, argsDigest, argsDigestScheme: argsScheme, outcome: "INVALID_PARAMS",
          responseDigest: canonicalDigest({ error: "invalid_params" }), serverNonce, ...sessionFields(),
        };
        if (receiptRun === undefined) {
          service.recordPreBind(principal, invalidEvidence);
        } else if (service.canReceipt(receiptRun, principal.keyId)) {
          service.recordReceipt(receiptRun, { ...invalidEvidence, principal: { role: principal.role, keyId: principal.keyId } });
        }
        throw new McpError(ErrorCode.InvalidParams, "invalid tool arguments");
      }
      const opened = await options.telemetryLanes.open(principal, sessionFields().mcpSessionId);
      const opOutcome = opened.ok
        ? ok({ laneId: opened.laneId, role: opened.role, sealedBox: opened.sealedBox, serverNonce })
        : refusal(opened.code, serverNonce, opened.retryable ? { retryable: true } : undefined);
      // The run may have ended during the await — never append to it then.
      return asResult(recordAny(receiptTargetFor(receiptRun), name, argsDigest, opOutcome, serverNonce, argsScheme));
    }

    const def = contractToolDef(name, features);
    if (def === undefined) {
      return asResult(withReceipt(receiptRun, name, argsDigest, refusal("NOT_FOUND", serverNonce), serverNonce));
    }
    if (!visible.has(name)) {
      return asResult(withReceipt(receiptRun, name, argsDigest, refusal("ROLE_REFUSED", serverNonce), serverNonce));
    }

    const parsed = z.object(def.schema).strict().safeParse(request.params.arguments ?? {});
    if (!parsed.success) {
      // Schema-invalid calls are receipted where a principal is known — the
      // malformed call is evidence too — then fail as JSON-RPC -32602.
      if (receiptRun !== undefined && service.canReceipt(receiptRun, principal.keyId)) {
        service.recordReceipt(receiptRun, {
          tool: name,
          argsDigest,
          principal: { role: principal.role, keyId: principal.keyId },
          outcome: "INVALID_PARAMS",
          responseDigest: canonicalDigest({ error: "invalid_params" }),
          argsDigestScheme: argsScheme,
          serverNonce,
          ...sessionFields(),
        });
      } else if (receiptRun === undefined) {
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
      return asResult(recordAny(receiptRun, name, argsDigest, outcome, serverNonce, argsScheme));
    }

    if (name === "contract_register_policy") {
      // Mandates without a restart: verified against the CONTRACT_PRINCIPALS
      // pin, durable, single-use; receipted like any other call.
      // M2: the per-keyId limit runs before any signature work, and the
      // refusal is receipted like every other outcome.
      if (!allowRegister(principal.keyId)) {
        outcome = refusal("RATE_LIMITED", serverNonce, { retryable: true });
        return asResult(recordAny(receiptRun, name, argsDigest, outcome, serverNonce, argsScheme));
      }
      const registered = service.registerPolicy(
        principal,
        parsed.data as { role: "buyer"; digest: string; expiresAt: string; principalSig: string },
      );
      outcome = registered.ok ? ok({ ...registered.result, serverNonce }) : refusal(registered.code, serverNonce);
      return asResult(recordAny(receiptRun, name, argsDigest, outcome, serverNonce, argsScheme));
    }

    if (name === "contract_get_brief") {
      // Server-side anchors: a pinned brief; its digest's shared anchor
      // (CDT-SEC M4) is issued on first need and the bounded wait completes BEFORE the result
      // returns, so the receipt's responseDigest covers the anchor id.
      const served = await service.getBrief((parsed.data as { name: string }).name, {
        ...(receiptRun !== undefined ? { run: receiptRun } : {}),
        preBindScope: service.preBindBriefScope(principal.keyId, options.session?.id),
      });
      outcome = served.ok ? ok({ ...served.result, serverNonce }) : refusal(served.code, serverNonce);
      return asResult(recordAny(receiptRun, name, argsDigest, outcome, serverNonce, argsScheme));
    }

    if (name === "contract_bind") {
      // P-GAP: the caller proves it holds the bearer token pinned to a party's
      // agentId, but NOT that it possesses that party's handshake session key.
      // N4b-7 closes it behind CONTRACT_REQUIRE_BIND_STATEMENT=1: the DRAFT
      // bindStatement (challenge-bound, EIP-191 over its canonical digest)
      // must recover to the certificate party's sessionKeyAddress.
      //
      // By reference: `handshakeSessionId` makes the SERVER resolve the
      // closing certificate (a model never carries the signed object). The
      // resolved envelope then takes the exact certificate path below —
      // same verification, plus sessionId equality. A certificate presented
      // alongside must equal the resolved one canonically.
      const bindData = parsed.data as {
        handshakeSessionId?: string;
        certificate?: unknown;
        signerKey: unknown;
        approvalKey: unknown;
        listingId?: unknown;
        bindStatement?: unknown;
        bindStatementSignature?: unknown;
      };
      const { handshakeSessionId, ...bindRest } = bindData;
      const preRefuse = (code: ContractRefusalCode, transient?: { retryable: boolean; retryAfterMs?: number }) =>
        asResult(recordAny(receiptRun, name, argsDigest, refusal(code, serverNonce, transient), serverNonce, argsScheme));
      let certificate: unknown = bindRest.certificate;
      if (handshakeSessionId === undefined) {
        if (certificate === undefined) return preRefuse("PAYLOAD_INVALID");
      } else {
        if (options.resolveCertificate === undefined) return preRefuse("CONTRACT_UNAVAILABLE");
        let resolved: Awaited<ReturnType<CertificateResolver>>;
        try {
          resolved = await options.resolveCertificate(handshakeSessionId);
        } catch {
          resolved = { ok: false, code: "CONTRACT_UNAVAILABLE", retryable: true };
        }
        // PR #180 F2: the caller's live run may have ENDED during the await —
        // re-resolve the receipt target (and the salt-scoped argsDigest) so
        // a refusal never lands on a run that is now terminal.
        const retarget = receiptTargetFor(receiptRun);
        if (retarget !== receiptRun) {
          receiptRun = retarget;
          argsDigest = argsDigestFor(receiptRun);
        }
        if (!resolved.ok) {
          return preRefuse(resolved.code, { retryable: resolved.retryable, retryAfterMs: resolved.retryAfterMs });
        }
        if (certificate !== undefined && !sameCanonical(certificate, resolved.certificate)) {
          return preRefuse("CERTIFICATE_INVALID");
        }
        certificate = resolved.certificate;
      }
      const bound = service.bind(
        principal,
        {
          ...bindRest,
          certificate,
          ...(handshakeSessionId !== undefined ? { expectedSessionId: handshakeSessionId } : {}),
        },
        { argsDigest, serverNonce, tool: name, ...sessionFields() },
      );
      if (!bound.ok) {
        outcome = refusal(bound.code, serverNonce);
        // A refused bind never creates or alters run state — with no run
        // the refusal lands on the principal's pre-bind chain (M1).
        outcome = recordAny(receiptRun, name, argsDigest, outcome, serverNonce, argsScheme);
      } else {
        outcome = ok(bound.result);
      }
      return asResult(outcome);
    }

    // N4b-3: polling gets its own limiter — never the evidence cap. A poll
    // that exceeds it is refused RATE_LIMITED (still receipted — the refusal
    // is evidence too).
    if (POLL_TOOLS.has(name) && !allowPoll(principal.keyId)) {
      return asResult(recordAny(receiptRun, name, argsDigest, refusal("RATE_LIMITED", serverNonce), serverNonce, argsScheme));
    }

    if (name === "contract_status") {
      if (run === undefined) {
        // N4b-9 (F14): after a restart the in-memory run is gone but its
        // terminal job persisted — render the durable record (terminal
        // state, close delivery, anchor outcomes), not "rendezvous".
        // Server-side anchors: the final anchor is awaited (bounded) before
        // the terminal state is reported.
        if (runId !== undefined && service.terminalJobFor(runId)?.terminalState != null) {
          await service.awaitFinalAnchor(runId);
        }
        const job = runId !== undefined ? service.terminalJobFor(runId) : undefined;
        if (job !== undefined && job.terminalState !== null) {
          const anchorJobs = job.anchors === undefined
            ? []
            : [job.anchors.agreement, job.anchors.terminal].filter((a) => a !== undefined);
          outcome = ok({
            stage: job.terminalState === "settled" ? "settled" : "terminal",
            terminalState: job.terminalState,
            telemetryClose: job.close === undefined || job.receiptDigest === undefined
              ? null
              : {
                  status: job.close.status,
                  attempts: job.close.attempts,
                  lastError: job.close.lastError ?? null,
                  deliveredAt: job.close.deliveredAt ?? null,
                  receiptDigest: job.receiptDigest,
                },
            anchor: anchorJobs.length === 0 && !service.anchorConfigured ? "disabled"
              : anchorJobs.some((a) => a!.status === "failed") ? "failed"
              : anchorJobs.some((a) => a!.status === "anchoring" || a!.status === "pending") ? "pending"
              : "ok",
            anchors: job.anchors === undefined ? null : {
              agreement: job.anchors.agreement === undefined ? null : {
                status: job.anchors.agreement.status,
                digest: job.anchors.agreement.digest,
                anchorId: job.anchors.agreement.anchorId ?? null,
                eventHash: job.anchors.agreement.eventHash ?? null,
                ledger: job.anchors.agreement.ledger ?? null,
                error: job.anchors.agreement.error ?? null,
              },
              terminal: job.anchors.terminal === undefined ? null : {
                status: job.anchors.terminal.status,
                digest: job.anchors.terminal.digest,
                anchorId: job.anchors.terminal.anchorId ?? null,
                eventHash: job.anchors.terminal.eventHash ?? null,
                ledger: job.anchors.terminal.ledger ?? null,
                error: job.anchors.terminal.error ?? null,
              },
              // M5: reported only with CONTRACT_SERVER_ANCHORS=1.
              ...(serverAnchorsOn ? {
                terms: renderServerAnchor(job.anchors.terms),
                brief: renderServerAnchor(job.anchors.brief),
                final: renderFinalAnchor(job.anchors.final),
              } : {}),
            },
            // PR #180 F4: the recovered terminal run is the caller's PRIOR run.
            priorRun: true,
            canBind: true,
            serverNonce,
          });
          return asResult(recordAny(run, name, argsDigest, outcome, serverNonce, argsScheme));
        }
        // No run yet — the caller is still in discovery/handshake. The call
        // lands on the principal's pre-bind chain (M1).
        outcome = ok({ stage: "rendezvous", terminalState: null, telemetryClose: null, anchor: null, anchors: null, serverNonce });
        return asResult(recordAny(run, name, argsDigest, outcome, serverNonce, argsScheme));
      }
      // N4b-8 (gap 4): anchor visibility — "disabled" when no anchor is
      // configured, "failed" when any subject's anchor recorded a failure
      // (surfaced as `anchor: "failed"` per the brief), "pending" while a
      // delivery is in flight, "ok" once every fired anchor resolved.
      if (run.terminalState !== null) await service.awaitFinalAnchor(run.runId);
      const anchorStates = run.anchors;
      const anchorVals = anchorStates === undefined
        ? []
        : [anchorStates.agreement, anchorStates.terminal].filter((s) => s !== undefined);
      const anchorSummary =
        anchorStates === undefined && !service.anchorConfigured ? "disabled"
        : anchorVals.some((s) => s!.status === "failed") ? "failed"
        // N4b-9 (F13): "anchoring" AND "pending" (resolved write awaiting
        // block/time confirmation) both read as pending — "ok" only once
        // every fired anchor is confirmed anchored.
        : anchorVals.some((s) => s!.status === "anchoring" || s!.status === "pending") ? "pending"
        : "ok";
      outcome = ok({
        stage: run.stage,
        terminalState: run.terminalState,
        // N4b-10 (D13): settlement rail visibility — "simulated" by
        // default; awaitingStripeTestKey is the honest stop when the
        // Stripe rail is configured but unkeyed.
        settlement: {
          // D13 clarification: recorded paymentRail evidence first —
          // `simulated: true` is never the discriminator.
          paymentRail: run.settlement?.paymentRail
            ?? (run.settlementIntent !== undefined || run.awaitingStripeTestKey === true
              ? "stripe_test_mode" : service.settlementRailId),
          awaitingStripeTestKey: run.awaitingStripeTestKey === true,
          ...(run.settlementIntent !== undefined
            ? { paymentIntentId: run.settlementIntent.paymentIntentId, stripeStatus: run.settlementIntent.status }
            : {}),
        },
        // N4b-8 (gap 3): a permanently failed telemetry close is visible here.
        telemetryClose: run.telemetryClose === undefined ? null : {
          status: run.telemetryClose.status,
          attempts: run.telemetryClose.attempts,
          lastError: run.telemetryClose.lastError ?? null,
          deliveredAt: run.telemetryClose.deliveredAt ?? null,
          receiptDigest: run.telemetryClose.receiptDigest,
        },
        anchor: anchorSummary,
        anchors: anchorStates === undefined ? null : {
          agreement: anchorStates.agreement === undefined ? null : {
            status: anchorStates.agreement.status,
            digest: anchorStates.agreement.digest,
            anchorId: anchorStates.agreement.anchorId ?? null,
            eventHash: anchorStates.agreement.eventHash ?? null,
            ledger: anchorStates.agreement.ledger ?? null,
            error: anchorStates.agreement.error ?? null,
          },
          terminal: anchorStates.terminal === undefined ? null : {
            status: anchorStates.terminal.status,
            digest: anchorStates.terminal.digest,
            anchorId: anchorStates.terminal.anchorId ?? null,
            eventHash: anchorStates.terminal.eventHash ?? null,
            ledger: anchorStates.terminal.ledger ?? null,
            error: anchorStates.terminal.error ?? null,
          },
          // Server-side anchors — recorded here, never chained receipts.
          ...(serverAnchorsOn ? {
            terms: renderServerAnchor(anchorStates.terms),
            brief: renderServerAnchor(anchorStates.brief),
            final: renderFinalAnchor(anchorStates.final),
          } : {}),
        },
        // AGENT-TOOLS-BY-REFERENCE S1 + S2: read-only, caller-scoped views of
        // this run's offers (+ the one this caller may accept), agreement,
        // booking orderRef and cancellation. Amount fields make the receipt's
        // responseDigest salted (responseEvidence) — never brute-forceable
        // from the observer feed.
        ...contractStatusReadView(run, principal.role),
        // PR #180 F4: an ENDED run read pre-bind is the caller's PRIOR run —
        // its terminalState is not the next run's; the caller may bind now.
        ...(receiptRun === undefined ? { priorRun: true as const, canBind: true as const } : {}),
        serverNonce,
      });
      // An ended run's status is still READ above; the receipt goes to
      // the pre-bind chain (receiptRun undefined) — never appended to it.
      outcome = recordAny(receiptRun, name, argsDigest, outcome, serverNonce, argsScheme);
      return asResult(outcome);
    }

    // Every other catalogued tool is business semantics — mandate,
    // negotiation, booking, verification, settlement (business.ts).
    // N4b-10 (D13): settlement cases may return a Promise (the Stripe
    // TEST rail is async) — awaited here; every other tool stays sync.
    // N4b-11 (M3): a failed durable enqueue throws out of endRun — the
    // transition was never acknowledged. Surface it as a code-only,
    // RECEIPTED refusal instead of a bare JSON-RPC error carrying the
    // filesystem error (and its stateDir path) verbatim.
    let dispatched: Awaited<ReturnType<typeof service.business.dispatch>>;
    try {
      // PR #180 F1: dispatch with the receipt target — for a pre-bind tool
      // whose run ENDED that is no run, so a `*` sender's invitation is
      // stamped unproven-pre-bind, never the released binding's agentId.
      dispatched = await service.business.dispatch(
        principal, receiptRun, name, parsed.data, serverNonce,
      );
    } catch {
      dispatched = { ok: false as const, code: "CONTRACT_UNAVAILABLE" as const };
    }
    // O-2: an inbox long-poll may hold for up to 25 s — like PR #180 F2,
    // re-resolve the receipt target so a run that ENDED meanwhile is never
    // appended to (the receipt lands on the pre-bind chain instead).
    if (name === "rendezvous_inbox") {
      const retarget = receiptTargetFor(receiptRun);
      if (retarget !== receiptRun) {
        receiptRun = retarget;
        argsDigest = argsDigestFor(receiptRun);
      }
    }
    outcome = dispatched.ok ? ok(dispatched.result) : refusal(dispatched.code, serverNonce);
    // D8: the dispatch may carry extra server-derived receipt fields (e.g.
    // an invitation's senderProof disclosure).
    return asResult(recordAny(receiptRun, name, argsDigest, outcome, serverNonce, argsScheme,
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
    const salt = run === undefined ? service.preBindSaltFor(principal.keyId, options.session?.id) : run.runSalt;
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
