import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { z } from "zod";

import { canonicalDigest } from "./canonical.js";
import { toolsListForRole, CONTRACT_SERVER_INSTRUCTIONS } from "./tools-list.js";
import { contractToolDef, toolDefsForRole } from "./schemas.js";
import { contractRefusalSchema, type ContractRefusalCode } from "./refusals.js";
import { newServerNonce, type ServerReceipt } from "./receipts.js";
import type { ContractService, ContractPrincipal, ContractRun } from "./service.js";

/**
 * The `/contract/mcp` MCP server (this slice: `contract_bind` +
 * `contract_status` live; every other catalogued tool answers
 * CONTRACT_UNAVAILABLE until its N4b slice lands).
 *
 * Built on the low-level `Server`, NOT `McpServer.registerTool`: the
 * `tools/list` result must be the verbatim `toolsListForRole(role)` payload
 * so its canonical digest equals the published `guidanceDigests` (R10), and
 * the SDK's own zod→JSON-Schema rendering would drift from it.
 *
 * The server is constructed per request with the caller's authenticated
 * principal, so `tools/list` is role-scoped by construction.
 */

interface CallOutcome {
  readonly body: Record<string, unknown>;
  readonly isError: boolean;
}

function refusal(code: ContractRefusalCode): CallOutcome {
  return {
    body: contractRefusalSchema.parse({ error: code, retryable: false }),
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
}): Server {
  const { principal, service } = options;
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
    const def = contractToolDef(name);
    if (def === undefined) return asResult(refusal("NOT_FOUND"));
    if (!visible.has(name)) return asResult(refusal("ROLE_REFUSED"));

    const parsed = z.object(def.schema).strict().safeParse(request.params.arguments ?? {});
    if (!parsed.success) {
      throw new McpError(ErrorCode.InvalidParams, "invalid tool arguments");
    }

    const serverNonce = newServerNonce();
    const argsDigest = canonicalDigest(request.params.arguments ?? {});
    const runId = service.runIdForPrincipal(principal.keyId);
    const run = runId === undefined ? undefined : service.runFor(runId);

    let outcome: CallOutcome;

    if (name === "contract_bind") {
      const bound = service.bind(
        principal,
        parsed.data as { certificate: unknown; signerKey: unknown; approvalKey: unknown },
        { argsDigest, sourceIp: options.sourceIp },
      );
      if (!bound.ok) {
        outcome = refusal(bound.code);
      } else {
        outcome = ok({
          runId: bound.runId,
          role: bound.role,
          bound: true,
          boundAt: bound.boundAt,
          serverNonce,
        });
      }
      // The bind call's own receipt lands on the run it created/joined.
      const target = bound.ok ? bound.run : run;
      if (target !== undefined) recordCall(target, name, argsDigest, outcome, serverNonce);
      return asResult(outcome);
    }

    if (name === "contract_status") {
      if (run === undefined) {
        // No run yet — the caller is still in discovery/handshake. No chain
        // exists to receipt against; the nonce is still echoed for the trace.
        return asResult(ok({ stage: "rendezvous", terminalState: null, serverNonce }));
      }
      outcome = ok({ stage: run.stage, terminalState: null, serverNonce });
      recordCall(run, name, argsDigest, outcome, serverNonce);
      return asResult(outcome);
    }

    // Catalogue tool not implemented in this slice.
    outcome = refusal("CONTRACT_UNAVAILABLE");
    if (run !== undefined) recordCall(run, name, argsDigest, outcome, serverNonce);
    return asResult(outcome);
  });

  function recordCall(run: ContractRun, tool: string, argsDigest: string, outcome: CallOutcome, serverNonce: string): ServerReceipt {
    return service.recordReceipt(run, {
      tool,
      argsDigest,
      principal: { role: principal.role, keyId: principal.keyId },
      outcome: outcome.isError ? String((outcome.body as { error?: string }).error) : "ok",
      responseDigest: canonicalDigest(outcome.body),
      serverNonce,
      sourceIp: options.sourceIp,
    });
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
