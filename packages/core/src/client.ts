import type { ClockchainConfig } from "./config.js";
import { DEFAULT_ENDPOINT } from "./config.js";
import {
  ApiError,
  AuthError,
  InsufficientCreditsError,
  RateLimitError,
} from "./errors.js";
import type {
  AgentReceipt,
  AttestActionInput,
  BlockResponse,
  LedgerRecord,
  LogEntry,
  LogResponse,
  ReceiptVerification,
  TimeResponse,
  TimestampResponse,
  ValidationBlock,
} from "./types.js";
import { buildReceipt, eventHashOf } from "./receipt.js";
import { resolveAgent } from "./erc8004.js";

/** Standard {success, data, meta} envelope used by some endpoints. */
interface SuccessEnvelope<T> {
  success: boolean;
  data: T;
  meta?: unknown;
}

/** Error envelope sometimes returned by /ledger/{id}. */
interface ErrorEnvelope {
  success: false;
  error?: { message?: string; [key: string]: unknown };
}

type RequestMethod = "GET" | "POST";

interface RequestOptions {
  method?: RequestMethod;
  body?: unknown;
}

/**
 * Typed client for the Clockchain gateway.
 *
 * The gateway's response envelopes are inconsistent, so each public method
 * unwraps its own shape. Errors are mapped to typed errors and never retried
 * here — the caller decides retry/backoff policy.
 */
export class ClockchainClient {
  private readonly config: ClockchainConfig;
  private readonly baseUrl: string;

  constructor(config: ClockchainConfig) {
    this.config = config;
    this.baseUrl = (config.endpoint || DEFAULT_ENDPOINT).replace(/\/+$/, "");
  }

  /**
   * Latest consented block time + height, derived from {@link getTimestamp}
   * (the public /getTime endpoint).
   */
  async getTime(): Promise<TimeResponse> {
    const ts = await this.getTimestamp();
    return {
      latestBlockTime: ts.madMarzulloTime,
      latestBlockHeight: ts.blockHeight,
    };
  }

  /**
   * GET /getTime -> {success, data, meta}; returns data.
   *
   * Public consensus-time endpoint — no api-key scope required. Supersedes the
   * scope-gated /api/time/time + /api/time/timestamp, which 401 ("Invalid or
   * expired API key") for logging-scope keys. The data shape matches
   * {@link TimestampResponse} exactly (blockHeight, madMarzulloTime, totalNodes,
   * nodeParticipation%, votes, …).
   */
  async getTimestamp(): Promise<TimestampResponse> {
    const env = await this.request<SuccessEnvelope<TimestampResponse>>("/getTime");
    return env.data;
  }

  /**
   * GET /api/time/block?height=N -> {success, data, meta}; returns data.
   * `"latest"` resolves the latest height via {@link getTime} first.
   */
  async getBlock(height: string | number | "latest"): Promise<BlockResponse> {
    let h = height;
    if (h === "latest") {
      const time = await this.getTime();
      h = time.latestBlockHeight;
    }
    const env = await this.request<SuccessEnvelope<BlockResponse>>(
      `/api/time/block?height=${encodeURIComponent(String(h))}`,
    );
    return env.data;
  }

  /**
   * GET /getValidationBlock/{h} -> {validationBlockData}; returns
   * validationBlockData. This endpoint has NO {success,data} envelope.
   */
  async getValidationBlock(height: string | number): Promise<ValidationBlock> {
    const res = await this.request<{ validationBlockData: ValidationBlock }>(
      `/getValidationBlock/${encodeURIComponent(String(height))}`,
    );
    return res.validationBlockData;
  }

  /**
   * POST /log. Fills clientId/walletId from config and applies defaults:
   * hashType "SHA-256", versionNumber 1, additionalInfo "".
   *
   * CRITICAL: hashType MUST be hyphenated ("SHA-256"); "SHA256" is rejected
   * with HTTP 400. `blockHeight` is null on create (pending) until the leader
   * writes the block ~0.6s later.
   */
  async log(
    entry: Partial<LogEntry> & { assetHash: string; assetReferenceId: string },
  ): Promise<LogResponse> {
    const body: LogEntry = {
      clientId: entry.clientId ?? this.config.clientId,
      walletId: entry.walletId ?? this.config.walletId,
      assetReferenceId: entry.assetReferenceId,
      assetHash: entry.assetHash,
      hashType: entry.hashType ?? "SHA-256",
      versionNumber: entry.versionNumber ?? 1,
      // Plain text only — the gateway strips punctuation/JSON server-side.
      additionalInfo: entry.additionalInfo ?? "",
    };
    return this.request<LogResponse>("/log", { method: "POST", body });
  }

  /**
   * GET /searchAsset?clientId=...&assetReferenceId=... -> bare JSON array.
   * EXACT-match only on assetReferenceId (no prefix search).
   */
  async searchAsset(assetReferenceId: string): Promise<LedgerRecord[]> {
    const params = new URLSearchParams({
      clientId: this.config.clientId,
      assetReferenceId,
    });
    return this.request<LedgerRecord[]>(`/searchAsset?${params.toString()}`);
  }

  /**
   * GET /ledger/{ledgerId} -> ledger record object. On error the gateway
   * returns {success:false, error:{...}}, which is mapped to an ApiError.
   */
  async getLedgerEntry(ledgerId: string): Promise<LedgerRecord> {
    const res = await this.request<LedgerRecord | ErrorEnvelope>(
      `/ledger/${encodeURIComponent(ledgerId)}`,
    );
    if (this.isErrorEnvelope(res)) {
      throw new ApiError(
        res.error?.message ?? "Ledger lookup failed",
        404,
        res,
      );
    }
    return res;
  }

  /**
   * Poll {@link getLedgerEntry} every ~500ms until blockHeight is populated
   * (no longer null), or until timeoutMs elapses.
   */
  async waitForConfirmation(
    ledgerId: string,
    timeoutMs = 15000,
  ): Promise<LedgerRecord> {
    const deadline = Date.now() + timeoutMs;
    let last: LedgerRecord | undefined;
    while (Date.now() < deadline) {
      last = await this.getLedgerEntry(ledgerId);
      if (last.blockHeight != null) {
        return last;
      }
      await this.delay(500);
    }
    if (last) return last;
    return this.getLedgerEntry(ledgerId);
  }

  /**
   * Attest an autonomous agent action and return an {@link AgentReceipt}.
   *
   * One call abstracts the whole flow: fingerprint the action (SHA-256 of the
   * canonical inputs/outputs), anchor it on-chain via {@link log}, wait for
   * confirmation, and gather the consensus time + validation + (optional)
   * ERC-8004 identity into a self-verifying receipt. Crypto/RPC/Web3 stay hidden.
   */
  async attestAction(input: AttestActionInput): Promise<AgentReceipt> {
    const eventHash = eventHashOf(input);
    const assetReferenceId = `${input.agentId}:${input.action}:${Date.now()}`;
    const wait = input.wait ?? true;

    let log = await this.log({
      assetHash: eventHash,
      assetReferenceId,
      additionalInfo: "agent attested receipt",
    });
    if (wait) {
      log = await this.waitForConfirmation(log.ledgerId, input.waitMs ?? 15000);
    }

    // Best-effort enrichment - none of these should fail the attestation.
    let block: BlockResponse | null = null;
    let validation: ValidationBlock | null = null;
    if (log.blockHeight != null) {
      block = await this.getBlock(log.blockHeight).catch(() => null);
      validation = await this.getValidationBlock(log.blockHeight).catch(() => null);
    }
    let identity: { resolved: boolean; status: string } | null = null;
    if (this.config.evmRpcUrl && this.config.erc8004RegistryAddress) {
      const id = await resolveAgent(this.config, input.agentId).catch(() => null);
      if (id) identity = { resolved: id.status !== "unknown", status: id.status };
    }

    // Single-validator today; this stays "testnet" until the network is mainnet.
    const network = "testnet";
    return buildReceipt({ input, eventHash, network, log, block, validation, identity });
  }

  /**
   * Independently re-verify a receipt: recompute the event hash from the receipt's
   * own payload and confirm it matches what is anchored on-chain at its ledgerId.
   */
  async verifyReceipt(receipt: AgentReceipt): Promise<ReceiptVerification> {
    const record = await this.getLedgerEntry(receipt.anchor.ledgerId);
    const recomputed = eventHashOf({
      agentId: receipt.agentId,
      action: receipt.action,
      inputs: receipt.payload.inputs,
      outputs: receipt.payload.outputs,
    });
    return {
      match: recomputed === record.assetHash && recomputed === receipt.eventHash,
      eventHash: recomputed,
      anchoredHash: record.assetHash,
      blockHeight: record.blockHeight,
      ledgerId: record.ledgerId,
    };
  }

  // --- internals ---

  private isErrorEnvelope(value: unknown): value is ErrorEnvelope {
    return (
      typeof value === "object" &&
      value !== null &&
      "success" in value &&
      (value as { success: unknown }).success === false
    );
  }

  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Single HTTP entry point: sets the x-api-key header, parses JSON, and maps
   * known failure shapes to typed errors. Uses Node 18+ built-in fetch.
   */
  private async request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      "x-api-key": this.config.apiKey,
      accept: "application/json",
    };
    if (opts.body !== undefined) {
      headers["content-type"] = "application/json";
    }

    const res = await fetch(url, {
      method: opts.method ?? "GET",
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });

    const raw = await res.text();
    let parsed: unknown = undefined;
    if (raw.length > 0) {
      try {
        parsed = JSON.parse(raw);
      } catch {
        parsed = raw;
      }
    }

    // Map known error conditions whether the gateway used HTTP status or a body
    // marker (it is inconsistent about both).
    const textForMatch =
      typeof parsed === "string" ? parsed : JSON.stringify(parsed ?? "");

    if (res.status === 429 || /rate limit exceeded/i.test(textForMatch)) {
      throw new RateLimitError("Rate limit exceeded", res.status, parsed);
    }
    if (/no enough tokens to facilitate this logging/i.test(textForMatch)) {
      throw new InsufficientCreditsError(
        "No enough tokens to facilitate this logging",
        res.status,
        parsed,
      );
    }
    if (res.status === 401) {
      throw new AuthError("Authentication failed (check x-api-key)", 401, parsed);
    }

    if (!res.ok) {
      throw new ApiError(
        `Clockchain request failed: ${res.status} ${res.statusText}`,
        res.status,
        parsed,
      );
    }

    return parsed as T;
  }
}
