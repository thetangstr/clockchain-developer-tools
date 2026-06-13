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
  AuditEvent,
  AuditTrail,
  BlockResponse,
  ChainRecord,
  ComplianceFormat,
  ComplianceReport,
  ContractEstimate,
  ContractParams,
  EvidencePackage,
  IdentityEvent,
  IdentityHistory,
  IdentityVerification,
  IdentityWrite,
  LedgerRecord,
  LogEntry,
  LogResponse,
  OnChainVerification,
  PackageVerification,
  ReceiptVerification,
  ScheduleApproval,
  ScheduledContract,
  TimeResponse,
  TimestampResponse,
  ValidationBlock,
} from "./types.js";
import { buildReceipt, eventHashOf } from "./receipt.js";
import { canonicalize } from "./receipt.js";
import { computeHash } from "./hash.js";
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

/** Shared honesty note shipped with every audit trail / report / pack. */
const AUDIT_HONESTY_NOTE =
  "Testnet. Designed-for court-grade evidence, not court-tested or certified. " +
  "Single-validator testnet: consensus/trust numbers are currently 0. Identity " +
  "binding may be a stub (own-client hash-anchor) until the public resolver lands.";

/**
 * Compliance format presets. Each is a PARAMETER-driven renderer over the same
 * assembled trail — adding a regulator is adding a preset here, never a new tool.
 */
const COMPLIANCE_PRESETS: Record<
  ComplianceFormat,
  (trail: AuditTrail) => Record<string, unknown>
> = {
  eu_ai_act_art12: (trail) => ({
    standard: "EU AI Act Article 12 (record-keeping)",
    assetReferenceId: trail.assetReferenceId,
    recordCount: trail.count,
    automaticallyGeneratedLogs: trail.events.map((e) => ({
      ledgerId: e.ledgerId,
      timestamp: e.time,
      referenceSituation: e.assetReferenceId,
      contentHash: e.assetHash,
    })),
    generatedAt: trail.builtAt,
  }),
  sec_17a4: (trail) => ({
    standard: "SEC Rule 17a-4 (WORM record retention)",
    assetReferenceId: trail.assetReferenceId,
    recordCount: trail.count,
    records: trail.events.map((e) => ({
      ledgerId: e.ledgerId,
      dateTime: e.time,
      recordHash: e.assetHash,
      reference: e.assetReferenceId,
    })),
    generatedAt: trail.builtAt,
  }),
  iso_27001: (trail) => ({
    standard: "ISO/IEC 27001 (information security event log)",
    assetReferenceId: trail.assetReferenceId,
    recordCount: trail.count,
    auditTrail: trail.events.map((e) => ({
      eventId: e.ledgerId,
      occurredAt: e.time,
      integrityHash: e.assetHash,
      asset: e.assetReferenceId,
    })),
    generatedAt: trail.builtAt,
  }),
};

/**
 * Bundled contract source so {@link ClockchainClient.estimateContract} works
 * without the caller uploading a file. `/api/contract/*` is multipart and
 * requires a `contractFile` part the network compiles/prices; pass
 * `contractSource` in the params to override this default.
 */
const DEFAULT_CONTRACT_TEMPLATE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract {{NAME}} {
  string public name = "{{NAME}}";
  string public symbol = "DEMO";
  uint8 public decimals = 18;
  uint256 public totalSupply = 1000000 ether;
  mapping(address => uint256) public balanceOf;
  event Transfer(address indexed from, address indexed to, uint256 value);
  constructor() { balanceOf[msg.sender] = totalSupply; }
  function transfer(address to, uint256 value) public returns (bool) {
    require(balanceOf[msg.sender] >= value, "insufficient");
    balanceOf[msg.sender] -= value; balanceOf[to] += value;
    emit Transfer(msg.sender, to, value); return true;
  }
}`;

/**
 * Coerce a contract name into a valid Solidity identifier (letters/digits/_/$,
 * not starting with a digit). Used for both the in-source contract name and the
 * upload filename, which must match for the gateway's bytecode lookup to succeed.
 */
export function solidityName(name: string): string {
  let s = String(name ?? "").replace(/[^a-zA-Z0-9_$]/g, "_");
  if (!/^[a-zA-Z_$]/.test(s)) s = "C" + s;
  return s || "Contract";
}

/**
 * Parse a Clockchain timestamp to epoch milliseconds (UTC). NaN if unparseable.
 *
 * CRITICAL: the gateway emits DD-MM-YYYY ("11-06-2026_14:41:29:089" for
 * consensus, "11-06-2026 16:10:48:544 UTC" for createdTimestamp). These MUST be
 * pattern-matched BEFORE Date.parse: V8 leniently mis-parses them month-first
 * (Nov 6 instead of Jun 11). Order: gateway regex → Date.parse (ISO) → epoch.
 */
export function parseClockTime(value: unknown): number {
  const s = String(value ?? "");
  const m = s.match(
    /^(\d{2})-(\d{2})-(\d{4})[_ ](\d{2}):(\d{2}):(\d{2}):(\d{3})(?: UTC)?$/,
  );
  if (m) {
    return Date.UTC(+m[3], +m[2] - 1, +m[1], +m[4], +m[5], +m[6], +m[7]);
  }
  const iso = Date.parse(s);
  if (!isNaN(iso)) return iso;
  const n = Number(s);
  if (!isNaN(n) && n > 0) return n > 1e12 ? n : n * 1000; // epoch ms or s
  return NaN;
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
   * Independently re-verify a receipt against the IMMUTABLE on-chain block.
   *
   * Recompute the event hash from the receipt's own payload, then confirm it
   * matches the hash anchored in the on-chain block. The receipt carries its own
   * block height + ledgerId, so a tampered record cache (PUT /ledger/{id} rewrites
   * the mutable convenience cache, which keyless GET /ledger/{id} and /verifyAsset
   * serve) cannot redirect the check. We fall back to the mutable cache ONLY when
   * the receipt is not yet anchored in a queryable block — and say so via
   * `verifiedAgainst`.
   */
  async verifyReceipt(receipt: AgentReceipt): Promise<ReceiptVerification> {
    const recomputed = eventHashOf({
      agentId: receipt.agentId,
      action: receipt.action,
      inputs: receipt.payload.inputs,
      outputs: receipt.payload.outputs,
    });
    const blockHeight = receipt.anchor.blockHeight;
    let anchoredHash: string | null = null;
    let verifiedAgainst = "on-chain block";
    if (blockHeight != null) {
      const chain = await this.getChainRecord(
        blockHeight,
        receipt.anchor.ledgerId,
      );
      if (chain) anchoredHash = chain.assetHash;
    }
    if (anchoredHash == null) {
      // Not yet anchored on-chain (or absent from the block): fall back to the
      // mutable record cache, and flag that this is NOT the authoritative read.
      const record = await this.getLedgerEntry(receipt.anchor.ledgerId);
      anchoredHash = record.assetHash;
      verifiedAgainst = "record cache (not yet anchored on-chain)";
    }
    return {
      match: recomputed === anchoredHash && recomputed === receipt.eventHash,
      eventHash: recomputed,
      anchoredHash,
      blockHeight,
      ledgerId: receipt.anchor.ledgerId,
      verifiedAgainst,
    };
  }

  // ===== SCHEDULER (smart-contract /api/contract/*) =====

  /**
   * GET /api/contract/types -> string[] of supported ERC contract types
   * (e.g. ["ERC-20","ERC-721",…]). Works with the x-api-key header.
   */
  async getContractTypes(): Promise<string[]> {
    return this.request<string[]>("/api/contract/types");
  }

  /**
   * POST /api/contract/estimate — VERIFIED multipart/form-data: form fields
   * (blockchain, contractType, contractName, scheduledTimestamp, + per-ERC keys)
   * PLUS a `contractFile` source upload the network compiles/prices. Returns the
   * gas/USD estimate (least/likely/veryLikely, each with an `estimateId`).
   *
   * The "propose" half of propose-then-approve: it prices the deploy and hands
   * back the params + an estimateId the caller signs. It moves no value. Pass
   * `contractSource` in params to override the bundled template.
   */
  async estimateContract(params: ContractParams): Promise<ContractEstimate> {
    // VERIFIED (Swagger): the estimate file part is named `contractFile`.
    const estimate = await this.requestContractMultipart<unknown>(
      "/api/contract/estimate",
      params,
      "contractFile",
    );
    return { estimate, params };
  }

  /**
   * POST /api/contract/schedule — VERIFIED multipart/form-data (2026-06-11,
   * gateway Swagger /v2/api-docs, live-tested). The file part is named
   * `solidityFile` (NOT `contractFile`, which is the estimate's part). Fields:
   * blockchain, clientId, walletId, contractName, contractType, deadline (int),
   * gasFees/minGasFees/maxGasFees (numbers from the chosen estimate),
   * totalPayablePrice, totalPayablePriceUnit, trustPercentage (int), `nonce`
   * (INTEGER), `signature` (string). Flow per Swagger: estimate →
   * buyService(SMARTCONTRACT, estimateId) → schedule.
   *
   * SIGNATURE SCHEME (decoded): the gateway's EVM wallet-sign pattern — its
   * AuthRequest is {message, signature, walletAddress} → personal_sign style.
   * The EXACT signed-message format and any testnet enforcement are UNCONFIRMED;
   * NEVER fabricate a signature for a demo. NON-CUSTODIAL: the server never
   * signs; the caller signs client-side and we only forward signature + nonce.
   * This deploys a time-triggered contract — a value-moving write.
   */
  async scheduleContract(
    params: ContractParams,
    approval: ScheduleApproval,
  ): Promise<ScheduledContract> {
    const result = await this.requestContractMultipart<unknown>(
      "/api/contract/schedule",
      {
        ...params,
        ...approval,
        clientId: this.config.clientId,
        walletId: this.config.walletId,
      },
      "solidityFile",
    );
    return { result, params, approval };
  }

  /**
   * GET /api/contract/client/{clientId} — the REAL list endpoint (VERIFIED;
   * returns {success, data:[...]}). Replaces the guessed /api/contract/list,
   * which 404s. Unwraps the envelope; returns [] on error.
   */
  async listScheduled(): Promise<unknown[]> {
    const res = await this.request<SuccessEnvelope<unknown[]> | unknown[]>(
      `/api/contract/client/${encodeURIComponent(this.config.clientId)}`,
    ).catch(() => [] as unknown[]);
    if (Array.isArray(res)) return res;
    if (
      res &&
      typeof res === "object" &&
      Array.isArray((res as SuccessEnvelope<unknown[]>).data)
    ) {
      return (res as SuccessEnvelope<unknown[]>).data;
    }
    return [];
  }

  // ===== AUDIT (derivative — composes Time + Logging + Identity) =====

  /**
   * Assemble the attested history for an asset into an ordered trail. Pure
   * composition: searchAsset to find the records, then enrich each with its
   * block time. Mints nothing — every event was already attested by Logging/Time.
   */
  async generateAuditTrail(assetReferenceId: string): Promise<AuditTrail> {
    const records = await this.searchAsset(assetReferenceId);
    const events: AuditEvent[] = [];
    for (const record of records) {
      let time: string | null = null;
      if (record.blockHeight != null) {
        const block = await this.getBlock(record.blockHeight).catch(() => null);
        time = block?.blockTime ?? null;
      }
      events.push({
        ledgerId: record.ledgerId,
        assetReferenceId: record.assetReferenceId,
        assetHash: record.assetHash,
        time,
        blockHeight: record.blockHeight,
        additionalInfo: record.additionalInfo,
      });
    }
    // Order by block height (pending/null last), then by creation order.
    events.sort((a, b) => {
      const ah = a.blockHeight == null ? Infinity : Number(a.blockHeight);
      const bh = b.blockHeight == null ? Infinity : Number(b.blockHeight);
      return ah - bh;
    });
    return {
      assetReferenceId,
      events,
      count: events.length,
      builtAt: new Date().toISOString(),
    };
  }

  /**
   * Render an audit trail into a compliance PRESET. `format` is a PARAMETER —
   * adding a regulator is adding a preset, never a new tool. The document is a
   * structured object; the reportHash is deterministic (canonical hash) so two
   * parties hash to the same digest.
   */
  async generateComplianceReport(
    assetReferenceId: string,
    format: ComplianceFormat,
  ): Promise<ComplianceReport> {
    const trail = await this.generateAuditTrail(assetReferenceId);
    const document = COMPLIANCE_PRESETS[format](trail);
    const reportHash = computeHash(canonicalize({ format, document }));
    return {
      format,
      assetReferenceId,
      reportHash,
      document,
      honestyNote: AUDIT_HONESTY_NOTE,
    };
  }

  /**
   * Build a self-contained evidence packet for one ledger record: the record +
   * block + validation + a plain-English "how to verify without trusting
   * Clockchain" note. The pkgHash is a canonical digest so re-export is
   * deterministic.
   */
  async buildEvidencePackage(ledgerId: string): Promise<EvidencePackage> {
    const record = await this.getLedgerEntry(ledgerId);
    let block: BlockResponse | null = null;
    let validation: ValidationBlock | null = null;
    if (record.blockHeight != null) {
      block = await this.getBlock(record.blockHeight).catch(() => null);
      validation = await this.getValidationBlock(record.blockHeight).catch(
        () => null,
      );
    }
    const plainEnglish =
      `Ledger record ${record.ledgerId} anchored asset hash ${record.assetHash} ` +
      `(reference ${record.assetReferenceId}) at block height ` +
      `${record.blockHeight ?? "pending"}. To verify without trusting Clockchain: ` +
      "recompute the SHA-256 hash of your original asset and confirm it equals " +
      "the anchored assetHash above, then fetch this ledgerId from the public " +
      "Clockchain ledger and confirm the anchored hash and block match this packet.";
    const pkgHash = computeHash(
      canonicalize({ record, block, validation, plainEnglish }),
    );
    return {
      packageId: `pkg_${record.ledgerId}`,
      pkgHash,
      record,
      block,
      validation,
      plainEnglish,
      honestyNote: AUDIT_HONESTY_NOTE,
    };
  }

  /**
   * Recompute an evidence package's pkgHash and compare its anchored hash to the
   * ledger. Reuses the same canonicalization used to build the packet, so a
   * faithful packet round-trips to the same digest.
   *
   * Resolves the anchored hash against the IMMUTABLE on-chain block
   * ({@link getChainRecord}) when the record carries a blockHeight — the
   * authoritative read a tampered cache (PUT /ledger/{id}) cannot redirect. Falls
   * back to the mutable cache (GET /ledger/{id}) only when not yet anchored. Never
   * a local store.
   */
  async verifyPackage(pkg: EvidencePackage): Promise<PackageVerification> {
    const recomputedPkgHash = computeHash(
      canonicalize({
        record: pkg.record,
        block: pkg.block,
        validation: pkg.validation,
        plainEnglish: pkg.plainEnglish,
      }),
    );
    let anchoredHash: string | null = null;
    let verifiedAgainst = "on-chain block";
    if (pkg.record.blockHeight != null) {
      const chain = await this.getChainRecord(
        pkg.record.blockHeight,
        pkg.record.ledgerId,
      );
      if (chain) anchoredHash = chain.assetHash;
    }
    if (anchoredHash == null) {
      const record = await this.getLedgerEntry(pkg.record.ledgerId);
      anchoredHash = record.assetHash;
      verifiedAgainst = "record cache (not yet anchored on-chain)";
    }
    const anchorMatch = anchoredHash === pkg.record.assetHash;
    const pkgHashMatch = recomputedPkgHash === pkg.pkgHash;
    return {
      valid: pkgHashMatch && anchorMatch,
      pkgHashMatch,
      anchorMatch,
      recomputedPkgHash,
      anchoredHash,
      note:
        `Verified against the Clockchain ${verifiedAgainst}. Testnet; ` +
        "designed-for court-grade, not certified.",
    };
  }

  // ===== AGENT IDENTITY (writes via the /log hash-anchor convention) =====

  /**
   * Mint an agent identity by anchoring SHA-256 of the canonical document under
   * the `did:mint:{did}` convention. The document stays client-side — only its
   * hash is anchored (additionalInfo is plain-text and strips structure).
   */
  async mintIdentity(
    did: string,
    document: unknown,
  ): Promise<IdentityWrite> {
    const docHash = computeHash(canonicalize(document));
    const assetReferenceId = `did:mint:${did}`;
    const log = await this.log({
      assetHash: docHash,
      assetReferenceId,
      additionalInfo: "agent identity mint",
    });
    return {
      did,
      assetReferenceId,
      docHash,
      ledgerId: log.ledgerId,
      blockHeight: log.blockHeight,
      status: "active",
    };
  }

  /**
   * Revoke an agent identity under the `did:revoke:{did}` convention. The
   * revoke-T is attested by the anchor's block time (load-bearing for valid-at-T).
   */
  async revokeIdentity(did: string): Promise<IdentityWrite> {
    const assetReferenceId = `did:revoke:${did}`;
    const docHash = computeHash(canonicalize({ revoke: did }));
    const log = await this.log({
      assetHash: docHash,
      assetReferenceId,
      additionalInfo: "agent identity revoke",
    });
    return {
      did,
      assetReferenceId,
      docHash,
      ledgerId: log.ledgerId,
      blockHeight: log.blockHeight,
      status: "revoked",
    };
  }

  /**
   * Delegate a scoped, time-boxed subset of authority from parent to child under
   * the `did:delegate:{parent}:{child}` convention. Anchors the hash of the
   * delegation document; the document itself stays client-side.
   */
  async delegateAuthority(args: {
    parentDid: string;
    childDid: string;
    scope: string[];
    until: string;
  }): Promise<IdentityWrite> {
    const { parentDid, childDid, scope, until } = args;
    const assetReferenceId = `did:delegate:${parentDid}:${childDid}`;
    const docHash = computeHash(
      canonicalize({ parent: parentDid, child: childDid, scope, until }),
    );
    const log = await this.log({
      assetHash: docHash,
      assetReferenceId,
      additionalInfo: "agent authority delegation",
    });
    return {
      did: childDid,
      assetReferenceId,
      docHash,
      ledgerId: log.ledgerId,
      blockHeight: log.blockHeight,
      status: "delegated",
    };
  }

  /**
   * Assemble a DID's attested activity history by exact-match searching the
   * mint / revoke / delegate references, then ordering by block height. Reuses
   * the Logging recall path; mints nothing.
   */
  async getIdentityHistory(did: string): Promise<IdentityHistory> {
    const refs: Array<{ type: "mint" | "revoke" | "delegate"; ref: string }> = [
      { type: "mint", ref: `did:mint:${did}` },
      { type: "revoke", ref: `did:revoke:${did}` },
    ];
    const events: IdentityHistory["events"] = [];
    for (const { type, ref } of refs) {
      const records = await this.searchAsset(ref).catch(() => []);
      for (const record of records) {
        const time = await this.consensusTimeFor(record.blockHeight);
        events.push(this.toIdentityEvent(type, record, time));
      }
    }
    // Delegations are keyed by `did:delegate:${did}:${child}`; searchAsset is
    // exact-match, so a child-agnostic prefix search is not available. We try the
    // self-delegation ref as a best-effort (full enumeration is backend-gated).
    const delegateRecords = await this.searchAsset(
      `did:delegate:${did}:${did}`,
    ).catch(() => []);
    for (const record of delegateRecords) {
      const time = await this.consensusTimeFor(record.blockHeight);
      events.push(this.toIdentityEvent("delegate", record, time));
    }
    events.sort((a, b) => {
      const ah = a.blockHeight == null ? Infinity : Number(a.blockHeight);
      const bh = b.blockHeight == null ? Infinity : Number(b.blockHeight);
      return ah - bh;
    });
    return { did, events };
  }

  /**
   * Valid-at-T — the dispute-winning query: was this agent's identity authorized
   * at the instant T? Computed from attested mint-T and revoke-T: authorized iff
   * a mint exists at or before T and no revoke exists at or before T.
   * acted-at-T1 vs revoked-at-T2 with T1 > T2 ⟹ provably unauthorized.
   *
   * This is identity VERIFICATION (was the binding valid at T?), NOT
   * authentication. Both timestamps are independently attested on-chain; any
   * counterparty can re-verify them keylessly via {@link publicGetLedger}.
   */
  async verifyIdentityAt(
    did: string,
    atIso: string,
  ): Promise<IdentityVerification> {
    const at = Date.parse(atIso);
    if (isNaN(at)) {
      throw new ApiError(
        "Invalid 'at' time — pass RFC 3339, e.g. 2026-06-11T14:00:00Z",
        400,
      );
    }
    const history = await this.getIdentityHistory(did);
    const mintsBefore = history.events.filter(
      (e) => e.type === "mint" && this.instantOf(e) <= at,
    );
    const revokesBefore = history.events.filter(
      (e) => e.type === "revoke" && this.instantOf(e) <= at,
    );
    const lastMint = mintsBefore[mintsBefore.length - 1];
    const lastRevoke = revokesBefore[revokesBefore.length - 1];
    const authorized = !!lastMint && !lastRevoke;
    return {
      did,
      at: atIso,
      authorized,
      reason: !lastMint
        ? "No attested mint exists at or before T — identity did not exist yet."
        : lastRevoke
          ? "An attested revoke exists at or before T — authority had been withdrawn."
          : "An attested mint exists at or before T and no revoke had occurred — authorized at T.",
      mintedAt: lastMint ? String(lastMint.time ?? lastMint.recordedAt) : null,
      revokedAt: lastRevoke
        ? String(lastRevoke.time ?? lastRevoke.recordedAt)
        : null,
      evidence: {
        mintLedgerId: lastMint?.ledgerId,
        revokeLedgerId: lastRevoke?.ledgerId,
      },
      note:
        "Both timestamps are independently attested on-chain; any counterparty " +
        "can re-verify them keylessly via /ledger/{id}. Own-client history " +
        "(cross-client discovery is backend-gated).",
    };
  }

  // ===== CROSS-PARTY (keyless) VERIFICATION =====
  // VERIFIED live (2026-06-11): GET /ledger/{id} and POST /verifyAsset require
  // NO api key. Any counterparty holding a receipt (ledgerId) or just the hash
  // can verify against the network WITHOUT a Clockchain account — present-and-
  // verify works cross-party TODAY. (Only DISCOVERY/enumeration — searchAsset —
  // is clientId-scoped.) This is the trust-minimizing payoff: an outside party
  // needs no privileged access to confirm an anchor.

  /**
   * Keyless ledger read (GET /ledger/{id}, NO x-api-key) — what an outside
   * counterparty does with a receipt's ledgerId, with no Clockchain account.
   */
  async publicGetLedger(ledgerId: string): Promise<LedgerRecord> {
    return this.keylessRequest<LedgerRecord>(
      `/ledger/${encodeURIComponent(ledgerId)}`,
    );
  }

  /**
   * Keyless verify-by-hash (POST /verifyAsset, body a JSON array of hashes, NO
   * x-api-key) — anyone holding the hash can confirm it is anchored, without an
   * account. Proves Clockchain stores no privileged gate on present-and-verify.
   *
   * ADVISORY ONLY: this reads the MUTABLE record cache, which an api-key holder
   * can rewrite via PUT /ledger/{id}. It is a convenience lookup, NOT the
   * authoritative check. For the authoritative, tamper-proof result use
   * {@link verifyOnChain} (reads the immutable on-chain block).
   */
  async publicVerifyHash(hash: string): Promise<Record<string, unknown>> {
    return this.keylessRequest<Record<string, unknown>>("/verifyAsset", {
      method: "POST",
      body: [hash],
    });
  }

  /**
   * Read a record from the IMMUTABLE on-chain block (GET
   * /searchAssetFromChain?blockHeight={h}, NO x-api-key). This is the
   * AUTHORITATIVE record. Unlike GET /ledger/{id} and /verifyAsset (which read a
   * mutable convenience cache an api-key holder can rewrite via PUT /ledger/{id}),
   * the block cannot be altered. The block stores records as stringified Java
   * objects (e.g. `Ledger(ledgerId=..., assetHash=a077..., assetReferenceId=...)`);
   * parse the matching ledgerId's assetHash. Returns null when the block has no
   * record for that ledgerId (e.g. not yet anchored).
   */
  async getChainRecord(
    blockHeight: string | number,
    ledgerId: string,
  ): Promise<ChainRecord | null> {
    const res = await this.keylessRequest<{
      blockHeight?: string;
      transactions?: string[];
    }>(
      `/searchAssetFromChain?blockHeight=${encodeURIComponent(String(blockHeight))}`,
    ).catch(() => null);
    for (const t of res?.transactions ?? []) {
      const id = (String(t).match(/ledgerId=([^,]+)/) || [])[1];
      if (id === ledgerId) {
        return {
          assetHash: (String(t).match(/assetHash=([0-9a-fx]+)/) || [])[1] ?? "",
          assetReferenceId:
            (String(t).match(/assetReferenceId=([^,]+)/) || [])[1] ?? "",
          blockHeight: String(res?.blockHeight ?? blockHeight),
        };
      }
    }
    return null;
  }

  /**
   * Cross-party verify against the IMMUTABLE chain (keyless) — what an outside
   * counterparty runs. The receipt carries its block height; the hash is confirmed
   * against the on-chain block, never the rewritable cache. When only a ledgerId is
   * known, the height is discovered via the cache (advisory) and the hash is still
   * checked against the chain. This is the AUTHORITATIVE check — a tampered cache
   * (PUT /ledger/{id}) cannot redirect it.
   */
  async verifyOnChain(
    ledgerId: string,
    blockHeight?: string | number,
  ): Promise<OnChainVerification> {
    let height = blockHeight;
    let heightSource = "from the receipt";
    if (height == null) {
      const cached = await this.publicGetLedger(ledgerId).catch(() => null);
      if (cached?.blockHeight != null) height = cached.blockHeight;
      heightSource = "discovered via the record cache (advisory)";
    }
    if (height == null) {
      return {
        verifiedAgainst: "none",
        ledgerId,
        note: "No block height available — the record may not be anchored on-chain yet.",
      };
    }
    const chain = await this.getChainRecord(height, ledgerId);
    if (!chain) {
      return {
        verifiedAgainst: "none",
        ledgerId,
        blockHeight: String(height),
        note: "No matching record in that on-chain block.",
      };
    }
    return {
      verifiedAgainst: "on-chain block",
      keyless: true,
      ledgerId,
      blockHeight: String(height),
      heightSource,
      anchoredHash: chain.assetHash,
      assetReferenceId: chain.assetReferenceId,
      note:
        "Read from the immutable on-chain block (/searchAssetFromChain) with NO " +
        "api key — not the rewritable record cache. This is the authoritative check.",
    };
  }

  // --- internals ---

  /**
   * Best-effort consensus (block) time for a height — null when pending or on
   * any lookup error. Used to enrich identity history with attested time.
   */
  private async consensusTimeFor(
    blockHeight: string | null,
  ): Promise<string | null> {
    if (blockHeight == null) return null;
    const block = await this.getBlock(blockHeight).catch(() => null);
    return block?.blockTime ?? null;
  }

  /**
   * Resolve an identity event to an epoch-ms instant for valid-at-T comparison.
   * Prefers the attested consensus `time`, falling back to `recordedAt`. Both
   * are parsed with {@link parseClockTime} (gateway DD-MM-YYYY formats FIRST).
   */
  private instantOf(event: IdentityEvent): number {
    const t = parseClockTime(event.time);
    return isNaN(t) ? parseClockTime(event.recordedAt) : t;
  }

  /**
   * Keyless HTTP entry point: deliberately sends NO x-api-key, proving cross-
   * party present-and-verify needs no privileged access. Parses JSON; maps a
   * non-2xx to an ApiError.
   */
  private async keylessRequest<T>(
    path: string,
    opts: RequestOptions = {},
  ): Promise<T> {
    const headers: Record<string, string> = { accept: "application/json" };
    if (opts.body !== undefined) {
      headers["content-type"] = "application/json";
    }
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: opts.method ?? "GET",
      headers, // NO x-api-key — that is the point
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });
    if (!res.ok) {
      throw new ApiError(
        `Clockchain request failed: ${res.status} ${res.statusText}`,
        res.status,
      );
    }
    return (await res.json()) as T;
  }

  /**
   * Multipart POST to /api/contract/* (the VERIFIED shape): form fields + a
   * Solidity source upload. The file-part name DIFFERS per endpoint (VERIFIED,
   * Swagger): `contractFile` for /estimate, `solidityFile` for /schedule — pass
   * it via `fileField`. Uses the bundled template when no `contractSource` is
   * given. Sets only x-api-key (fetch adds the multipart boundary itself).
   * Non-custodial: any signature/nonce are caller-supplied.
   */
  private async requestContractMultipart<T>(
    path: string,
    params: Record<string, string | number>,
    fileField: string = "contractFile",
  ): Promise<T> {
    const { contractSource, ...fields } = params as Record<string, string | number> & {
      contractSource?: string;
    };
    // A Solidity contract name must be a valid identifier — `contract treasury-payout {}`
    // is a SYNTAX ERROR. The gateway names the compiled bytecode by the uploaded
    // FILENAME and solc names it by the CONTRACT name, so both must be this exact
    // sanitized identifier, or the compile yields no bytecode ("Bytecode missing" 500).
    const name = solidityName(String(fields.contractName ?? "Contract"));
    fields.contractName = name; // keep the form field consistent with source + filename
    const source =
      typeof contractSource === "string" && contractSource.length > 0
        ? contractSource
        : DEFAULT_CONTRACT_TEMPLATE.replace(/\{\{NAME\}\}/g, name);

    const fd = new FormData();
    for (const [k, v] of Object.entries(fields)) {
      if (v === undefined || v === null) continue;
      fd.append(k, String(v));
    }
    fd.append(fileField, new Blob([source], { type: "text/plain" }), `${name}.sol`);

    const res = await fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: { "x-api-key": this.config.apiKey, accept: "application/json" },
      body: fd,
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
    const textForMatch = typeof parsed === "string" ? parsed : JSON.stringify(parsed ?? "");
    if (res.status === 429 || /rate limit exceeded/i.test(textForMatch)) {
      throw new RateLimitError("Rate limit exceeded", res.status, parsed);
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

  /**
   * Map a ledger record into an ordered identity-history event. Carries the
   * gateway's createdTimestamp as `recordedAt` so valid-at-T can fall back to it
   * when consensus `time` is not (yet) resolved. `time` is enriched separately
   * by {@link getIdentityHistory} (best-effort block-time lookup).
   */
  private toIdentityEvent(
    type: "mint" | "revoke" | "delegate",
    record: LedgerRecord,
    time: string | null = null,
  ): IdentityHistory["events"][number] {
    return {
      type,
      assetReferenceId: record.assetReferenceId,
      ledgerId: record.ledgerId,
      assetHash: record.assetHash,
      time,
      blockHeight: record.blockHeight,
      recordedAt: record.createdTimestamp,
    };
  }

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
