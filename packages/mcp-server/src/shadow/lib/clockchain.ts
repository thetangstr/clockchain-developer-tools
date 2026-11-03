// HAND-WRITTEN SHIM (not vendored; scripts/sync-shadow-lib.mjs leaves it alone).
//
// The library's clockchain.ts is an HTTP MCP client. Hosted Shadow anchors through the server's own in-process
// Clockchain client instead, so only what the vendored verify.ts imports lives here: the typed error (whose
// RateLimited kind verify.ts waits out) and the two online reads its witness check makes. The shapes match
// clockchain-shadow/ts/src/clockchain.ts exactly.

export type ErrorKind = "Auth" | "Credits" | "RateLimited" | "PoolDegraded" | "Transient" | "Permanent";

// `code` is a fixed, content-free label (http_503, network, timeout, ...). Only kind and code go into a record.
export class ClockchainError extends Error {
  kind: ErrorKind;
  retryAfterSeconds: number | null;
  code: string;
  constructor(kind: ErrorKind, message: string, retryAfterSeconds: number | null = null, code = "error") {
    super(message);
    this.name = "ClockchainError";
    this.kind = kind;
    this.retryAfterSeconds = retryAfterSeconds;
    this.code = code;
  }
}

// submittedAt is Clockchain's record creation time: the earliest moment the ledger id could be known.
export type WriteReceipt = {
  ledgerId: string;
  blockHeight: string | null;
  assetHash: string | null;
  blockTime: string | null;
  submittedAt: string | null;
};

/** The online reads the October verify.ts imported as a type; the current one declares its own OnlineClient. */
export interface ClockchainClient {
  logEntry(ledgerId: string): Promise<WriteReceipt>;
  confirmPackage(ledgerId: string): Promise<{ valid: boolean; pkgHash: string | null }>;
  search?(referenceId: string): Promise<{ ledgerId: string; assetHash: string | null; blockHeight: string | null }[]>;
  readonly network?: string;
}
