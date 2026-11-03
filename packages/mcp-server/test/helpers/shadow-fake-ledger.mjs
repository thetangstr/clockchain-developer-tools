// An in-process stand-in for @clockchain/core's ClockchainClient, covering the calls hosted Shadow makes. It keeps
// every write so tests can check exactly what reached the ledger. Times are ISO 8601 (block time = submission + 1 s).
import { randomUUID, createHash } from "node:crypto";
import { ApiError } from "@clockchain/core";

export class FakeLedger {
  records = [];
  writes = [];
  height = 1000;
  down = false; // every call fails like an unreachable gateway
  confirm = true; // false leaves new writes pending (no block yet)
  degraded = false;
  failNextLog = null; // an Error thrown by the next log()
  failBlockReads = false;
  base = Date.UTC(2026, 10, 2, 12, 0, 0);

  time(h) {
    return new Date(this.base + Number(h) * 2000).toISOString();
  }

  #gate() {
    if (this.down) throw new TypeError("fetch failed");
  }

  async getPoolHealth() {
    this.#gate();
    return { totalNodes: 1, nodeParticipationPct: this.degraded ? 0 : 100, degraded: this.degraded };
  }

  async log(entry) {
    this.#gate();
    if (this.failNextLog) {
      const e = this.failNextLog;
      this.failNextLog = null;
      throw e;
    }
    this.writes.push({ ...entry });
    const h = ++this.height;
    const r = {
      ledgerId: randomUUID(), clientId: "client-1", walletId: "wallet-1",
      assetReferenceId: entry.assetReferenceId, assetHash: entry.assetHash, hashType: entry.hashType ?? "SHA-256",
      versionNumber: 1, additionalInfo: entry.additionalInfo ?? "", blockHeight: this.confirm ? String(h) : null,
      createdTimestamp: new Date(this.base + h * 2000 - 1000).toISOString(), updatedTimestamp: null, assetName: null, type: null,
      _height: h,
    };
    this.records.push(r);
    return this.#public(r);
  }

  confirmPending() {
    for (const r of this.records) if (!r.blockHeight) r.blockHeight = String(r._height);
  }

  #public(r) {
    const { _height, ...rest } = r;
    return { ...rest, status: rest.blockHeight ? "anchored" : "pending" };
  }

  async getLedgerEntry(ledgerId) {
    this.#gate();
    const r = this.records.find((x) => x.ledgerId === ledgerId);
    if (!r) throw new ApiError("Ledger lookup failed", 404);
    return this.#public(r);
  }

  async waitForConfirmation(ledgerId) {
    return this.getLedgerEntry(ledgerId);
  }

  async searchAsset(ref) {
    this.#gate();
    return this.records.filter((r) => r.assetReferenceId === ref).map((r) => this.#public(r));
  }

  async getBlock(height) {
    this.#gate();
    if (this.failBlockReads) throw new ApiError("Clockchain API error (503)", 503);
    return { blockHeight: Number(height), proposerAddress: "validator-1", blockTime: this.time(height) };
  }

  async buildEvidencePackage(ledgerId) {
    const record = await this.getLedgerEntry(ledgerId);
    return { packageId: `pkg_${ledgerId}`, pkgHash: createHash("sha256").update(JSON.stringify(record)).digest("hex"), record, block: null, validation: null, plainEnglish: "", honestyNote: "" };
  }

  async verifyPackage(pkg) {
    this.#gate();
    const r = this.records.find((x) => x.ledgerId === pkg.record.ledgerId);
    return { valid: !!r && r.assetHash === pkg.record.assetHash, pkgHashMatch: true, anchorMatch: !!r, recomputedPkgHash: pkg.pkgHash, anchoredHash: r?.assetHash ?? null, note: "" };
  }
}
