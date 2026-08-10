type FetchLike = (
  url: string,
  init: { method: "POST"; headers: Record<string, string>; body: string },
) => Promise<{ ok: boolean; status: number; text(): Promise<string> }>;

export interface RecoverEip191AddressOptions {
  rpcUrl: string;
  bytes: string | Uint8Array;
  signatureHex: string;
  fetchImpl?: FetchLike;
}

export interface ResolveOwnedAgentIdOptions {
  rpcUrl: string;
  registryAddress: string;
  address: string;
  fetchImpl?: FetchLike;
  fromBlock?: string;
}

interface JsonRpcResponse {
  jsonrpc?: unknown;
  id?: unknown;
  result?: unknown;
  error?: unknown;
}

interface TransferLog {
  address?: string;
  blockNumber?: string;
  logIndex?: string;
  transactionHash?: string;
  topics?: string[];
}

const ECRECOVER_PRECOMPILE = "0x0000000000000000000000000000000000000001";
const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const OWNER_OF_SELECTOR = "0x6352211e";
const SEPOLIA_ERC8004_REGISTRY_ADDRESS = "0x8004a818bfb912233c491871b3d84c89a494bd9e";
const SEPOLIA_ERC8004_REGISTRY_CREATION_BLOCK = 9_989_393n;
const MAX_LOG_BLOCKS = 50_000n;
const MAX_REVERSE_SCAN_BLOCKS = 5_000_000n;
const MAX_OWNER_OF_PROBES = 32;
const HEX = /^[0-9a-fA-F]*$/;

export async function recoverEip191Address(options: RecoverEip191AddressOptions): Promise<string> {
  const signature = parseSignature(options.signatureHex);
  const fetchImpl = options.fetchImpl ?? globalFetch();
  const messageHex = bytesToHex(eip191Payload(options.bytes));
  const digest = await rpcString(options.rpcUrl, fetchImpl, "web3_sha3", [messageHex], "compute EIP-191 digest");
  assertBytesHex(digest, 32, "web3_sha3 digest");

  const data = "0x" + strip0x(digest) + word(signature.v) + signature.r + signature.s;
  const recovered = await rpcString(
    options.rpcUrl,
    fetchImpl,
    "eth_call",
    [{ to: ECRECOVER_PRECOMPILE, data }, "latest"],
    "recover EIP-191 signer through ecrecover",
  );
  assertBytesHex(recovered, 32, "ecrecover result");
  const address = "0x" + strip0x(recovered).slice(-40);
  if (/^0x0{40}$/i.test(address)) {
    throw new Error("EIP-191 signature recovery failed: ecrecover returned the zero address");
  }
  return normalizeAddress(address, "recovered address");
}

export async function resolveOwnedAgentId(options: ResolveOwnedAgentIdOptions): Promise<string | null> {
  const fetchImpl = options.fetchImpl ?? globalFetch();
  const registryAddress = normalizeAddress(options.registryAddress, "registryAddress");
  const ownerAddress = normalizeAddress(options.address, "address");
  const latest = hexQuantity(await rpcString(
    options.rpcUrl,
    fetchImpl,
    "eth_blockNumber",
    [],
    "read the latest block before scanning ERC-721 transfers",
  ));
  const earliest = resolveEarliestBlock(registryAddress, options.fromBlock);
  if (earliest > latest) return null;
  const scanBlocks = latest - earliest + 1n;
  if (scanBlocks > MAX_REVERSE_SCAN_BLOCKS) {
    throw new Error(
      `Reverse ERC-721 Transfer scan range exceeds ${MAX_REVERSE_SCAN_BLOCKS.toString()} blocks; ` +
        "pass a narrower fromBlock",
    );
  }
  const seenTokens = new Set<string>();
  let ownerOfProbes = 0;

  for (let high = latest; high >= earliest;) {
    const low = high - earliest + 1n > MAX_LOG_BLOCKS
      ? high - MAX_LOG_BLOCKS + 1n
      : earliest;
    const logs = await rpcArray(
      options.rpcUrl,
      fetchImpl,
      "eth_getLogs",
      [{
        address: registryAddress,
        fromBlock: toHexQuantity(low),
        toBlock: toHexQuantity(high),
        topics: [TRANSFER_TOPIC, null, topicAddress(ownerAddress)],
      }],
      "load ERC-721 Transfer logs for acquired agent tokens",
    );

    const transferLogs = logs
      .filter(isTransferLog)
      .sort((a, b) => compareHexQuantity(b.blockNumber ?? "0x0", a.blockNumber ?? "0x0")
        || compareHexQuantity(b.logIndex ?? "0x0", a.logIndex ?? "0x0"));

    for (const log of transferLogs) {
      const tokenWord = log.topics?.[3];
      if (!tokenWord || !isBytesHex(tokenWord, 32) || seenTokens.has(tokenWord)) continue;
      seenTokens.add(tokenWord);
      ownerOfProbes += 1;
      if (ownerOfProbes > MAX_OWNER_OF_PROBES) {
        throw new Error(`ownerOf candidate probe cap exceeded (${MAX_OWNER_OF_PROBES}); pass a narrower fromBlock`);
      }
      const owner = await ownerOf(options.rpcUrl, fetchImpl, registryAddress, tokenWord);
      if (owner === ownerAddress) return BigInt(tokenWord).toString(10);
    }
    if (low === earliest) break;
    high = low - 1n;
  }

  return null;
}

export async function resolveOwnedAgentRegistration(options: ResolveOwnedAgentIdOptions): Promise<Readonly<{
  agentId: string;
  registrationBlock: string;
  registrationTx: string;
}> | null> {
  const fetchImpl = options.fetchImpl ?? globalFetch();
  const registryAddress = normalizeAddress(options.registryAddress, "registryAddress");
  const ownerAddress = normalizeAddress(options.address, "address");
  const latest = hexQuantity(await rpcString(options.rpcUrl, fetchImpl, "eth_blockNumber", [], "read the latest block before scanning ERC-721 transfers"));
  const earliest = resolveEarliestBlock(registryAddress, options.fromBlock);
  if (earliest > latest) return null;
  const seenTokens = new Set<string>();
  let ownerOfProbes = 0;
  for (let high = latest; high >= earliest;) {
    const low = high - earliest + 1n > MAX_LOG_BLOCKS ? high - MAX_LOG_BLOCKS + 1n : earliest;
    const logs = await rpcArray(options.rpcUrl, fetchImpl, "eth_getLogs", [{
      address: registryAddress,
      fromBlock: toHexQuantity(low),
      toBlock: toHexQuantity(high),
      topics: [TRANSFER_TOPIC, null, topicAddress(ownerAddress)],
    }], "load ERC-721 Transfer logs for acquired agent tokens");
    const transferLogs = logs.filter(isTransferLog).sort((a, b) =>
      compareHexQuantity(b.blockNumber ?? "0x0", a.blockNumber ?? "0x0") ||
      compareHexQuantity(b.logIndex ?? "0x0", a.logIndex ?? "0x0"));
    for (const log of transferLogs) {
      const tokenWord = log.topics?.[3];
      if (!tokenWord || !isBytesHex(tokenWord, 32) || seenTokens.has(tokenWord)) continue;
      seenTokens.add(tokenWord);
      ownerOfProbes += 1;
      if (ownerOfProbes > MAX_OWNER_OF_PROBES) throw new Error(`ownerOf candidate probe cap exceeded (${MAX_OWNER_OF_PROBES}); pass a narrower fromBlock`);
      const owner = await ownerOf(options.rpcUrl, fetchImpl, registryAddress, tokenWord);
      if (owner !== ownerAddress) continue;
      const transactionHash = log.transactionHash;
      const blockNumber = log.blockNumber;
      if (typeof transactionHash !== "string" || !isBytesHex(transactionHash, 32) || typeof blockNumber !== "string") {
        throw new Error("ERC-8004 registration log is missing its transaction or block binding");
      }
      return Object.freeze({
        agentId: BigInt(tokenWord).toString(10),
        registrationBlock: hexQuantity(blockNumber).toString(10),
        registrationTx: transactionHash.toLowerCase(),
      });
    }
    if (low === earliest) break;
    high = low - 1n;
  }
  return null;
}

async function ownerOf(
  rpcUrl: string,
  fetchImpl: FetchLike,
  registryAddress: string,
  tokenWord: string,
): Promise<string | null> {
  const result = await rpcString(
    rpcUrl,
    fetchImpl,
    "eth_call",
    [{ to: registryAddress, data: OWNER_OF_SELECTOR + strip0x(tokenWord) }, "latest"],
    `check ownerOf token ${BigInt(tokenWord).toString(10)}`,
  );
  if (!isBytesHex(result, 32)) {
    throw new Error(`ownerOf returned an invalid address word for token ${BigInt(tokenWord).toString(10)}`);
  }
  const address = "0x" + strip0x(result).slice(-40);
  return /^0x0{40}$/i.test(address) ? null : normalizeAddress(address, "ownerOf result");
}

async function rpcString(
  rpcUrl: string,
  fetchImpl: FetchLike,
  method: string,
  params: unknown[],
  action: string,
): Promise<string> {
  const result = await rpc(rpcUrl, fetchImpl, method, params, action);
  if (typeof result !== "string") {
    throw new Error(`RPC ${method} failed to ${action}: expected string result`);
  }
  return result;
}

async function rpcArray(
  rpcUrl: string,
  fetchImpl: FetchLike,
  method: string,
  params: unknown[],
  action: string,
): Promise<unknown[]> {
  const result = await rpc(rpcUrl, fetchImpl, method, params, action);
  if (!Array.isArray(result)) {
    throw new Error(`RPC ${method} failed to ${action}: expected array result`);
  }
  return result;
}

async function rpc(
  rpcUrl: string,
  fetchImpl: FetchLike,
  method: string,
  params: unknown[],
  action: string,
): Promise<unknown> {
  let response: Awaited<ReturnType<FetchLike>>;
  try {
    response = await fetchImpl(rpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
  } catch (err) {
    throw new Error(`RPC ${method} failed to ${action}: ${(err as Error).message}`);
  }

  const text = await response.text();
  if (!response.ok) {
    throw new Error(`RPC ${method} failed to ${action}: HTTP ${response.status} ${text.slice(0, 300)}`);
  }

  let body: unknown;
  try {
    body = JSON.parse(text) as unknown;
  } catch {
    throw new Error(`RPC ${method} failed to ${action}: invalid JSON response`);
  }

  const envelope = validateJsonRpcEnvelope(body, method, action);
  if (envelope.error !== undefined) {
    throw new Error(`RPC ${method} failed to ${action}: ${envelope.error.message}`);
  }
  return envelope.result;
}

function validateJsonRpcEnvelope(
  body: unknown,
  method: string,
  action: string,
): { result?: unknown; error?: { code: number; message: string } } {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw new Error(`RPC ${method} failed to ${action}: invalid JSON-RPC response envelope`);
  }
  const envelope = body as JsonRpcResponse;
  const hasResult = Object.prototype.hasOwnProperty.call(envelope, "result");
  const hasError = Object.prototype.hasOwnProperty.call(envelope, "error");
  if (
    envelope.jsonrpc !== "2.0"
    || envelope.id !== 1
    || hasResult === hasError
  ) {
    throw new Error(`RPC ${method} failed to ${action}: invalid JSON-RPC response envelope`);
  }
  if (hasError) {
    if (
      typeof envelope.error !== "object"
      || envelope.error === null
      || Array.isArray(envelope.error)
      || typeof (envelope.error as { code?: unknown }).code !== "number"
      || typeof (envelope.error as { message?: unknown }).message !== "string"
    ) {
      throw new Error(`RPC ${method} failed to ${action}: invalid JSON-RPC response envelope`);
    }
    return { error: envelope.error as { code: number; message: string } };
  }
  return { result: envelope.result };
}

function parseSignature(signatureHex: string): { r: string; s: string; v: number } {
  if (!isBytesHex(signatureHex, 65)) {
    throw new Error("Expected a 65-byte hex EIP-191 signature (0x + r + s + v)");
  }
  const hex = strip0x(signatureHex);
  const rawV = Number.parseInt(hex.slice(128, 130), 16);
  const v = rawV === 0 || rawV === 1 ? rawV + 27 : rawV;
  if (v !== 27 && v !== 28) {
    throw new Error("Expected a 65-byte hex EIP-191 signature with v equal to 27/28 or 0/1");
  }
  return { r: hex.slice(0, 64).toLowerCase(), s: hex.slice(64, 128).toLowerCase(), v };
}

function eip191Payload(bytes: string | Uint8Array): Uint8Array {
  const message = typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes;
  const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${message.length}`);
  const out = new Uint8Array(prefix.length + message.length);
  out.set(prefix, 0);
  out.set(message, prefix.length);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return "0x" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function word(n: number): string {
  return n.toString(16).padStart(64, "0");
}

function topicAddress(address: string): string {
  return "0x" + strip0x(address).padStart(64, "0");
}

function normalizeAddress(value: string, name: string): string {
  if (!isBytesHex(value, 20)) {
    throw new Error(`Invalid ${name}: expected 20-byte hex address`);
  }
  return "0x" + strip0x(value).toLowerCase();
}

function assertBytesHex(value: string, bytes: number, name: string): void {
  if (!isBytesHex(value, bytes)) throw new Error(`Invalid ${name}: expected ${bytes}-byte hex value`);
}

function isBytesHex(value: string, bytes: number): boolean {
  const hex = strip0x(value);
  return value.startsWith("0x") && hex.length === bytes * 2 && HEX.test(hex);
}

function strip0x(value: string): string {
  return value.startsWith("0x") || value.startsWith("0X") ? value.slice(2) : value;
}

function isTransferLog(value: unknown): value is TransferLog {
  if (typeof value !== "object" || value === null) return false;
  const log = value as TransferLog;
  return Array.isArray(log.topics) && log.topics.length >= 4;
}

function compareHexQuantity(a: string, b: string): number {
  const left = hexQuantity(a);
  const right = hexQuantity(b);
  return left > right ? 1 : left < right ? -1 : 0;
}

function hexQuantity(value: string): bigint {
  if (!/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$/.test(value)) {
    throw new Error("Invalid JSON-RPC block quantity");
  }
  return BigInt(value);
}

function toHexQuantity(value: bigint): string {
  return `0x${value.toString(16)}`;
}

function resolveEarliestBlock(registryAddress: string, fromBlock?: string): bigint {
  if (fromBlock !== undefined) return hexQuantity(fromBlock);
  return registryAddress === SEPOLIA_ERC8004_REGISTRY_ADDRESS
    ? SEPOLIA_ERC8004_REGISTRY_CREATION_BLOCK
    : 0n;
}

function globalFetch(): FetchLike {
  if (typeof fetch !== "function") {
    throw new Error("No fetch implementation available; pass fetchImpl to the EVM handshake helper");
  }
  return fetch as unknown as FetchLike;
}
