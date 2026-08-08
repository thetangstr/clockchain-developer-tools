import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  timingSafeEqual,
  verify,
} from "node:crypto";

export const BILATERAL_PROTOCOL = "clockchain.bilateral-authorization/v1";
export const DESCRIPTOR_SCHEMA = "clockchain.bilateral-session-descriptor/v2";
export const PAYER_MANDATE_SCHEMA = "clockchain.bilateral-payer-mandate/v1";
export const PAYER_MANDATE_ENVELOPE_SCHEMA = "clockchain.bilateral-payer-mandate-envelope/v1";
export const PAYMENT_REQUEST_SCHEMA = "clockchain.bilateral-payment-request/v1";
export const PAYMENT_REQUEST_ENVELOPE_SCHEMA = "clockchain.bilateral-payment-request-envelope/v1";
export const TRANSITION_SCHEMA = "clockchain.bilateral-transition/v1";
export const PARTY_SIGNATURE_SCHEMA = "clockchain.bilateral-party-signature/v1";
export const COMPLETION_MARKER_SCHEMA = "clockchain.bilateral-party-result-completion/v1";
export const RESULT_SCHEMA = "clockchain.handshake-result/v1";

const DESCRIPTOR_CHAIN_ID = "11155111";
const DESCRIPTOR_EXPIRY_SECONDS = "600";
const DESCRIPTOR_NAMESPACE = "cbv1";
const DESCRIPTOR_SETTLEMENT = "not-executed";
const REGISTRY_ADDRESS = "0x8004a818bfb912233c491871b3d84c89a494bd9e";
const OPERATOR_KEY_ALGORITHM = "ed25519";
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const MAX_CANONICAL_STRING_LENGTH = 256;
const MAX_CANONICAL_DEPTH = 32;
const HASH_PATTERN = /^[0-9a-f]{64}$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const INTAKE_UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SESSION_ID_PATTERN = /^[0-9a-f]{32}$/;
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const DECIMAL_INTEGER_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const DECIMAL_AMOUNT_PATTERN = /^(?:[1-9][0-9]*|(?:0|[1-9][0-9]*)\.[0-9]*[1-9])$/;
const PRINTABLE_ASCII_PATTERN = /^[ -~]*$/;
const SIGNATURE_PATTERN = /^0x[0-9a-f]{130}$/;
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const ARRAY_INDEX_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const BLOCK_TIME_PATTERN = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{1,9})Z$/;
const LIVE_UPPER_BOUND_SLACK_MS = 1100;
const EXPIRY_WINDOW_MS = 600000;
const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;
const CURRENCY_PATTERN = /^[A-Z]{3}$/;
const DISPLAY_NAME_PATTERN = /^[ -~]{1,64}$/;
const DECIMAL_QUANTITY_PATTERN = /^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/;
const RESULT_DISCLAIMER =
  "Single-validator testnet: anchored and independently re-verifiable; not mainnet, court-grade, consensus-secure, or trustless.";
const TRANSITION_KIND_ORDER = ["proposal", "acceptance", "acknowledgment"] as const;
const MS_PER_SECOND = 1000;
const MS_PER_MINUTE = 60 * MS_PER_SECOND;
const MS_PER_HOUR = 60 * MS_PER_MINUTE;
const MS_PER_DAY = 24 * MS_PER_HOUR;
const DAYS_IN_MONTH = Object.freeze([
  31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
]);

type JsonObject = Record<string, unknown>;
type AnyRecord = Record<string, any>;

export class HandshakeProtocolError extends Error {
  constructor(message: string, readonly code = "HANDSHAKE_PROTOCOL_INVALID") {
    super(message);
    this.name = new.target.name;
  }
}

function invalid(code = "HANDSHAKE_PROTOCOL_INVALID"): never {
  throw new HandshakeProtocolError("Handshake protocol validation failed.", code);
}

function isPlainObject(value: unknown): value is JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value: unknown, keys: readonly string[]): value is AnyRecord {
  if (!isPlainObject(value)) return false;
  const ownKeys = Reflect.ownKeys(value);
  return ownKeys.length === keys.length &&
    ownKeys.every((key) => typeof key === "string" && keys.includes(key)) &&
    keys.every((key) => {
      const property = Object.getOwnPropertyDescriptor(value, key);
      return property?.enumerable === true && Object.hasOwn(property, "value");
    });
}

function assertExactKeys(value: unknown, keys: readonly string[], code: string): asserts value is AnyRecord {
  if (!hasExactKeys(value, keys)) invalid(code);
}

function canonicalize(value: unknown, ancestors: Set<object>, depth: number): unknown {
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (
      value.length > MAX_CANONICAL_STRING_LENGTH ||
      value.trim() !== value ||
      !PRINTABLE_ASCII_PATTERN.test(value) ||
      (/^0[xX][0-9a-fA-F]{40}$/.test(value) && value !== value.toLowerCase())
    ) invalid("CANONICAL_STRING");
    return value;
  }
  if (typeof value === "number" || typeof value === "bigint") invalid("CANONICAL_NUMBER");
  if (typeof value !== "object" || value === null || depth > MAX_CANONICAL_DEPTH || ancestors.has(value)) {
    invalid("CANONICAL_VALUE");
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const keys = Reflect.ownKeys(value);
      if (
        keys.length !== value.length + 1 ||
        keys.some((key) => key !== "length" &&
          (typeof key !== "string" || !ARRAY_INDEX_PATTERN.test(key) || Number(key) >= value.length))
      ) invalid("CANONICAL_ARRAY");
      return value.map((entry) => canonicalize(entry, ancestors, depth + 1));
    }
    if (!isPlainObject(value)) invalid("CANONICAL_OBJECT");
    const result = Object.create(null) as AnyRecord;
    for (const key of Reflect.ownKeys(value).sort()) {
      if (typeof key !== "string" || key.length === 0 || DECIMAL_INTEGER_PATTERN.test(key)) {
        invalid("CANONICAL_KEY");
      }
      const property = Object.getOwnPropertyDescriptor(value, key);
      if (property?.enumerable !== true || !Object.hasOwn(property, "value")) invalid("CANONICAL_KEY");
      result[key] = canonicalize(property.value, ancestors, depth + 1);
    }
    return result;
  } finally {
    ancestors.delete(value);
  }
}

export function canonicalBytes(value: unknown): Buffer {
  if (!isPlainObject(value)) invalid("CANONICAL_TOP_LEVEL");
  return Buffer.from(JSON.stringify(canonicalize(value, new Set(), 1)), "utf8");
}

export function digestHex(value: unknown): string {
  return createHash("sha256").update(canonicalBytes(value)).digest("hex");
}

function decimal(value: unknown, amount = false): asserts value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_CANONICAL_STRING_LENGTH) invalid("DECIMAL");
  if (!(amount ? DECIMAL_AMOUNT_PATTERN : DECIMAL_INTEGER_PATTERN).test(value)) invalid("DECIMAL");
}

function printable(value: unknown, max = 128): asserts value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > max || value.trim() !== value || !/^[ -~]+$/.test(value)) {
    invalid("PRINTABLE");
  }
}

function party(value: unknown): { address: string; agentId: string } {
  assertExactKeys(value, ["address", "agentId"], "PARTY");
  if (typeof value.address !== "string" || !ADDRESS_PATTERN.test(value.address)) invalid("PARTY");
  decimal(value.agentId);
  return Object.freeze({ address: value.address, agentId: value.agentId });
}

function amount(value: unknown): { currency: string; value: string } {
  assertExactKeys(value, ["currency", "value"], "AMOUNT");
  if (value.currency !== "USD") invalid("AMOUNT");
  decimal(value.value);
  return Object.freeze({ currency: value.currency, value: value.value });
}

function assertEip191Signature(signature: unknown): asserts signature is string {
  if (typeof signature !== "string" || !SIGNATURE_PATTERN.test(signature)) invalid("EIP191_SIGNATURE");
}

export function preparePayerMandate(input: AnyRecord): Readonly<AnyRecord> {
  const payer = party(input.payer);
  const payee = party(input.payee);
  const amountValue = amount(input.amount);
  decimal(input.issuedAtMs);
  decimal(input.expiresAtMs);
  if (
    BigInt(input.issuedAtMs) >= BigInt(input.expiresAtMs) ||
    typeof input.intakeDigest !== "string" || !HASH_PATTERN.test(input.intakeDigest) ||
    typeof input.intakeRequestId !== "string" || !INTAKE_UUID_PATTERN.test(input.intakeRequestId) ||
    typeof input.repositorySha !== "string" || !SHA_PATTERN.test(input.repositorySha) ||
    typeof input.sessionId !== "string" || !UUID_PATTERN.test(input.sessionId) ||
    !["rehearsal", "stakeholder"].includes(input.subjectRun)
  ) invalid("PAYER_MANDATE");
  printable(input.invoiceReferencePrefix);
  printable(input.purpose);
  printable(input.releaseId);
  return Object.freeze({
    amount: amountValue,
    expiresAtMs: input.expiresAtMs,
    intakeDigest: input.intakeDigest,
    intakeRequestId: input.intakeRequestId,
    invoiceReferencePrefix: input.invoiceReferencePrefix,
    issuedAtMs: input.issuedAtMs,
    payee,
    payer,
    paymentMoved: false,
    protocol: BILATERAL_PROTOCOL,
    purpose: input.purpose,
    releaseId: input.releaseId,
    repositorySha: input.repositorySha,
    requestEndpoint: `/v1/sessions/${input.sessionId}/payment-requests`,
    schema: PAYER_MANDATE_SCHEMA,
    sessionId: input.sessionId,
    subjectRun: input.subjectRun,
  });
}

export function sealPayerMandate(mandate: AnyRecord, signatureValue: string): Readonly<AnyRecord> {
  const prepared = preparePayerMandate(mandate);
  assertEip191Signature(signatureValue);
  return Object.freeze({
    mandate: prepared,
    schema: PAYER_MANDATE_ENVELOPE_SCHEMA,
    signature: Object.freeze({
      address: prepared.payer.address,
      algorithm: "eip191",
      value: signatureValue,
    }),
  });
}

export function preparePaymentRequest(input: AnyRecord): Readonly<AnyRecord> {
  const payer = party(input.payer);
  const payee = party(input.payee);
  const amountValue = amount(input.amount);
  decimal(input.createdAtMs);
  decimal(input.expiresAtMs);
  if (
    BigInt(input.createdAtMs) >= BigInt(input.expiresAtMs) ||
    typeof input.intakeDigest !== "string" || !HASH_PATTERN.test(input.intakeDigest) ||
    typeof input.intakeRequestId !== "string" || !INTAKE_UUID_PATTERN.test(input.intakeRequestId) ||
    typeof input.mandateDigest !== "string" || !HASH_PATTERN.test(input.mandateDigest) ||
    typeof input.repositorySha !== "string" || !SHA_PATTERN.test(input.repositorySha) ||
    typeof input.requestId !== "string" || !UUID_PATTERN.test(input.requestId) ||
    typeof input.sessionId !== "string" || !UUID_PATTERN.test(input.sessionId) ||
    !["rehearsal", "stakeholder"].includes(input.subjectRun)
  ) invalid("PAYMENT_REQUEST");
  printable(input.invoiceReference);
  printable(input.purpose);
  printable(input.releaseId);
  return Object.freeze({
    amount: amountValue,
    createdAtMs: input.createdAtMs,
    expiresAtMs: input.expiresAtMs,
    intakeDigest: input.intakeDigest,
    intakeRequestId: input.intakeRequestId,
    invoiceReference: input.invoiceReference,
    mandateDigest: input.mandateDigest,
    payee,
    payer,
    paymentMoved: false,
    protocol: BILATERAL_PROTOCOL,
    purpose: input.purpose,
    releaseId: input.releaseId,
    repositorySha: input.repositorySha,
    requestId: input.requestId,
    schema: PAYMENT_REQUEST_SCHEMA,
    sessionId: input.sessionId,
    subjectRun: input.subjectRun,
  });
}

export function sealPaymentRequest(request: AnyRecord, signatureValue: string): Readonly<AnyRecord> {
  const prepared = preparePaymentRequest(request);
  assertEip191Signature(signatureValue);
  return Object.freeze({
    request: prepared,
    schema: PAYMENT_REQUEST_ENVELOPE_SCHEMA,
    signature: Object.freeze({
      address: prepared.payee.address,
      algorithm: "eip191",
      value: signatureValue,
    }),
  });
}

function rawPublicKeyBase64FromPem(publicKeyPem: string): string {
  const key = createPublicKey(publicKeyPem);
  if (key.asymmetricKeyType !== "ed25519") invalid("OPERATOR_PUBLIC_KEY");
  const der = key.export({ format: "der", type: "spki" });
  if (!Buffer.isBuffer(der) || der.length !== ED25519_SPKI_PREFIX.length + 32 || !der.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)) {
    invalid("OPERATOR_PUBLIC_KEY");
  }
  return der.subarray(ED25519_SPKI_PREFIX.length).toString("base64");
}

function publicKeyPemFromRawBase64(rawPublicKeyBase64: string): string {
  const raw = decodeRawPublicKey(rawPublicKeyBase64);
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
    format: "der",
    type: "spki",
  }).export({ format: "pem", type: "spki" }) as string;
}

function decodeRawPublicKey(rawPublicKeyBase64: string): Buffer {
  if (typeof rawPublicKeyBase64 !== "string" || rawPublicKeyBase64.length !== 44 || !BASE64_PATTERN.test(rawPublicKeyBase64)) {
    invalid("OPERATOR_PUBLIC_KEY");
  }
  const raw = Buffer.from(rawPublicKeyBase64, "base64");
  if (raw.length !== 32 || raw.toString("base64") !== rawPublicKeyBase64) invalid("OPERATOR_PUBLIC_KEY");
  return raw;
}

function validateDescriptorParty(value: unknown, role: "payer" | "payee"): void {
  assertExactKeys(value, ["address", "agentId", "displayName", "role"], "DESCRIPTOR_PARTY");
  if (
    typeof value.address !== "string" ||
    !ADDRESS_PATTERN.test(value.address) ||
    typeof value.agentId !== "string" ||
    !DECIMAL_INTEGER_PATTERN.test(value.agentId) ||
    typeof value.displayName !== "string" ||
    !DISPLAY_NAME_PATTERN.test(value.displayName) ||
    value.displayName.trim() !== value.displayName ||
    value.role !== role
  ) invalid("DESCRIPTOR_PARTY");
}

function compareAmountOptions(left: AnyRecord, right: AnyRecord): number {
  if (left.currency !== right.currency) return left.currency < right.currency ? -1 : 1;
  if (left.value === right.value) return 0;
  return left.value < right.value ? -1 : 1;
}

function validateDescriptorAmountOptions(options: unknown): asserts options is AnyRecord[] {
  if (!Array.isArray(options) || options.length === 0 || options.length > 8) invalid("DESCRIPTOR_AMOUNT_OPTIONS");
  const keys = Reflect.ownKeys(options);
  if (
    keys.length !== options.length + 1 ||
    keys.some((key) => key !== "length" && (typeof key !== "string" || !ARRAY_INDEX_PATTERN.test(key) || Number(key) >= options.length))
  ) invalid("DESCRIPTOR_AMOUNT_OPTIONS");
  for (let index = 0; index < options.length; index += 1) {
    const option = options[index];
    assertExactKeys(option, ["currency", "value"], "DESCRIPTOR_AMOUNT_OPTIONS");
    if (
      typeof option.currency !== "string" ||
      !CURRENCY_PATTERN.test(option.currency) ||
      typeof option.value !== "string" ||
      option.value.length === 0 ||
      option.value.length > MAX_CANONICAL_STRING_LENGTH ||
      !DECIMAL_AMOUNT_PATTERN.test(option.value)
    ) invalid("DESCRIPTOR_AMOUNT_OPTIONS");
    if (index > 0 && compareAmountOptions(options[index - 1], option) >= 0) invalid("DESCRIPTOR_AMOUNT_OPTIONS");
  }
}

function validateDescriptor(descriptor: AnyRecord): void {
  assertExactKeys(descriptor, [
    "amountOptions", "chainId", "expirySeconds", "mandateDigest", "namespace", "payee", "payer", "paymentMoved",
    "promptSha256", "protocol", "protocolVersion", "registry", "repositorySha", "requestDigest", "schema", "sessionId", "settlement",
  ], "DESCRIPTOR_SHAPE");
  if (
    descriptor.chainId !== DESCRIPTOR_CHAIN_ID ||
    descriptor.expirySeconds !== DESCRIPTOR_EXPIRY_SECONDS ||
    descriptor.namespace !== DESCRIPTOR_NAMESPACE ||
    descriptor.paymentMoved !== false ||
    descriptor.protocol !== BILATERAL_PROTOCOL ||
    descriptor.protocolVersion !== "1" ||
    descriptor.registry !== REGISTRY_ADDRESS ||
    descriptor.schema !== DESCRIPTOR_SCHEMA ||
    descriptor.settlement !== DESCRIPTOR_SETTLEMENT ||
    typeof descriptor.mandateDigest !== "string" || !HASH_PATTERN.test(descriptor.mandateDigest) ||
    typeof descriptor.requestDigest !== "string" || !HASH_PATTERN.test(descriptor.requestDigest) ||
    typeof descriptor.promptSha256 !== "string" || !HASH_PATTERN.test(descriptor.promptSha256) ||
    typeof descriptor.repositorySha !== "string" || !SHA_PATTERN.test(descriptor.repositorySha) ||
    typeof descriptor.sessionId !== "string" || !SESSION_ID_PATTERN.test(descriptor.sessionId) ||
    !Array.isArray(descriptor.amountOptions) ||
    descriptor.amountOptions.length === 0 ||
    descriptor.amountOptions.length > 8
  ) invalid("DESCRIPTOR_FIELD");
  validateDescriptorParty(descriptor.payer, "payer");
  validateDescriptorParty(descriptor.payee, "payee");
  if (descriptor.payer.address === descriptor.payee.address || descriptor.payer.agentId === descriptor.payee.agentId) {
    invalid("DESCRIPTOR_PARTY");
  }
  validateDescriptorAmountOptions(descriptor.amountOptions);
}

export function verifyDescriptorEnvelope(envelope: AnyRecord, { repositoryPublicKey }: { repositoryPublicKey: string }): Readonly<AnyRecord> {
  assertExactKeys(envelope, ["descriptor", "operator"], "DESCRIPTOR_ENVELOPE");
  assertExactKeys(envelope.operator, ["algorithm", "keyId", "publicKey", "signature"], "DESCRIPTOR_OPERATOR");
  if (
    envelope.operator.algorithm !== OPERATOR_KEY_ALGORITHM ||
    typeof envelope.operator.keyId !== "string" ||
    !KEY_ID_PATTERN.test(envelope.operator.keyId)
  ) invalid("DESCRIPTOR_OPERATOR");
  validateDescriptor(envelope.descriptor);
  const repositoryRaw = decodeRawPublicKey(repositoryPublicKey);
  const shippedRaw = decodeRawPublicKey(envelope.operator.publicKey);
  if (repositoryRaw.length !== shippedRaw.length || !timingSafeEqual(repositoryRaw, shippedRaw)) {
    invalid("OPERATOR_KEY_MISMATCH");
  }
  const signatureBytes = Buffer.from(envelope.operator.signature, "base64");
  if (
    signatureBytes.length !== 64 ||
    signatureBytes.toString("base64") !== envelope.operator.signature ||
    !verify(null, canonicalBytes(envelope.descriptor), createPublicKey(publicKeyPemFromRawBase64(repositoryPublicKey)), signatureBytes)
  ) invalid("DESCRIPTOR_SIGNATURE");
  return Object.freeze({
    descriptor: envelope.descriptor,
    sessionDigest: digestHex(envelope.descriptor),
  });
}

function frozenAmount(currency: string, value: string): Readonly<AnyRecord> {
  return Object.freeze({ currency, moved: false, value });
}

function frozenPayee(payeeValue: AnyRecord): Readonly<AnyRecord> {
  return Object.freeze({ address: payeeValue.address, agentId: payeeValue.agentId });
}

function frozenPayer(payerValue: AnyRecord): Readonly<AnyRecord> {
  return Object.freeze({
    address: payerValue.address,
    agentId: payerValue.agentId,
    reference: `eip155:${DESCRIPTOR_CHAIN_ID}:${REGISTRY_ADDRESS}:${payerValue.agentId}`,
  });
}

export function authoritativeTriple(input: AnyRecord): Readonly<AnyRecord> {
  assertExactKeys(input, ["anchoredHash", "blockHeight", "kind", "ledgerId"], "TRANSITION_TRIPLE");
  if (
    typeof input.anchoredHash !== "string" || !HASH_PATTERN.test(input.anchoredHash) ||
    typeof input.blockHeight !== "string" || !DECIMAL_INTEGER_PATTERN.test(input.blockHeight) ||
    typeof input.ledgerId !== "string" || !UUID_PATTERN.test(input.ledgerId) ||
    !["proposal", "acceptance", "acknowledgment"].includes(input.kind)
  ) invalid("TRANSITION_TRIPLE");
  return Object.freeze({
    anchoredHash: input.anchoredHash,
    blockHeight: input.blockHeight,
    kind: input.kind,
    ledgerId: input.ledgerId,
  });
}

export function buildProposal(input: AnyRecord): Readonly<AnyRecord> {
  validateDescriptor(input.descriptor);
  assertExactKeys(input.amount, ["currency", "value"], "TRANSITION_AMOUNT_OPTION");
  if (
    typeof input.amount.currency !== "string" ||
    !CURRENCY_PATTERN.test(input.amount.currency) ||
    typeof input.amount.value !== "string" ||
    !DECIMAL_AMOUNT_PATTERN.test(input.amount.value)
  ) invalid("TRANSITION_AMOUNT_OPTION");
  if (input.sessionDigest !== digestHex(input.descriptor)) invalid("TRANSITION_SESSION_DIGEST");
  if (!input.descriptor.amountOptions.some((option: AnyRecord) => option.currency === input.amount.currency && option.value === input.amount.value)) {
    invalid("TRANSITION_AMOUNT_OPTION");
  }
  return Object.freeze({
    amount: frozenAmount(input.amount.currency, input.amount.value),
    expirySeconds: input.descriptor.expirySeconds,
    kind: "proposal",
    payee: frozenPayee(input.descriptor.payee),
    payer: frozenPayer(input.descriptor.payer),
    predecessor: null,
    protocol: input.descriptor.protocol,
    schema: TRANSITION_SCHEMA,
    sequence: "1",
    sessionDigest: input.sessionDigest,
  });
}

export function buildAcceptance({ proposal, proposalTriple }: AnyRecord): Readonly<AnyRecord> {
  validateTransition(proposal);
  if (proposal?.kind !== "proposal" || proposalTriple?.kind !== "proposal" || proposalTriple.anchoredHash !== digestHex(proposal)) {
    invalid("TRANSITION_PROPOSAL");
  }
  return Object.freeze({
    amount: proposal.amount,
    expirySeconds: proposal.expirySeconds,
    payee: proposal.payee,
    payer: proposal.payer,
    protocol: proposal.protocol,
    schema: proposal.schema,
    sessionDigest: proposal.sessionDigest,
    decision: "ACCEPT",
    kind: "acceptance",
    predecessor: authoritativeTriple(proposalTriple),
    sequence: "2",
  });
}

export function buildAcknowledgment({ acceptance, acceptanceTriple, proposalTriple }: AnyRecord): Readonly<AnyRecord> {
  validateTransition(acceptance);
  if (
    acceptance?.kind !== "acceptance" ||
    acceptanceTriple?.kind !== "acceptance" ||
    proposalTriple?.kind !== "proposal" ||
    acceptanceTriple.anchoredHash !== digestHex(acceptance) ||
    !triplesEqual(acceptance.predecessor, proposalTriple)
  ) invalid("TRANSITION_ACCEPTANCE");
  return Object.freeze({
    amount: acceptance.amount,
    expirySeconds: acceptance.expirySeconds,
    payee: acceptance.payee,
    payer: acceptance.payer,
    protocol: acceptance.protocol,
    schema: acceptance.schema,
    sessionDigest: acceptance.sessionDigest,
    kind: "acknowledgment",
    outcome: "ACKNOWLEDGED",
    paymentMoved: false,
    predecessor: authoritativeTriple(acceptanceTriple),
    proposal: authoritativeTriple(proposalTriple),
    sequence: "3",
  });
}

export function sessionKey(sessionDigest: string, slot: "proposal" | "acceptance" | "acknowledgment"): string {
  if (!HASH_PATTERN.test(sessionDigest) || !["proposal", "acceptance", "acknowledgment"].includes(slot)) invalid("REFERENCE_ID");
  return `${DESCRIPTOR_NAMESPACE}:${sessionDigest}:${slot}`;
}

function transitionAmount(value: unknown): void {
  assertExactKeys(value, ["currency", "moved", "value"], "TRANSITION_AMOUNT");
  if (
    value.moved !== false ||
    typeof value.currency !== "string" ||
    !CURRENCY_PATTERN.test(value.currency) ||
    typeof value.value !== "string" ||
    !DECIMAL_AMOUNT_PATTERN.test(value.value)
  ) invalid("TRANSITION_AMOUNT");
}

function transitionPayee(value: unknown): void {
  assertExactKeys(value, ["address", "agentId"], "TRANSITION_PAYEE");
  if (
    typeof value.address !== "string" ||
    !ADDRESS_PATTERN.test(value.address) ||
    typeof value.agentId !== "string" ||
    !DECIMAL_INTEGER_PATTERN.test(value.agentId)
  ) invalid("TRANSITION_PAYEE");
}

function transitionPayer(value: unknown): void {
  assertExactKeys(value, ["address", "agentId", "reference"], "TRANSITION_PAYER");
  if (
    typeof value.address !== "string" ||
    !ADDRESS_PATTERN.test(value.address) ||
    typeof value.agentId !== "string" ||
    !DECIMAL_INTEGER_PATTERN.test(value.agentId) ||
    value.reference !== `eip155:${DESCRIPTOR_CHAIN_ID}:${REGISTRY_ADDRESS}:${value.agentId}`
  ) invalid("TRANSITION_PAYER");
}

function validateTransitionHead(message: AnyRecord): void {
  transitionAmount(message.amount);
  transitionPayee(message.payee);
  transitionPayer(message.payer);
  if (
    message.expirySeconds !== DESCRIPTOR_EXPIRY_SECONDS ||
    message.protocol !== BILATERAL_PROTOCOL ||
    message.schema !== TRANSITION_SCHEMA ||
    typeof message.sessionDigest !== "string" ||
    !HASH_PATTERN.test(message.sessionDigest) ||
    message.payee.address === message.payer.address ||
    message.payee.agentId === message.payer.agentId
  ) invalid("TRANSITION_HEAD");
}

function validateTriple(triple: unknown, expectedKind?: string): void {
  assertExactKeys(triple, ["anchoredHash", "blockHeight", "kind", "ledgerId"], "TRANSITION_TRIPLE");
  if (
    typeof triple.anchoredHash !== "string" ||
    !HASH_PATTERN.test(triple.anchoredHash) ||
    typeof triple.blockHeight !== "string" ||
    !DECIMAL_INTEGER_PATTERN.test(triple.blockHeight) ||
    typeof triple.ledgerId !== "string" ||
    !UUID_PATTERN.test(triple.ledgerId) ||
    !TRANSITION_KIND_ORDER.includes(triple.kind) ||
    (expectedKind !== undefined && triple.kind !== expectedKind)
  ) invalid("TRANSITION_TRIPLE");
}

function validateTransition(message: unknown): asserts message is AnyRecord {
  if (!isPlainObject(message)) invalid("TRANSITION_SHAPE");
  if (message.kind === "proposal") {
    assertExactKeys(message, ["amount", "expirySeconds", "kind", "payee", "payer", "predecessor", "protocol", "schema", "sequence", "sessionDigest"], "TRANSITION_SHAPE");
    validateTransitionHead(message);
    if (message.sequence !== "1" || message.predecessor !== null) invalid("TRANSITION_PROPOSAL");
    return;
  }
  if (message.kind === "acceptance") {
    assertExactKeys(message, ["amount", "decision", "expirySeconds", "kind", "payee", "payer", "predecessor", "protocol", "schema", "sequence", "sessionDigest"], "TRANSITION_SHAPE");
    validateTransitionHead(message);
    validateTriple(message.predecessor, "proposal");
    if (message.sequence !== "2" || message.decision !== "ACCEPT") invalid("TRANSITION_ACCEPTANCE");
    return;
  }
  if (message.kind === "acknowledgment") {
    assertExactKeys(message, ["amount", "expirySeconds", "kind", "outcome", "payee", "payer", "paymentMoved", "predecessor", "proposal", "protocol", "schema", "sequence", "sessionDigest"], "TRANSITION_SHAPE");
    validateTransitionHead(message);
    validateTriple(message.predecessor, "acceptance");
    validateTriple(message.proposal, "proposal");
    if (message.sequence !== "3" || message.outcome !== "ACKNOWLEDGED" || message.paymentMoved !== false) invalid("TRANSITION_ACKNOWLEDGMENT");
    return;
  }
  invalid("TRANSITION_KIND");
}

function triplesEqual(left: AnyRecord, right: AnyRecord): boolean {
  return ["anchoredHash", "blockHeight", "kind", "ledgerId"].every((key) => left?.[key] === right?.[key]);
}

function commonHeadMatches(left: AnyRecord, right: AnyRecord): boolean {
  return ["amount", "expirySeconds", "payee", "payer", "protocol", "schema", "sessionDigest"]
    .every((key) => {
      if (left[key] === null || typeof left[key] !== "object") return left[key] === right[key];
      if (right[key] === null || typeof right[key] !== "object") return false;
      return canonicalBytes(left[key]).equals(canonicalBytes(right[key]));
    });
}

function tripleFor(entry: AnyRecord, kind: string): AnyRecord {
  return {
    anchoredHash: entry.onChain.anchoredHash,
    blockHeight: entry.onChain.blockHeight,
    kind,
    ledgerId: entry.onChain.ledgerId,
  };
}

export function partySignatureBytes(input: AnyRecord): Buffer {
  assertExactKeys(input, ["role", "sessionDigest", "transitions"], "PARTY_SIGNATURE");
  if (!["payer", "payee"].includes(input.role) || typeof input.sessionDigest !== "string" || !HASH_PATTERN.test(input.sessionDigest)) {
    invalid("PARTY_SIGNATURE");
  }
  const transitions = validateTransitionEntries(input.transitions, input.sessionDigest);
  if ((input.role === "payer" && transitions.length !== 3) || (input.role === "payee" && (transitions.length < 2 || transitions.length > 3))) {
    invalid("PARTY_SIGNATURE");
  }
  const messages = input.role === "payer"
    ? [transitions[0]?.message, transitions[2]?.message]
    : [transitions[1]?.message];
  return canonicalBytes(Object.freeze({
    messages,
    role: input.role,
    schema: PARTY_SIGNATURE_SCHEMA,
    sessionDigest: input.sessionDigest,
  }));
}

function isLeapYear(year: number): boolean {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
}

function daysInMonth(year: number, month: number): number {
  if (month === 2 && isLeapYear(year)) return 29;
  return DAYS_IN_MONTH[month - 1] ?? 0;
}

function epochDays(year: number, month: number, day: number): number {
  const shiftedYear = month <= 2 ? year - 1 : year;
  const era = Math.floor(shiftedYear / 400);
  const yearOfEra = shiftedYear - era * 400;
  const dayOfYear =
    Math.trunc((153 * (month + (month > 2 ? -3 : 9)) + 2) / 5) + day - 1;
  const dayOfEra =
    yearOfEra * 365 +
    Math.trunc(yearOfEra / 4) -
    Math.trunc(yearOfEra / 100) +
    dayOfYear;
  return era * 146097 + dayOfEra - 719468;
}

function parseBlockTime(value: string): number {
  const match = BLOCK_TIME_PATTERN.exec(value);
  if (!match) invalid("BLOCK_TIME");
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > daysInMonth(year, month) ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  ) invalid("BLOCK_TIME");
  const milliseconds = Number(match[7].padEnd(3, "0").slice(0, 3));
  return (
    epochDays(year, month, day) * MS_PER_DAY +
    hour * MS_PER_HOUR +
    minute * MS_PER_MINUTE +
    second * MS_PER_SECOND +
    milliseconds
  );
}

function validateOnChain(value: unknown): void {
  assertExactKeys(value, ["anchoredHash", "blockHeight", "ledgerId"], "EVIDENCE_ON_CHAIN");
  if (
    typeof value.anchoredHash !== "string" ||
    !HASH_PATTERN.test(value.anchoredHash) ||
    typeof value.blockHeight !== "string" ||
    !DECIMAL_INTEGER_PATTERN.test(value.blockHeight) ||
    typeof value.ledgerId !== "string" ||
    !UUID_PATTERN.test(value.ledgerId)
  ) invalid("EVIDENCE_ON_CHAIN");
}

function validateTransitionEntries(transitions: unknown, sessionDigest: string): AnyRecord[] {
  if (!Array.isArray(transitions) || transitions.length > 3) invalid("EVIDENCE_TRANSITIONS");
  const parsedTimes: number[] = [];
  const ledgerIds = new Set<string>();
  let proposalDeadline: number | null = null;
  for (let index = 0; index < transitions.length; index += 1) {
    const entry = transitions[index];
    assertExactKeys(entry, ["blockTimeMs", "blockTimeRaw", "digest", "message", "onChain", "upperBoundMs"], "EVIDENCE_TRANSITION");
    validateOnChain(entry.onChain);
    validateTransition(entry.message);
    if (
      entry.message.kind !== TRANSITION_KIND_ORDER[index] ||
      entry.message.sequence !== String(index + 1) ||
      entry.message.sessionDigest !== sessionDigest ||
      typeof entry.digest !== "string" ||
      !HASH_PATTERN.test(entry.digest) ||
      entry.digest !== digestHex(entry.message) ||
      entry.digest !== entry.onChain.anchoredHash ||
      ledgerIds.has(entry.onChain.ledgerId)
    ) invalid("EVIDENCE_TRANSITION");
    ledgerIds.add(entry.onChain.ledgerId);
    const blockTimeMs = parseBlockTime(entry.blockTimeRaw);
    if (entry.blockTimeMs !== String(blockTimeMs)) invalid("EVIDENCE_BLOCK_TIME");
    parsedTimes.push(blockTimeMs);
    if (index === 0) {
      if (entry.upperBoundMs !== null) invalid("EVIDENCE_UPPER_BOUND");
      proposalDeadline = blockTimeMs + EXPIRY_WINDOW_MS;
    } else {
      const previous = transitions[index - 1];
      if (
        entry.upperBoundMs !== String(blockTimeMs + LIVE_UPPER_BOUND_SLACK_MS) ||
        proposalDeadline === null ||
        Number(entry.upperBoundMs) > proposalDeadline ||
        BigInt(previous.onChain.blockHeight) >= BigInt(entry.onChain.blockHeight) ||
        parsedTimes[index - 1] >= blockTimeMs ||
        !commonHeadMatches(transitions[0].message, entry.message) ||
        !triplesEqual(entry.message.predecessor, tripleFor(previous, TRANSITION_KIND_ORDER[index - 1]))
      ) invalid("EVIDENCE_CHAIN");
    }
  }
  if (transitions.length === 3 && !triplesEqual(transitions[2].message.proposal, tripleFor(transitions[0], "proposal"))) {
    invalid("EVIDENCE_CHAIN");
  }
  return transitions;
}

function decimalQuantityAtMost100(value: string): boolean {
  if (!DECIMAL_QUANTITY_PATTERN.test(value)) return false;
  const [integer, fraction = ""] = value.split(".");
  const integerValue = BigInt(integer);
  return integerValue < 100n || (integerValue === 100n && !/[1-9]/.test(fraction));
}

function rendezvousSentence(rendezvous: AnyRecord): string {
  if (rendezvous.channel === "derived-reference-id" && rendezvous.tenancy === "cross-client") {
    return "Peer evidence was discovered by derived reference ID across separate client tenancies.";
  }
  if (rendezvous.channel === "derived-reference-id") {
    return "Peer evidence was discovered by derived reference ID; separate-client tenancy was not proven.";
  }
  if (rendezvous.channel === "digest-hash") {
    return "Peer evidence was discovered by digest hash; Clockchain reference-ID rendezvous was not proven.";
  }
  return "Peer evidence was exchanged by out-of-band pointer; Clockchain rendezvous was not proven.";
}

function canonicalPrettyJson(snapshot: unknown): string {
  return `${JSON.stringify(JSON.parse(canonicalBytes(snapshot).toString("utf8")), null, 2)}\n`;
}

function renderPartyResultMarkdown(snapshot: AnyRecord): string {
  const transitionLines = snapshot.transitions.flatMap((entry: AnyRecord, index: number) => [
    `### ${index + 1}. ${entry.message.kind}`,
    "",
    `- Ledger ID: \`${entry.onChain.ledgerId}\``,
    `- Block height: \`${entry.onChain.blockHeight}\``,
    `- Digest: \`${entry.digest}\``,
    `- Block time: \`${entry.blockTimeRaw}\``,
    `- Upper bound: ${entry.upperBoundMs === null ? "not applicable" : `\`${entry.upperBoundMs}\``}`,
    "",
  ]);
  return [
    "# Bilateral party result",
    "",
    `- Role: \`${snapshot.role}\``,
    `- Local verdict: \`${snapshot.localVerdict}\``,
    "- Payment moved: no",
    `- Session digest: \`${snapshot.sessionDigest}\``,
    `- Repository SHA: \`${snapshot.repositorySha}\``,
    `- Prompt SHA-256: \`${snapshot.promptSha256}\``,
    `- Protocol version: \`${snapshot.protocolVersion}\``,
    "",
    "## Rendezvous",
    "",
    rendezvousSentence(snapshot.rendezvous),
    "",
    `- Channel: \`${snapshot.rendezvous.channel}\``,
    `- Tenancy: \`${snapshot.rendezvous.tenancy}\``,
    `- Degraded at submission: ${snapshot.rendezvous.degradedAtSubmission ? "yes" : "no"}`,
    "",
    "## Transition chain",
    "",
    `- Observed transitions: ${snapshot.transitions.length}`,
    `- Deadline: ${snapshot.deadlineMs === null ? "not established" : `\`${snapshot.deadlineMs}\``}`,
    `- Acknowledgment observed: ${snapshot.ackObserved ? "yes" : "no"}`,
    "",
    ...transitionLines,
    "## Validated JSON",
    "",
    "```json",
    canonicalPrettyJson(snapshot).trimEnd(),
    "```",
    "",
  ].join("\n");
}

export function buildEvidencePackage(result: AnyRecord): Readonly<{ json: string; markdown: string; marker: string }> {
  validatePartyResult(result);
  const json = canonicalPrettyJson(result);
  const markdown = renderPartyResultMarkdown(result);
  const marker = `${canonicalBytes({
    jsonSha256: createHash("sha256").update(json, "utf8").digest("hex"),
    markdownSha256: createHash("sha256").update(markdown, "utf8").digest("hex"),
    schema: COMPLETION_MARKER_SCHEMA,
  }).toString("utf8")}\n`;
  return Object.freeze({ json, markdown, marker });
}

function validatePartyResult(result: AnyRecord): void {
  assertExactKeys(result, ["ackObserved", "deadlineMs", "localVerdict", "paymentMoved", "poolHealth", "promptSha256", "protocolVersion", "rendezvous", "repositorySha", "role", "schema", "sessionDigest", "signature", "transitions"], "PARTY_RESULT");
  if (
    result.schema !== "clockchain.bilateral-party-result/v1" ||
    !["payer", "payee"].includes(result.role) ||
    !["LOCAL_OK", "RENDEZVOUS_UNAVAILABLE", "EXPIRED", "DUPLICATE", "AMBIGUOUS_WRITE", "BINDING_MISMATCH", "ANCHOR_UNVERIFIED", "RATE_BLOCKED", "AMOUNT_UNRESOLVED", "FAILED"].includes(result.localVerdict) ||
    result.paymentMoved !== false ||
    result.protocolVersion !== "1" ||
    typeof result.sessionDigest !== "string" ||
    !HASH_PATTERN.test(result.sessionDigest) ||
    typeof result.repositorySha !== "string" ||
    !SHA_PATTERN.test(result.repositorySha) ||
    typeof result.promptSha256 !== "string" ||
    !HASH_PATTERN.test(result.promptSha256) ||
    typeof result.ackObserved !== "boolean"
  ) invalid("PARTY_RESULT");
  assertExactKeys(result.poolHealth, ["degradedAtSubmission", "nodeParticipationPct", "totalNodes"], "PARTY_POOL_HEALTH");
  if (
    typeof result.poolHealth.degradedAtSubmission !== "boolean" ||
    typeof result.poolHealth.nodeParticipationPct !== "string" ||
    !decimalQuantityAtMost100(result.poolHealth.nodeParticipationPct) ||
    typeof result.poolHealth.totalNodes !== "string" ||
    !DECIMAL_QUANTITY_PATTERN.test(result.poolHealth.totalNodes)
  ) invalid("PARTY_POOL_HEALTH");
  assertExactKeys(result.rendezvous, ["channel", "degradedAtSubmission", "tenancy"], "PARTY_RENDEZVOUS");
  if (
    !["derived-reference-id", "digest-hash", "out-of-band-pointer"].includes(result.rendezvous.channel) ||
    !["same-client", "cross-client", "unknown"].includes(result.rendezvous.tenancy) ||
    typeof result.rendezvous.degradedAtSubmission !== "boolean" ||
    result.rendezvous.degradedAtSubmission !== result.poolHealth.degradedAtSubmission
  ) invalid("PARTY_RENDEZVOUS");
  assertExactKeys(result.signature, ["address", "algorithm", "signature"], "PARTY_SIGNATURE_BLOCK");
  if (
    result.signature.algorithm !== "eip191" ||
    typeof result.signature.address !== "string" ||
    !ADDRESS_PATTERN.test(result.signature.address) ||
    typeof result.signature.signature !== "string" ||
    !SIGNATURE_PATTERN.test(result.signature.signature)
  ) invalid("PARTY_SIGNATURE_BLOCK");
  const transitions = validateTransitionEntries(result.transitions, result.sessionDigest);
  if (transitions.length > 0) {
    const deadline = parseBlockTime(transitions[0].blockTimeRaw) + EXPIRY_WINDOW_MS;
    if (result.deadlineMs !== String(deadline)) invalid("PARTY_DEADLINE");
    const roleAddress = result.role === "payer" ? transitions[0].message.payer.address : transitions[0].message.payee.address;
    if (result.signature.address !== roleAddress) invalid("PARTY_SIGNATURE_BLOCK");
  } else if (result.deadlineMs !== null) {
    invalid("PARTY_DEADLINE");
  }
  if (
    result.ackObserved !== (transitions.length === 3) ||
    (result.localVerdict === "LOCAL_OK" &&
      ((result.role === "payer" && transitions.length !== 3) || (result.role === "payee" && transitions.length < 2)))
  ) invalid("PARTY_RESULT");
}

export function generateRelayKeyPair(): Readonly<{ privateKeyPem: string; publicKeyPem: string; senderKey: string }> {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" }) as string;
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }) as string;
  return Object.freeze({
    privateKeyPem,
    publicKeyPem,
    senderKey: rawPublicKeyBase64FromPem(publicKeyPem),
  });
}

export function signRelayEnvelope(input: AnyRecord): Readonly<AnyRecord> {
  if (typeof input.seq !== "string" || !DECIMAL_INTEGER_PATTERN.test(input.seq)) invalid("ENVELOPE_SHAPE");
  const key = createPrivateKey(input.privateKeyPem);
  if (key.asymmetricKeyType !== "ed25519") invalid("ENVELOPE_KEY");
  const preimage = {
    sessionId: input.sessionId,
    seq: input.seq,
    role: input.role,
    kind: input.kind,
    body: input.body,
  };
  return Object.freeze({
    ...preimage,
    senderKey: input.senderKey,
    sig: sign(null, canonicalBytes(preimage), key).toString("base64"),
  });
}

export function verifyResultEnvelope(envelope: AnyRecord, { expectedPublicKey = null }: { expectedPublicKey?: string | null } = {}): AnyRecord {
  validateResultEnvelope(envelope);
  if (expectedPublicKey !== null) {
    const given = decodeRawPublicKey(envelope.signer.publicKey);
    const expected = decodeRawPublicKey(expectedPublicKey);
    if (given.length !== expected.length || !timingSafeEqual(given, expected)) invalid("RESULT_SIGNER_KEY");
  }
  const signatureBytes = Buffer.from(envelope.signer.signature, "base64");
  if (
    signatureBytes.length !== 64 ||
    signatureBytes.toString("base64") !== envelope.signer.signature ||
    !verify(null, canonicalBytes(envelope.result), createPublicKey(publicKeyPemFromRawBase64(envelope.signer.publicKey)), signatureBytes)
  ) invalid("RESULT_SIGNATURE");
  return envelope.result;
}

function validateResultEnvelope(envelope: AnyRecord): void {
  assertExactKeys(envelope, ["result", "signer"], "RESULT_ENVELOPE");
  const { result, signer } = envelope;
  assertExactKeys(result, ["anchors", "disclaimer", "issuedAtMs", "outcome", "parties", "paymentMoved", "schema", "sessionDigest", "sessionId", "subjectRun"], "RESULT");
  if (
    result.schema !== RESULT_SCHEMA ||
    result.paymentMoved !== false ||
    typeof result.sessionId !== "string" ||
    !UUID_PATTERN.test(result.sessionId) ||
    typeof result.sessionDigest !== "string" ||
    !HASH_PATTERN.test(result.sessionDigest) ||
    typeof result.outcome !== "string" ||
    result.outcome.length === 0 ||
    typeof result.issuedAtMs !== "string" ||
    !DECIMAL_INTEGER_PATTERN.test(result.issuedAtMs) ||
    result.disclaimer !== RESULT_DISCLAIMER ||
    !["stakeholder", "rehearsal"].includes(result.subjectRun)
  ) invalid("RESULT");
  assertExactKeys(result.parties, ["payee", "payer"], "RESULT_PARTIES");
  for (const role of ["payer", "payee"] as const) {
    const partyValue = result.parties[role];
    assertExactKeys(partyValue, ["address", "agentId", "reference"], "RESULT_PARTY");
    if (
      typeof partyValue.address !== "string" ||
      !ADDRESS_PATTERN.test(partyValue.address) ||
      typeof partyValue.agentId !== "string" ||
      !DECIMAL_INTEGER_PATTERN.test(partyValue.agentId) ||
      typeof partyValue.reference !== "string" ||
      partyValue.reference.length === 0
    ) invalid("RESULT_PARTY");
  }
  if (!Array.isArray(result.anchors) || result.anchors.length !== 3) invalid("RESULT_ANCHORS");
  let previousHeight: bigint | null = null;
  for (let index = 0; index < result.anchors.length; index += 1) {
    const anchor = result.anchors[index];
    assertExactKeys(anchor, ["blockHeight", "blockTimeRaw", "digest", "kind", "ledgerId"], "RESULT_ANCHOR");
    if (
      anchor.kind !== TRANSITION_KIND_ORDER[index] ||
      typeof anchor.blockHeight !== "string" ||
      !DECIMAL_INTEGER_PATTERN.test(anchor.blockHeight) ||
      typeof anchor.blockTimeRaw !== "string" ||
      anchor.blockTimeRaw.length === 0 ||
      typeof anchor.digest !== "string" ||
      !HASH_PATTERN.test(anchor.digest) ||
      typeof anchor.ledgerId !== "string" ||
      !UUID_PATTERN.test(anchor.ledgerId)
    ) invalid("RESULT_ANCHOR");
    const height = BigInt(anchor.blockHeight);
    if (previousHeight !== null && height <= previousHeight) invalid("RESULT_ANCHOR");
    previousHeight = height;
  }
  assertExactKeys(signer, ["algorithm", "keyId", "publicKey", "signature"], "RESULT_SIGNER");
  if (
    signer.algorithm !== "ed25519" ||
    typeof signer.keyId !== "string" ||
    !KEY_ID_PATTERN.test(signer.keyId) ||
    typeof signer.publicKey !== "string" ||
    typeof signer.signature !== "string"
  ) invalid("RESULT_SIGNER");
  decodeRawPublicKey(signer.publicKey);
}

export function verifyRelayEnvelope(envelope: AnyRecord): boolean {
  assertExactKeys(envelope, ["sessionId", "seq", "role", "kind", "body", "senderKey", "sig"], "ENVELOPE_SHAPE");
  const signatureBytes = Buffer.from(envelope.sig, "base64");
  if (signatureBytes.length !== 64 || signatureBytes.toString("base64") !== envelope.sig) invalid("ENVELOPE_SIGNATURE");
  const preimage = {
    sessionId: envelope.sessionId,
    seq: envelope.seq,
    role: envelope.role,
    kind: envelope.kind,
    body: envelope.body,
  };
  if (!verify(null, canonicalBytes(preimage), createPublicKey(publicKeyPemFromRawBase64(envelope.senderKey)), signatureBytes)) {
    invalid("ENVELOPE_SIGNATURE");
  }
  return true;
}
