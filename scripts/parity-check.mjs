#!/usr/bin/env node
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

const DEFAULT_GCP_URL = "https://mcp.clockchain.network";
const DEFAULT_AWS_URL = "https://mcp-aws.clockchain.network";
const LOG_WAIT_MS = 15_000;
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_BYTES = 1_000_000;
const MAX_TIMEOUT_MS = 120_000;
const MAX_BYTES = 10_000_000;

function trimSlash(s) {
  return String(s ?? "").replace(/\/+$/, "");
}

function endpoint(base, path) {
  return `${trimSlash(base)}${path}`;
}

function sha256(s) {
  return createHash("sha256").update(s).digest("hex");
}

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function stableKeys(v) {
  return Object.keys(v).sort();
}

function shapeOf(v) {
  if (Array.isArray(v)) return ["array", v.length === 0 ? "empty" : shapeOf(v[0])];
  if (isPlainObject(v)) {
    return ["object", stableKeys(v).map((k) => [k, shapeOf(v[k])])];
  }
  if (v === null) return "null";
  return typeof v;
}

function canonicalJson(v) {
  if (Array.isArray(v)) return `[${v.map((item) => canonicalJson(item)).join(",")}]`;
  if (isPlainObject(v)) {
    return `{${stableKeys(v).map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(",")}}`;
  }
  return JSON.stringify(v);
}

function sameShape(a, b) {
  return JSON.stringify(shapeOf(a)) === JSON.stringify(shapeOf(b));
}

function publicShape(v) {
  return JSON.stringify(shapeOf(v));
}

function blockHeightOf(v) {
  if (!isPlainObject(v)) return undefined;
  return v.height ?? v.blockHeight;
}

function parsePositiveInteger(v) {
  const s = String(v ?? "");
  return /^(?:0|[1-9]\d*)$/.test(s) ? s : undefined;
}

function daysInMonth(year, month) {
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  return [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
}

function isValidGatewayDate(parts) {
  const [day, month, year, hour, minute, second, millis] = parts.map(Number);
  if (month < 1 || month > 12) return false;
  if (day < 1 || day > daysInMonth(year, month)) return false;
  if (hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59) return false;
  if (millis < 0 || millis > 999) return false;
  const ms = Date.UTC(year, month - 1, day, hour, minute, second, millis);
  const d = new Date(ms);
  return d.getUTCFullYear() === year &&
    d.getUTCMonth() === month - 1 &&
    d.getUTCDate() === day &&
    d.getUTCHours() === hour &&
    d.getUTCMinutes() === minute &&
    d.getUTCSeconds() === second &&
    d.getUTCMilliseconds() === millis;
}

function isValidRfc3339Date(s) {
  const match = s.match(
    /^(\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/,
  );
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  return day <= daysInMonth(year, month) && !Number.isNaN(Date.parse(s));
}

function parseClockTime(value) {
  const s = String(value ?? "");
  const gateway = s.match(
    /^(\d{2})-(\d{2})-(\d{4})[_ ](\d{2}):(\d{2}):(\d{2}):(\d{3})(?: UTC)?$/,
  );
  if (gateway) {
    if (!isValidGatewayDate(gateway.slice(1))) return NaN;
    const ms = Date.UTC(
      Number(gateway[3]),
      Number(gateway[2]) - 1,
      Number(gateway[1]),
      Number(gateway[4]),
      Number(gateway[5]),
      Number(gateway[6]),
      Number(gateway[7]),
    );
    return Number.isNaN(ms) ? NaN : ms;
  }
  if (isValidRfc3339Date(s)) return Date.parse(s);
  const n = Number(s);
  if (!Number.isNaN(n) && n > 0) return n > 1e12 ? n : n * 1000;
  return NaN;
}

function parseHeaders(headers) {
  const out = {};
  for (const name of ["x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset"]) {
    const value = headers.get(name);
    if (value != null) out[name] = value;
  }
  return out;
}

function requiredNumericHeader(headers, name) {
  if (!(name in headers)) return undefined;
  const n = Number(headers[name]);
  return Number.isFinite(n) ? n : undefined;
}

async function readBounded(res, maxBytes) {
  const reader = res.body?.getReader?.();
  if (!reader) {
    const text = await res.text();
    if (Buffer.byteLength(text, "utf8") > maxBytes) throw new Error("response too large");
    return text;
  }

  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel();
      throw new Error("response too large");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function boundedFetch(url, opts, limits) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error("request timed out")), limits.timeoutMs);
  try {
    const res = await (limits.fetchImpl ?? fetch)(url, { ...opts, signal: controller.signal });
    const text = await readBounded(res, limits.maxBytes);
    return { res, text };
  } finally {
    clearTimeout(timer);
  }
}

function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new Error(`invalid JSON response: ${err instanceof Error ? err.message : String(err)}`);
  }
}

function parseSse(text, wantedId) {
  const events = text.split(/\r?\n(?:\r?\n)+/);
  for (const event of events) {
    const data = event
      .split(/\r?\n/)
      .filter((line) => line.trimStart().startsWith("data:"))
      .map((line) => line.replace(/^\s*data:\s?/, ""))
      .join("\n")
      .trim();
    if (!data) continue;
    const rpc = parseJson(data);
    if (wantedId === undefined || rpc?.id === wantedId) return rpc;
  }
  throw new Error("SSE response did not contain the matching JSON-RPC response");
}

function parseRpcResponse(contentType, text, wantedId) {
  const rpc = contentType.includes("text/event-stream") ? parseSse(text, wantedId) : parseJson(text);
  if (rpc.error) throw new Error("MCP JSON-RPC error");
  if (wantedId !== undefined && rpc.id !== wantedId) {
    throw new Error("MCP JSON-RPC response id mismatch");
  }
  return rpc.result;
}

function toolPayload(result) {
  if (result?.isError) throw new Error("MCP tool returned an error");
  const text = Array.isArray(result?.content)
    ? result.content.filter((c) => c?.type === "text").map((c) => c.text).join("\n")
    : "";
  if (!text) return result;
  return parseJson(text);
}

async function fetchJson(baseUrl, path, opts, limits) {
  const { res, text } = await boundedFetch(endpoint(baseUrl, path), opts, limits);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return { body: parseJson(text), headers: parseHeaders(res.headers), status: res.status };
}

async function callTool(baseUrl, token, name, args, limits) {
  const id = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const { res, text } = await boundedFetch(endpoint(baseUrl, "/mcp"), {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      "x-api-key": token,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id,
      method: "tools/call",
      params: { name, arguments: args ?? {} },
    }),
  }, limits);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return toolPayload(parseRpcResponse(res.headers.get("content-type") ?? "", text, id));
}

function compareShape(row, gcp, aws) {
  if (!sameShape(gcp, aws)) {
    return { ok: false, detail: `${row} shape mismatch gcp=${publicShape(gcp)} aws=${publicShape(aws)}` };
  }
  return { ok: true };
}

function compareToken(row, gcp, aws, previous, sharedBackend = false) {
  const shapeGcp = { ...gcp.body, token: "<redacted>" };
  const shapeAws = { ...aws.body, token: "<redacted>" };
  const shape = compareShape(row, shapeGcp, shapeAws);
  if (!shape.ok) return shape;
  if (typeof gcp.body?.token !== "string" || typeof aws.body?.token !== "string") {
    return { ok: false, detail: `${row} did not return usable tokens` };
  }
  const gcpLimit = requiredNumericHeader(gcp.headers, "x-ratelimit-limit");
  const awsLimit = requiredNumericHeader(aws.headers, "x-ratelimit-limit");
  const gcpRemaining = requiredNumericHeader(gcp.headers, "x-ratelimit-remaining");
  const awsRemaining = requiredNumericHeader(aws.headers, "x-ratelimit-remaining");
  if (
    gcpLimit === undefined ||
    awsLimit === undefined ||
    gcpRemaining === undefined ||
    awsRemaining === undefined
  ) {
    return { ok: false, detail: `${row} missing or invalid quota headers` };
  }
  const gcpReset = "x-ratelimit-reset" in gcp.headers
    ? requiredNumericHeader(gcp.headers, "x-ratelimit-reset")
    : 0;
  const awsReset = "x-ratelimit-reset" in aws.headers
    ? requiredNumericHeader(aws.headers, "x-ratelimit-reset")
    : 0;
  if (gcpReset === undefined || awsReset === undefined) {
    return { ok: false, detail: `${row} invalid quota reset header` };
  }
  if (gcpLimit !== awsLimit) {
    return { ok: false, detail: `${row} quota limit mismatch` };
  }
  if (sharedBackend) {
    if (Math.abs(gcpRemaining - awsRemaining) !== 1) {
      return { ok: false, detail: `${row} shared quota did not consume consecutive slots` };
    }
    if (previous) {
      const previousRemaining = [
        requiredNumericHeader(previous.gcp.headers, "x-ratelimit-remaining"),
        requiredNumericHeader(previous.aws.headers, "x-ratelimit-remaining"),
      ];
      if (previousRemaining.some((value) => value === undefined)) {
        return { ok: false, detail: `${row} missing previous quota headers` };
      }
      const previousSorted = previousRemaining.sort((a, b) => b - a);
      const currentSorted = [gcpRemaining, awsRemaining].sort((a, b) => b - a);
      if (
        previousSorted[0] - currentSorted[0] !== 2 ||
        previousSorted[1] - currentSorted[1] !== 2
      ) {
        return { ok: false, detail: `${row} shared quota did not decrement by two` };
      }
    }
    return { ok: true };
  }
  if (previous) {
    const prevGcpRemaining = requiredNumericHeader(previous.gcp.headers, "x-ratelimit-remaining");
    const prevAwsRemaining = requiredNumericHeader(previous.aws.headers, "x-ratelimit-remaining");
    if (prevGcpRemaining === undefined || prevAwsRemaining === undefined) {
      return { ok: false, detail: `${row} missing previous quota headers` };
    }
    const gcpDelta = prevGcpRemaining - gcpRemaining;
    const awsDelta = prevAwsRemaining - awsRemaining;
    if (gcpDelta !== 1 || awsDelta !== 1) {
      return { ok: false, detail: `${row} quota did not decrement by one` };
    }
    if (gcpDelta !== awsDelta) {
      return { ok: false, detail: `${row} quota movement mismatch` };
    }
  }
  return { ok: true };
}

function consensusTimeOf(v) {
  if (!isPlainObject(v)) return "";
  for (const key of ["madMarzulloTime", "latestBlockTime", "consensusTime", "timestamp"]) {
    if (typeof v[key] === "string" && v[key].trim() !== "") return v[key];
  }
  return "";
}

function validClockTime(v) {
  return Number.isFinite(parseClockTime(v));
}

function normalizeValue(v) {
  if (Array.isArray(v)) return v.map((item) => normalizeValue(item));
  if (isPlainObject(v)) {
    return Object.fromEntries(stableKeys(v).map((k) => [k, normalizeValue(v[k])]));
  }
  return v;
}

function compareTimestamp(row, gcp, aws) {
  const shape = compareShape(row, gcp, aws);
  if (!shape.ok) return shape;
  const gcpHeight = parsePositiveInteger(blockHeightOf(gcp));
  const awsHeight = parsePositiveInteger(blockHeightOf(aws));
  if (gcpHeight === undefined || awsHeight === undefined) {
    return { ok: false, detail: `${row} blockHeight is not canonical` };
  }
  if (!validClockTime(consensusTimeOf(gcp)) || !validClockTime(consensusTimeOf(aws))) {
    return { ok: false, detail: `${row} consensus time invalid` };
  }
  return { ok: true };
}

function compareHealth(row, gcp, aws) {
  const shape = compareShape(row, gcp, aws);
  if (!shape.ok) return shape;
  if (gcp?.status !== aws?.status || gcp?.status !== "ok") {
    return { ok: false, detail: `${row} status mismatch` };
  }
  return { ok: true };
}

function compareBlock(row, gcp, aws, wantedHeight) {
  const shape = compareShape(row, gcp, aws);
  if (!shape.ok) return shape;
  const gcpHeight = parsePositiveInteger(blockHeightOf(gcp));
  const awsHeight = parsePositiveInteger(blockHeightOf(aws));
  if (gcpHeight !== String(wantedHeight) || awsHeight !== String(wantedHeight)) {
    return { ok: false, detail: `${row} height mismatch` };
  }
  if (!validClockTime(gcp?.blockTime) || !validClockTime(aws?.blockTime)) {
    return { ok: false, detail: `${row} blockTime invalid` };
  }
  const normalizeBlock = (block) => {
    const normalized = normalizeValue(block);
    if (Object.hasOwn(normalized, "height")) normalized.height = parsePositiveInteger(normalized.height);
    if (Object.hasOwn(normalized, "blockHeight")) normalized.blockHeight = parsePositiveInteger(normalized.blockHeight);
    if (Object.hasOwn(normalized, "blockTime")) normalized.blockTime = parseClockTime(normalized.blockTime);
    return normalized;
  };
  if (canonicalJson(normalizeBlock(gcp)) !== canonicalJson(normalizeBlock(aws))) {
    return { ok: false, detail: `${row} immutable block mismatch` };
  }
  return { ok: true };
}

function validateDynamicLogFields(row, name, entry) {
  if (!isPlainObject(entry)) return { ok: false, detail: `${row} ${name} log response invalid` };
  if (entry.ledgerId !== undefined && typeof entry.ledgerId !== "string") {
    return { ok: false, detail: `${row} ${name} ledgerId invalid` };
  }
  for (const key of ["createdTimestamp", "updatedTimestamp"]) {
    if (entry[key] !== undefined && entry[key] !== null && !validClockTime(entry[key])) {
      return { ok: false, detail: `${row} ${name} ${key} invalid` };
    }
  }
  return { ok: true };
}

function normalizeLogResponse(row, name, v, reference, actionHash) {
  const dynamic = validateDynamicLogFields(row, name, v);
  if (!dynamic.ok) return dynamic;
  const entry = { ...v };
  delete entry.ledgerId;
  delete entry.id;
  delete entry.createdTimestamp;
  delete entry.updatedTimestamp;
  if (entry.assetReferenceId !== reference) return { ok: false, detail: `${row} ${name} reference mismatch` };
  if (entry.assetHash !== actionHash) return { ok: false, detail: `${row} ${name} hash mismatch` };
  if (entry.hashType !== "SHA-256") return { ok: false, detail: `${row} ${name} hashType mismatch` };
  if (!parsePositiveInteger(entry.blockHeight)) return { ok: false, detail: `${row} ${name} blockHeight invalid` };
  if (entry.status !== "anchored") return { ok: false, detail: `${row} ${name} status invalid` };
  entry.blockHeight = "<positive-integer>";
  return { ok: true, value: normalizeValue(entry) };
}

function compareDirectLogs(row, awsWrite, gcpWrite, reference, actionHash) {
  const aws = normalizeLogResponse(row, "aws", awsWrite, reference, actionHash);
  if (!aws.ok) return aws;
  const gcp = normalizeLogResponse(row, "gcp", gcpWrite, reference, actionHash);
  if (!gcp.ok) return gcp;
  const shape = compareShape(row, aws.value, gcp.value);
  if (!shape.ok) return shape;
  if (canonicalJson(aws.value) !== canonicalJson(gcp.value)) {
    return { ok: false, detail: `${row} semantic mismatch` };
  }
  return { ok: true };
}

function compareLogEntry(row, written, read, reference, actionHash) {
  if (!sameShape(written, read)) {
    return { ok: false, detail: `${row} shape mismatch written=${publicShape(written)} read=${publicShape(read)}` };
  }
  for (const key of ["assetReferenceId", "assetHash", "hashType"]) {
    if (written?.[key] !== read?.[key]) return { ok: false, detail: `${row} ${key} mismatch` };
  }
  if (written?.assetReferenceId !== reference) return { ok: false, detail: `${row} reference mismatch` };
  if (written?.assetHash !== actionHash) return { ok: false, detail: `${row} hash mismatch` };
  if (!parsePositiveInteger(written?.blockHeight) || !parsePositiveInteger(read?.blockHeight)) {
    return { ok: false, detail: `${row} is not anchored` };
  }
  return { ok: true };
}

function writeRow(stdout, name, result) {
  const status = result.skipped ? "SKIP" : result.ok ? "PASS" : "FAIL";
  stdout.write(`${name.padEnd(24)} ${status}${result.detail ? `  ${result.detail}` : ""}\n`);
}

async function row(name, stdout, fn) {
  try {
    const result = await fn();
    writeRow(stdout, name, result);
    return result;
  } catch (err) {
    const result = { ok: false, detail: `${name} error: ${err instanceof Error ? err.message : String(err)}` };
    writeRow(stdout, name, result);
    return result;
  }
}

function requireOption(value, name) {
  if (value === undefined || value === null || String(value).trim() === "") {
    throw new Error(`${name} is required`);
  }
  return String(value);
}

function positiveBoundedNumber(value, name, max) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0 || n > max) {
    throw new Error(`${name} must be a positive number <= ${max}`);
  }
  return n;
}

function booleanOption(value, name) {
  if (value === undefined || value === null || value === false || value === "false") return false;
  if (value === true || value === "true") return true;
  throw new Error(`${name} must be true or false`);
}

function anyFailed(results) {
  return results.some((r) => !r.ok);
}

function skip(detail) {
  return { ok: false, skipped: true, detail };
}

export async function runParity(options = {}) {
  const stdout = options.stdout ?? process.stdout;
  const limits = {
    timeoutMs: positiveBoundedNumber(options.timeoutMs ?? DEFAULT_TIMEOUT_MS, "timeoutMs", MAX_TIMEOUT_MS),
    maxBytes: positiveBoundedNumber(options.maxBytes ?? DEFAULT_MAX_BYTES, "maxBytes", MAX_BYTES),
    fetchImpl: options.fetchImpl,
  };
  const writeLimits = {
    ...limits,
    timeoutMs: Math.max(limits.timeoutMs, LOG_WAIT_MS + 5_000),
  };
  const gcpBaseUrl = options.gcpBaseUrl ?? DEFAULT_GCP_URL;
  const awsBaseUrl = options.awsBaseUrl ?? DEFAULT_AWS_URL;
  const blockHeight = requireOption(options.blockHeight, "blockHeight");
  const reference = requireOption(options.reference, "reference");
  const action = requireOption(options.action, "action");
  const allowDegraded = booleanOption(options.allowDegraded, "allowDegraded");
  const sharedBackend = booleanOption(options.sharedBackend, "sharedBackend");
  const actionHash = sha256(action);
  const results = [];

  let firstMint;
  let secondMint;
  let gcpToken;
  let awsToken;

  results.push(await row("health", stdout, async () => {
    const [gcp, aws] = await Promise.all([
      fetchJson(gcpBaseUrl, "/health", { method: "GET" }, limits),
      fetchJson(awsBaseUrl, "/health", { method: "GET" }, limits),
    ]);
    return compareHealth("health", gcp.body, aws.body);
  }));

  results.push(await row("token mint 1", stdout, async () => {
    firstMint = await Promise.all([
      fetchJson(gcpBaseUrl, "/token", { method: "POST" }, limits),
      fetchJson(awsBaseUrl, "/token", { method: "POST" }, limits),
    ]);
    gcpToken = firstMint[0].body.token;
    awsToken = firstMint[1].body.token;
    return compareToken("token mint 1", firstMint[0], firstMint[1], undefined, sharedBackend);
  }));

  results.push(await row("token mint 2", stdout, async () => {
    if (!firstMint) return { ok: false, detail: "token mint 2 skipped after token mint 1 failure" };
    secondMint = await Promise.all([
      fetchJson(gcpBaseUrl, "/token", { method: "POST" }, limits),
      fetchJson(awsBaseUrl, "/token", { method: "POST" }, limits),
    ]);
    return compareToken(
      "token mint 2",
      secondMint[0],
      secondMint[1],
      { gcp: firstMint[0], aws: firstMint[1] },
      sharedBackend,
    );
  }));

  results.push(await row("get_timestamp", stdout, async () => {
    if (!gcpToken || !awsToken) return { ok: false, detail: "get_timestamp skipped without minted tokens" };
    const [gcp, aws] = await Promise.all([
      callTool(gcpBaseUrl, gcpToken, "get_timestamp", {}, limits),
      callTool(awsBaseUrl, awsToken, "get_timestamp", {}, limits),
    ]);
    return compareTimestamp("get_timestamp", gcp, aws);
  }));

  results.push(await row("get_block", stdout, async () => {
    if (!gcpToken || !awsToken) return { ok: false, detail: "get_block skipped without minted tokens" };
    const [gcp, aws] = await Promise.all([
      callTool(gcpBaseUrl, gcpToken, "get_block", { height: blockHeight }, limits),
      callTool(awsBaseUrl, awsToken, "get_block", { height: blockHeight }, limits),
    ]);
    return compareBlock("get_block", gcp, aws, blockHeight);
  }));

  let awsWrite;
  let gcpWrite;
  results.push(await row("log_action aws->gcp", stdout, async () => {
    if (anyFailed(results)) return skip("log_action aws->gcp skipped after pre-write failure");
    if (!gcpToken || !awsToken) return { ok: false, detail: "log_action aws->gcp skipped without minted tokens" };
    awsWrite = await callTool(awsBaseUrl, awsToken, "log_action", {
      content: action,
      asset_reference_id: reference,
      wait: true,
      wait_ms: LOG_WAIT_MS,
      idempotency_key: `parity:${reference}:aws`,
      ...(allowDegraded ? { allow_degraded: true } : {}),
    }, writeLimits);
    const read = await callTool(gcpBaseUrl, gcpToken, "get_log_entry", {
      ledger_id: awsWrite.ledgerId,
    }, limits);
    return compareLogEntry("log_action aws->gcp", awsWrite, read, reference, actionHash);
  }));

  results.push(await row("log_action gcp->aws", stdout, async () => {
    if (anyFailed(results)) return skip("log_action gcp->aws skipped after pre-write failure");
    if (!gcpToken || !awsToken) return { ok: false, detail: "log_action gcp->aws skipped without minted tokens" };
    gcpWrite = await callTool(gcpBaseUrl, gcpToken, "log_action", {
      content: action,
      asset_reference_id: reference,
      wait: true,
      wait_ms: LOG_WAIT_MS,
      idempotency_key: `parity:${reference}:gcp`,
      ...(allowDegraded ? { allow_degraded: true } : {}),
    }, writeLimits);
    const read = await callTool(awsBaseUrl, awsToken, "get_log_entry", {
      ledger_id: gcpWrite.ledgerId,
    }, limits);
    return compareLogEntry("log_action gcp->aws", gcpWrite, read, reference, actionHash);
  }));

  results.push(await row("log_action compare", stdout, async () => {
    if (anyFailed(results)) return skip("log_action compare skipped after write failure");
    return compareDirectLogs("log_action compare", awsWrite, gcpWrite, reference, actionHash);
  }));

  const ok = results.every((r) => r.ok);
  stdout.write(`\nresult ${ok ? "PASS" : "FAIL"}\n`);
  return { ok, results };
}

function parseArgs(argv, env) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("--")) throw new Error(`unknown argument ${arg}`);
    const key = arg.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    const next = argv[i + 1];
    if (next === undefined || next.startsWith("--")) throw new Error(`missing value for ${arg}`);
    args[key] = next;
    i++;
  }
  return {
    gcpBaseUrl: args.gcpUrl ?? env.PARITY_GCP_URL ?? DEFAULT_GCP_URL,
    awsBaseUrl: args.awsUrl ?? env.PARITY_AWS_URL ?? DEFAULT_AWS_URL,
    blockHeight: args.blockHeight ?? env.PARITY_BLOCK_HEIGHT,
    reference: args.reference ?? env.PARITY_REFERENCE,
    action: args.action ?? env.PARITY_ACTION,
    allowDegraded: args.allowDegraded ?? env.PARITY_ALLOW_DEGRADED,
    sharedBackend: args.sharedBackend ?? env.PARITY_SHARED_BACKEND,
    timeoutMs: args.timeoutMs ?? env.PARITY_TIMEOUT_MS ?? DEFAULT_TIMEOUT_MS,
    maxBytes: args.maxBytes ?? env.PARITY_MAX_BYTES ?? DEFAULT_MAX_BYTES,
  };
}

async function main() {
  try {
    const result = await runParity(parseArgs(process.argv.slice(2), process.env));
    process.exitCode = result.ok ? 0 : 1;
  } catch (err) {
    process.stderr.write(`parity-check: ${err instanceof Error ? err.message : String(err)}\n`);
    process.stderr.write(
      "usage: node scripts/parity-check.mjs --block-height <height> --reference <unique-ref> --action <harmless-action> " +
        "[--gcp-url <url>] [--aws-url <url>] [--allow-degraded <true|false>] " +
        "[--shared-backend <true|false>] " +
        "[--timeout-ms <ms>] [--max-bytes <bytes>]\n",
    );
    process.exitCode = 2;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await main();
}
