import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

/**
 * LLM-driven agent: MiniMax (the same model Clark uses) reasons and drives the
 * Clockchain tools over MCP. This is the "LLM drives MCP" path, in the browser.
 *
 * The web backend is an MCP client to our own stdio MCP server; MiniMax is the
 * brain. Every tool the model calls goes through the real MCP transport.
 */

const MM_BASE = process.env.MINIMAX_BASE_URL || "https://api.minimaxi.com/anthropic";
const MM_KEY = process.env.MINIMAX_CN_API_KEY || process.env.MINIMAX_API_KEY || "";
const MM_MODEL = process.env.MINIMAX_MODEL || "MiniMax-M2.7-highspeed";

// The built MCP stdio server (sibling package), overridable for deployment.
const MCP_SERVER_PATH =
  process.env.MCP_SERVER_PATH ||
  new URL("../../mcp-server/dist/stdio.js", import.meta.url).pathname;

// Only expose the read + attest tools to the agent (keep it on-rails).
const ALLOWED_TOOLS = new Set(["get_time", "attest_action", "verify_receipt", "get_timestamp", "resolve_agent"]);

const SYSTEM_PROMPT =
  "You are an autonomous treasury agent operating on behalf of a company. You can " +
  "read Clockchain's decentralized consensus time and attest actions on-chain. " +
  "When asked to perform an action: briefly state your reasoning, then call " +
  "attest_action with a clear agent_id, the action name, and the exact inputs and " +
  "outputs of your decision. After it succeeds, confirm in one sentence citing the " +
  "receipt's ledgerId and block height. Be concise.";

export const llmConfigured = (): boolean => MM_KEY.length > 0;

let clientPromise: Promise<Client> | null = null;
function mcpClient(): Promise<Client> {
  if (!clientPromise) {
    const transport = new StdioClientTransport({
      command: process.execPath, // node
      args: [MCP_SERVER_PATH],
      env: { ...process.env, MCP_LOG: "off" },
    });
    const c = new Client({ name: "web-demo-agent", version: "1.0.0" }, { capabilities: {} });
    clientPromise = c.connect(transport).then(() => c);
  }
  return clientPromise;
}

export type AgentEvent =
  | { type: "thinking"; text: string }
  | { type: "text"; text: string }
  | { type: "tool_use"; name: string; input: unknown }
  | { type: "tool_result"; name: string; content: string }
  | { type: "error"; text: string };

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// The MiniMax endpoint can be flaky from a remote host (transient "fetch failed",
// resets, 429/5xx). Retry with backoff + a per-attempt timeout so one blip doesn't
// surface to the user as a failed turn.
async function callMiniMax(body: unknown, attempt = 0): Promise<any> {
  const MAX_RETRIES = 3;
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 60_000);
    let res: Response;
    try {
      res = await fetch(`${MM_BASE}/v1/messages`, {
        method: "POST",
        headers: {
          "x-api-key": MM_KEY,
          "anthropic-version": "2023-06-01",
          "content-type": "application/json",
        },
        body: JSON.stringify(body),
        signal: ctrl.signal,
      });
    } finally {
      clearTimeout(timer);
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      if ((res.status === 429 || res.status >= 500) && attempt < MAX_RETRIES) {
        await sleep(500 * 2 ** attempt);
        return callMiniMax(body, attempt + 1);
      }
      throw new Error(`LLM error ${res.status}: ${JSON.stringify(data).slice(0, 200)}`);
    }
    return data;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const transient = /abort|fetch failed|terminated|ECONNRESET|ETIMEDOUT|EAI_AGAIN|network|socket|timeout/i.test(msg);
    if (transient && attempt < MAX_RETRIES) {
      await sleep(500 * 2 ** attempt);
      return callMiniMax(body, attempt + 1);
    }
    throw err;
  }
}

/**
 * Run one chat turn: append the user's message to the running conversation,
 * let MiniMax reason and drive the MCP tools, and return the events produced this
 * turn plus any receipt. `messages` is the per-session history, mutated in place.
 */
export async function runTurn(
  messages: any[],
  userText: string,
): Promise<{ events: AgentEvent[]; receipt: unknown | null }> {
  if (!llmConfigured()) throw new Error("LLM is not configured (MINIMAX_CN_API_KEY unset).");

  const client = await mcpClient();
  const listed = await client.listTools();
  const tools = listed.tools
    .filter((t) => ALLOWED_TOOLS.has(t.name))
    .map((t) => ({ name: t.name, description: t.description ?? "", input_schema: t.inputSchema }));

  const transcript: AgentEvent[] = [];
  let receipt: unknown | null = null;
  messages.push({ role: "user", content: userText });

  for (let turn = 0; turn < 6; turn++) {
    const resp = await callMiniMax({
      model: MM_MODEL,
      max_tokens: 1500,
      system: SYSTEM_PROMPT,
      tools,
      messages,
    });

    const content: any[] = resp.content ?? [];
    for (const block of content) {
      if (block.type === "thinking" && block.thinking) transcript.push({ type: "thinking", text: block.thinking });
      else if (block.type === "text" && block.text) transcript.push({ type: "text", text: block.text });
      else if (block.type === "tool_use") transcript.push({ type: "tool_use", name: block.name, input: block.input });
    }
    messages.push({ role: "assistant", content });

    if (resp.stop_reason !== "tool_use") break;

    const toolResults: any[] = [];
    for (const block of content) {
      if (block.type !== "tool_use") continue;
      try {
        const result = await client.callTool({ name: block.name, arguments: block.input ?? {} });
        const text = (((result as any).content ?? []) as any[]).map((c: any) => c.text ?? "").join("\n");
        transcript.push({ type: "tool_result", name: block.name, content: text });
        if (block.name === "attest_action") {
          try { receipt = JSON.parse(text); } catch { /* leave null */ }
        }
        toolResults.push({ type: "tool_result", tool_use_id: block.id, content: text });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        transcript.push({ type: "tool_result", name: block.name, content: "ERROR: " + msg });
        toolResults.push({ type: "tool_result", tool_use_id: block.id, content: "ERROR: " + msg, is_error: true });
      }
    }
    messages.push({ role: "user", content: toolResults });
  }

  return { events: transcript, receipt };
}
