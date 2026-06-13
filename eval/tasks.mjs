// Execution-scored task suite for the Clockchain MCP.
// Each task: { id, prompt, expectTools, check }. `prompt` embeds a unique ref so
// `check` can INDEPENDENTLY verify the outcome on-chain (no LLM judge, no reliance
// on parsing the agent's words). `check(helpers)` -> { pass, detail }.
// helpers: { callTool, trajectory } — trajectory = [{name, input, result}] (best-effort).

export function tasks(runId) {
  const ref = (t) => `eval-${runId}-${t}`;
  return [
    {
      id: "time-read",
      prompt: "Use Clockchain to tell me the current consensus time and the latest block height.",
      expectTools: ["get_time"],
      // Completion = the agent surfaced a real, current block height (we re-read it).
      async check({ callTool, trajectory }) {
        const live = await callTool("get_time");
        const h = live.data?.latestBlockHeight;
        const said = trajectory.some((c) => c.name?.endsWith("get_time"));
        return { pass: !!h && said, detail: `live height ${h}; called get_time=${said}` };
      },
    },
    {
      id: "notarize",
      prompt: `Notarize (log/anchor) this exact content on Clockchain under the reference id "${ref("notarize")}". Content: "eval notarization probe". Report the ledger id.`,
      expectTools: ["log_action"],
      // Execution check: search the chain for the reference — independent of what the agent claims.
      async check({ callTool }) {
        const r = await callTool("search_actions", { asset_reference_id: ref("notarize") });
        const found = Array.isArray(r.data) ? r.data.length > 0 : !!r.data;
        return { pass: found, detail: found ? "reference found on-chain" : "reference NOT found on-chain" };
      },
    },
    {
      id: "attest-verify",
      prompt: `Using Clockchain, attest that agent "eval-agent" performed action "ran-eval-${runId}" with output {"result":"pass"}, then INDEPENDENTLY verify the resulting receipt and tell me whether it matches.`,
      expectTools: ["attest_action", "verify_receipt"],
      // Completion = a verify_receipt in the trajectory returned match=true.
      async check({ trajectory }) {
        const vr = trajectory.find((c) => c.name?.endsWith("verify_receipt"));
        const data = safe(vr?.result);
        const match = data?.match === true || String(data?.match).toLowerCase() === "true";
        return { pass: !!vr && match, detail: `verify_receipt called=${!!vr}, match=${data?.match}` };
      },
    },
    {
      id: "identity-valid-at",
      prompt: `Using Clockchain agent identity: mint the identity "did:clockchain:agent:eval-${runId}" (document {"name":"eval"}), then check whether that identity was authorized at the instant 2020-01-01T00:00:00Z (well before it was minted).`,
      expectTools: ["mint_identity", "verify_identity_at"],
      // Deterministic temporal truth: authorized-at a time BEFORE mint must be false.
      async check({ trajectory }) {
        const v = trajectory.find((c) => c.name?.endsWith("verify_identity_at"));
        const data = safe(v?.result);
        const authorized = data?.authorized;
        return { pass: !!v && authorized === false, detail: `verify_identity_at called=${!!v}, authorized=${authorized} (expect false)` };
      },
    },
    {
      id: "cross-party-verify",
      prompt: `Using Clockchain, attest action "settle-${runId}" by agent "eval-agent", then do a KEYLESS cross-party verification of that record against the on-chain block (as an outside auditor would).`,
      expectTools: ["attest_action", "verify_cross_party"],
      async check({ trajectory }) {
        const x = trajectory.find((c) => c.name?.endsWith("verify_cross_party"));
        const data = safe(x?.result);
        const ok = !!data && (data.onChain || data.chainVerify || data.keyless);
        return { pass: !!x && !!ok, detail: `verify_cross_party called=${!!x}, has on-chain result=${!!ok}` };
      },
    },
  ];
}

function safe(v) {
  if (v == null) return undefined;
  if (typeof v === "object") return v;
  try { return JSON.parse(v); } catch { return undefined; }
}
