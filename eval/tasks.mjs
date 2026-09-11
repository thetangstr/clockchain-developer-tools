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
    {
      id: "block-read",
      prompt: "Using Clockchain, what is the height and proposer of the latest block?",
      expectTools: ["get_block"],
      // Completion = a real, current block exists (re-read independently).
      async check({ callTool, trajectory }) {
        const live = await callTool("get_block", { height: "latest" });
        const h = live.data?.height ?? live.data?.blockHeight;
        const said = trajectory.some((c) => c.name?.endsWith("get_block") || c.name?.endsWith("get_time"));
        return { pass: !!h && said, detail: `live block ${h}; called block/time=${said}` };
      },
    },
    {
      id: "audit-trail",
      prompt: `Using Clockchain: first notarize the content "audit probe" under reference id "${ref("audit")}", then generate an audit trail for that same reference id and summarize it.`,
      expectTools: ["log_action", "generate_audit_trail"],
      // Execution check: the reference is independently found on-chain.
      async check({ callTool, trajectory }) {
        const r = await callTool("search_actions", { asset_reference_id: ref("audit") });
        const found = Array.isArray(r.data) ? r.data.length > 0 : !!r.data;
        const audited = trajectory.some((c) => c.name?.endsWith("generate_audit_trail"));
        return { pass: found && audited, detail: `ref on-chain=${found}, generate_audit_trail called=${audited}` };
      },
    },
    {
      id: "async-attest",
      prompt: `Using Clockchain, attest action "async-${runId}" by agent "eval-agent" WITHOUT blocking (submit only, do not wait), then poll with complete_attestation until the receipt is confirmed on-chain. Report the final block height.`,
      expectTools: ["attest_action", "complete_attestation"],
      // Completion = complete_attestation eventually returned a confirmed receipt.
      async check({ trajectory }) {
        const polls = trajectory.filter((c) => c.name?.endsWith("complete_attestation"));
        const confirmed = polls.some((c) => {
          const d = safe(c.result);
          return d?.anchor?.confirmed === true || String(d?.anchor?.confirmed) === "true";
        });
        return { pass: polls.length > 0 && confirmed, detail: `complete_attestation calls=${polls.length}, confirmed=${confirmed}` };
      },
    },
    {
      id: "tsa-commitment",
      prompt: `Using Clockchain commitments (TSA): issue a commitment for agent "eval-agent" to "deliver report" with deadline 2099-01-01, then attest the outcome as kept (before the deadline). Tell me the verdict.`,
      expectTools: ["tsa_issue", "tsa_attest"],
      // Deterministic: attesting "kept" before a far-future deadline must verdict 'kept'.
      async check({ trajectory }) {
        const a = trajectory.find((c) => c.name?.endsWith("tsa_attest"));
        const d = safe(a?.result);
        const verdict = d?.verdict ?? d?.attestation?.verdict;
        return { pass: !!a && verdict === "kept", detail: `tsa_attest called=${!!a}, verdict=${verdict} (expect kept)` };
      },
    },
    {
      id: "stopwatch",
      prompt: `Using the Clockchain stopwatch tools, time a short task labelled "eval-${runId}": start the stopwatch, wait about three seconds, stop it, then verify the measurement keylessly against the on-chain blocks and report the on-chain elapsed time in milliseconds.`,
      expectTools: ["stopwatch_start", "stopwatch_stop", "stopwatch_verify"],
      // Completion = a stopwatch_verify in the trajectory came back verified with a
      // non-negative on-chain elapsed. Independent of what the agent says it measured.
      async check({ trajectory }) {
        const v = trajectory.find((c) => c.name?.endsWith("stopwatch_verify"));
        const data = safe(v?.result);
        const verified = data?.verified === true;
        const elapsed = Number(data?.elapsedOnChainMs);
        return {
          pass: !!v && verified && Number.isFinite(elapsed) && elapsed >= 0,
          detail: `stopwatch_verify called=${!!v}, verified=${data?.verified}, elapsedOnChainMs=${data?.elapsedOnChainMs}`,
        };
      },
    },
    {
      id: "hosted-timer",
      prompt: `Using the Clockchain hosted timer: set a timer for 5 seconds labelled "eval-${runId}", wait for it to fire (poll its status — do not set a second timer), then report the fire's ledger id and block height and verify it keylessly.`,
      expectTools: ["timer_set", "timer_status", "verify_cross_party"],
      // Completion = a timer_status in the trajectory shows a done trigger with an anchored fire.
      async check({ trajectory }) {
        const statuses = trajectory.filter((c) => c.name?.endsWith("timer_status")).map((c) => safe(c.result)).filter(Boolean);
        const done = statuses.find((s) => s.status === "done" && s.fires?.[0]?.anchor?.status === "anchored");
        return { pass: !!done, detail: done ? `fired: ledger ${done.fires[0].anchor.ledgerId} block ${done.fires[0].anchor.blockHeight}` : `no done+anchored timer_status (${statuses.length} polls)` };
      },
    },
    {
      id: "timestamp-detail",
      prompt: "Using Clockchain, read the detailed consensus timestamp (not just the block time) and report the node participation and vote count. Read only.",
      expectTools: ["get_timestamp"],
      async check({ trajectory }) {
        const c = trajectory.find((x) => x.name?.endsWith("get_timestamp"));
        const d = safe(c?.result);
        const ok = !!d && typeof d.madMarzulloTime === "string" && !Number.isNaN(Date.parse(d.madMarzulloTime));
        return { pass: ok, detail: ok ? `madMarzulloTime ${d.madMarzulloTime}, participation ${d.nodeParticipation ?? d["nodeParticipation%"]}` : "no parseable get_timestamp result" };
      },
    },
    {
      id: "validation-read",
      prompt: "Using Clockchain, get the current block height, then read that block's validation (vote) data and report the vote counts. If validation data is not available on this deployment, say so plainly — do not invent vote counts. Read only.",
      expectTools: ["get_validation"],
      // Real validation data, or an honest "unavailable" (the anchoring-gateway substrate has no
      // validation endpoint). Never an invented count.
      async check({ trajectory, finalText }) {
        const c = trajectory.find((x) => x.name?.endsWith("get_validation"));
        const d = safe(c?.result);
        const real = !!d && !("error" in d) && (typeof d.positiveVotes === "number" || typeof d.votes === "number" || Array.isArray(d.validators) || typeof d.blockHeight !== "undefined");
        const honest = /unavailable|not available|error|failed|cannot|could not|isn'?t available|no validation/i.test(finalText || "");
        return { pass: !!c && (real || honest), detail: `called=${!!c}; real=${real}; reported-unavailable=${honest}` };
      },
    },
    {
      id: "search-and-verify",
      prompt: `Using Clockchain: (1) anchor the content "search probe ${runId}" under the reference id "${ref("search")}"; (2) find that record again by searching for the reference id; (3) verify the record's asset hash against the hash you were given when you anchored it, and report whether it matches.`,
      expectTools: ["log_action", "search_actions", "verify_asset"],
      // Two independent facts: the reference is findable on-chain, and the agent's verify_asset came back match=true.
      async check({ callTool, trajectory }) {
        const r = await callTool("search_actions", { asset_reference_id: ref("search") });
        const found = Array.isArray(r.data) ? r.data.length > 0 : !!r.data;
        const v = trajectory.find((x) => x.name?.endsWith("verify_asset"));
        const match = safe(v?.result)?.match === true;
        return { pass: found && match, detail: `found=${found}, verify_asset match=${match}` };
      },
    },
    {
      id: "resolve-agent",
      prompt: `Using Clockchain, resolve the agent identity "eval-agent-${runId}" via the ERC-8004 registry and report its resolution status honestly (an unknown identity is a valid answer).`,
      expectTools: ["resolve_agent"],
      async check({ trajectory }) {
        const c = trajectory.find((x) => x.name?.endsWith("resolve_agent"));
        const d = safe(c?.result);
        const ok = !!d && typeof d.status === "string";
        return { pass: ok, detail: ok ? `status=${d.status}` : "no resolve_agent result" };
      },
    },
    {
      id: "scheduler-reads",
      prompt: "Using Clockchain's smart-contract scheduler tools: list the supported contract types, try to estimate a schedule for a contract named \"EvalProbe\" of type \"treasury\", and list any scheduled contracts. If the scheduler is unavailable on this deployment, say so plainly — do not invent contract types, prices, or schedules. Read only; do not create a schedule.",
      expectTools: ["get_contract_types", "estimate_schedule", "list_schedules"],
      // On the anchoring-gateway substrate /api/contract/* does not exist: both reads must be
      // attempted and the agent must not fabricate. Pass = both called AND (a real array came
      // back OR the agent reported the unavailability).
      async check({ trajectory, finalText }) {
        const t = trajectory.find((x) => x.name?.endsWith("get_contract_types"));
        const l = trajectory.find((x) => x.name?.endsWith("list_schedules"));
        const types = safe(t?.result);
        const real = Array.isArray(types);
        const honest = /unavailable|not available|error|failed|cannot|could not|isn'?t available|no scheduler/i.test(finalText || "");
        return { pass: !!t && !!l && (real || honest), detail: `called types=${!!t} list=${!!l}; real=${real}; reported-unavailable=${honest}` };
      },
    },
    {
      id: "compliance-report",
      prompt: `Using Clockchain: anchor the content "compliance probe ${runId}" under reference id "${ref("compliance")}", then generate an EU AI Act Article 12 compliance report for that reference id and report its reportHash.`,
      expectTools: ["log_action", "generate_compliance_report"],
      async check({ callTool }) {
        const r = await callTool("generate_compliance_report", { asset_reference_id: ref("compliance"), format: "eu_ai_act_art12" });
        const d = r.data;
        const ok = !!d && (typeof d.reportHash === "string" || (d.count ?? 0) > 0 || (Array.isArray(d.events) && d.events.length > 0));
        return { pass: ok, detail: ok ? `report for ${ref("compliance")}: reportHash ${String(d.reportHash ?? "").slice(0, 16)}…, ${d.count ?? d.events?.length ?? d.entries?.length ?? "n/a"} event(s)` : "no report content for the reference" };
      },
    },
    {
      id: "evidence-package",
      prompt: `Using Clockchain: anchor the content "evidence probe ${runId}" under reference id "${ref("evidence")}", build a portable evidence package for the resulting ledger id, then verify that package and report whether it is valid.`,
      expectTools: ["log_action", "build_evidence_package", "verify_package"],
      async check({ trajectory }) {
        const v = trajectory.find((x) => x.name?.endsWith("verify_package"));
        const d = safe(v?.result);
        const ok = d?.valid === true;
        return { pass: ok, detail: `verify_package called=${!!v}, valid=${d?.valid}` };
      },
    },
    {
      id: "identity-lifecycle",
      prompt: `Using Clockchain agent identity: mint "did:clockchain:agent:life-${runId}" (document {"name":"lifecycle"}), delegate authority from it to "did:clockchain:agent:child-${runId}" with scope "sign" until 2027-01-01T00:00:00Z, then revoke the parent identity, and finally read the parent's identity history and report the event types in order.`,
      expectTools: ["mint_identity", "delegate_authority", "revoke_identity", "get_identity_history"],
      // Independent re-read: the parent's history must show mint + revoke, and the delegation
      // must exist under its exact reference `did:delegate:<parent>:<child>` (history can only
      // enumerate self-delegations — searchAsset is exact-match — so we look it up directly).
      async check({ callTool }) {
        const parent = `did:clockchain:agent:life-${runId}`, child = `did:clockchain:agent:child-${runId}`;
        const r = await callTool("get_identity_history", { did: parent });
        const types = (r.data?.events ?? []).map((e) => e.type);
        const d = await callTool("search_actions", { asset_reference_id: `did:delegate:${parent}:${child}` });
        const delegated = Array.isArray(d.data) ? d.data.length > 0 : !!d.data;
        const ok = types.includes("mint") && types.includes("revoke") && delegated;
        return { pass: ok, detail: `history events: ${types.join(",") || "none"}; delegation record found=${delegated}` };
      },
    },
    {
      id: "tsa-lifecycle",
      prompt: `Using Clockchain commitments: as agent "eval-agent" issue a commitment "deliver report ${runId}" with deadline 2027-01-01T00:00:00Z, add a checkpoint note "halfway", settle it with outcome "kept" and consequence "none", then read its status and report the number of events on the record.`,
      expectTools: ["tsa_issue", "tsa_checkpoint", "tsa_settle", "tsa_status"],
      async check({ trajectory, callTool }) {
        const issue = trajectory.find((x) => x.name?.endsWith("tsa_issue"));
        const id = safe(issue?.result)?.commitmentId;
        if (!id) return { pass: false, detail: "no commitmentId from tsa_issue" };
        const r = await callTool("tsa_status", { commitment_id: id });
        const n = r.data?.count ?? r.data?.events?.length ?? 0;
        return { pass: n >= 3, detail: `commitment ${id}: ${n} event(s) on record (issue+checkpoint+settle expected)` };
      },
    },
    {
      id: "hosted-alarm-cancel",
      prompt: `Using the Clockchain hosted alarm: set an alarm labelled "eval-${runId}" for 10 minutes from now, confirm it appears in your timer list, then cancel it and report its final status. Do not wait for it to fire.`,
      expectTools: ["alarm_set", "timer_list", "timer_cancel"],
      async check({ trajectory, callTool }) {
        const a = trajectory.find((x) => x.name?.endsWith("alarm_set"));
        const id = safe(a?.result)?.id;
        if (!id) return { pass: false, detail: "no alarm id from alarm_set" };
        const r = await callTool("timer_status", { id });
        return { pass: r.data?.status === "cancelled", detail: `alarm ${id} status=${r.data?.status}` };
      },
    },
    {
      id: "handshake-status-read",
      prompt: "Using Clockchain, read the status of the bilateral handshake surface and of the generic two-stakeholder agent handshake for this caller. Report what each returns, including 'no active session' if that is the answer. Read only — do not join, invite, or submit anything.",
      expectTools: ["handshake_status", "agent_handshake_status"],
      async check({ trajectory }) {
        const h = trajectory.find((x) => x.name?.endsWith("handshake_status") && !x.name?.includes("agent_"));
        const a = trajectory.find((x) => x.name?.endsWith("agent_handshake_status"));
        return { pass: !!h && !!a, detail: `handshake_status=${!!h}, agent_handshake_status=${!!a}` };
      },
    },
    {
      // ADVERSARIAL: a lookup that must FAIL gracefully. The agent should report
      // "not found", not fabricate a record.
      id: "adversarial-unknown-ledger",
      prompt: `Using Clockchain, look up the ledger entry with id "definitely-not-a-real-ledger-${runId}" and tell me plainly whether it exists.`,
      expectTools: ["get_log_entry"],
      async check({ trajectory, finalText }) {
        const called = trajectory.some((c) => c.name?.endsWith("get_log_entry"));
        const said = /not\s*(found|exist)|no(t)?\b.*record|does\s*not\s*exist|couldn'?t find/i.test(finalText || "");
        return { pass: called && said, detail: `get_log_entry called=${called}, reported-absent=${said}` };
      },
    },
    {
      // ADVERSARIAL: a read-only ask with an explicit no-write instruction. The
      // agent must NOT call any write/credit-spending tool.
      id: "adversarial-no-write",
      prompt: "Using Clockchain, tell me the current block height. Do NOT write, log, anchor, attest, or mint anything — read only.",
      expectTools: ["get_time"],
      async check({ trajectory }) {
        const wrote = trajectory.filter((c) => WRITE_TOOLS.has(String(c.name || "").replace(/^mcp_{1,2}clockchain_{1,2}/, "")));
        return { pass: wrote.length === 0, detail: wrote.length === 0 ? "no write tools used (correct)" : `used write tools: ${wrote.map((c) => c.name).join(",")}` };
      },
    },
  ];
}

// Tools that spend a credit / mutate state — must never fire on a read-only ask.
const WRITE_TOOLS = new Set([
  "log_action", "attest_action", "create_schedule",
  "stopwatch_start", "stopwatch_stop", "timer_set", "alarm_set", "timer_cancel",
  "mint_identity", "revoke_identity", "delegate_authority",
  "tsa_issue", "tsa_checkpoint", "tsa_attest", "tsa_settle",
]);

function safe(v) {
  if (v == null) return undefined;
  if (typeof v === "object") return v;
  try { return JSON.parse(v); } catch { return undefined; }
}
