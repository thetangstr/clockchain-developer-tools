/**
 * Clockchain "verify-a-receipt" widget (read-only).
 *
 * A single esbuild-bundled ESM module. It renders the structured output of the
 * `verify_receipt` / `verify_cross_party` tools, read from `window.openai.toolOutput`.
 *
 * AGE-193 truthfulness rule (load-bearing): NEVER imply "confirmed" while the
 * anchor is pending. The status pill is driven only by the server-derived
 * `status` field ("anchored" requires a blockHeight); anything else renders as
 * pending / unconfirmed.
 */
import { createRoot } from "react-dom/client";
import { useEffect, useState } from "react";

/** The stable shape produced by the verify tools' `structuredContent`. */
interface WidgetOutput {
  kind: "receipt" | "cross_party";
  /** Truthful anchor status (AGE-193): only "anchored" once a blockHeight exists. */
  status: "anchored" | "pending" | "degraded" | "unverified";
  confirmed: boolean;
  match: boolean | null;
  ledgerId: string | null;
  blockHeight: string | number | null;
  verifiedAgainst: string;
  eventHash?: string | null;
  anchoredHash?: string | null;
  consensusTime?: string | null;
  network?: string | null;
  summary: string;
  raw?: unknown;
}

declare global {
  interface Window {
    openai?: { toolOutput?: unknown; toolInput?: unknown };
  }
}

function readOutput(): WidgetOutput | null {
  const o = window.openai?.toolOutput as WidgetOutput | undefined;
  return o && typeof o === "object" ? o : null;
}

const PALETTE = {
  anchored: { bg: "#e6f4ea", fg: "#137333", label: "Confirmed on-chain" },
  pending: { bg: "#fef7e0", fg: "#a36a00", label: "Pending — not yet confirmed" },
  degraded: { bg: "#fef7e0", fg: "#a36a00", label: "Pending (pool degraded)" },
  unverified: { bg: "#fce8e6", fg: "#c5221f", label: "Could not verify" },
} as const;

function StatusPill({ status }: { status: WidgetOutput["status"] }) {
  const p = PALETTE[status] ?? PALETTE.unverified;
  return (
    <span
      style={{
        display: "inline-block",
        padding: "2px 10px",
        borderRadius: 999,
        background: p.bg,
        color: p.fg,
        fontWeight: 600,
        fontSize: 13,
      }}
    >
      {p.label}
    </span>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  if (value == null || value === "") return null;
  return (
    <div style={{ display: "flex", gap: 8, padding: "4px 0", fontSize: 13 }}>
      <span style={{ color: "#5f6368", minWidth: 130 }}>{label}</span>
      <span style={{ fontFamily: "ui-monospace, monospace", wordBreak: "break-all" }}>
        {value}
      </span>
    </div>
  );
}

function ReceiptCard({ data }: { data: WidgetOutput }) {
  // Defense in depth: a positive verdict requires BOTH a hash match AND an
  // anchored status. A pending entry is never shown as confirmed.
  const matchOk = data.match !== false;
  const effectiveStatus: WidgetOutput["status"] =
    data.match === false ? "unverified" : data.status;

  return (
    <div
      style={{
        fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, sans-serif",
        border: "1px solid #e0e0e0",
        borderRadius: 12,
        padding: 16,
        maxWidth: 480,
        color: "#202124",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <strong style={{ fontSize: 15 }}>
          {data.kind === "cross_party" ? "Cross-party verification" : "Agent Attested Receipt"}
        </strong>
        <StatusPill status={effectiveStatus} />
      </div>

      <p style={{ fontSize: 13, color: "#3c4043", margin: "8px 0 12px" }}>{data.summary}</p>

      <Row label="Hash match" value={data.match == null ? "n/a" : matchOk ? "yes" : "NO"} />
      <Row label="Verified against" value={data.verifiedAgainst} />
      <Row label="Ledger ID" value={data.ledgerId} />
      <Row
        label="Block height"
        value={data.blockHeight == null ? "(none — pending)" : String(data.blockHeight)}
      />
      <Row label="Consensus time" value={data.consensusTime ?? undefined} />
      <Row label="Event hash" value={data.eventHash ?? undefined} />
      <Row label="Anchored hash" value={data.anchoredHash ?? undefined} />
      <Row label="Network" value={data.network ?? undefined} />

      {effectiveStatus !== "anchored" && (
        <p style={{ fontSize: 12, color: "#a36a00", marginTop: 12 }}>
          This entry is not yet anchored on-chain. It is recorded but unconfirmed —
          do not treat it as final until a block height is present.
        </p>
      )}
      <p style={{ fontSize: 11, color: "#80868b", marginTop: 12 }}>
        Single-validator testnet. Independently verifiable; not a court-of-law
        evidentiary claim.
      </p>
    </div>
  );
}

function App() {
  const [data, setData] = useState<WidgetOutput | null>(readOutput);

  useEffect(() => {
    // The host updates window.openai.* and fires this event when tool output arrives.
    const onGlobals = () => setData(readOutput());
    window.addEventListener("openai:set_globals", onGlobals as EventListener);
    return () => window.removeEventListener("openai:set_globals", onGlobals as EventListener);
  }, []);

  if (!data) {
    return (
      <div style={{ fontFamily: "system-ui, sans-serif", fontSize: 13, color: "#5f6368", padding: 16 }}>
        Waiting for a verification result…
      </div>
    );
  }
  return <ReceiptCard data={data} />;
}

const el = document.getElementById("receipt-root");
if (el) createRoot(el).render(<App />);
