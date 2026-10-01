import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { JsonWebKey } from "node:crypto";

import { openSealJwk, type SealedBox } from "./seal.js";
import type { ContractRole } from "./tokens.js";

/**
 * `ac-otlp-forward` (N4c, E12): the per-role local OTLP forwarder run by the
 * local-services uid. The agent's OTel exporter points here with NO token;
 * the forwarder unseals the ingest token with the services key (kept only in
 * this process's memory), attaches `Authorization: Bearer`, and relays the
 * request body BYTE-FOR-BYTE to the sink — it adds nothing and alters
 * nothing, so the digest the sink records is the digest of what the runtime
 * emitted.
 *
 * The listener accepts only the literal loopback addresses `127.0.0.1` and
 * `::1` — no `localhost`, no IPv4-mapped forms, no wildcards (post-review
 * LOW). No runtime can export to a Unix socket, and pf restricts which agent
 * uid may reach which role's port.
 *
 * The sealed token is bound to (runId, role) in its AAD (M4): the forwarder
 * must be told its own runId+role to unseal at all, and it cross-checks the
 * runId in every sink reply against its own — a reply naming another run is
 * not relayed.
 */

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1"]);
const DEFAULT_MAX_BODY_BYTES = 4 * 1024 * 1024;

export function createForwarder(options: {
  listen: { host: string; port: number };
  targetBaseUrl: string;
  sealedToken: SealedBox;
  servicesPrivateKeyJwk: JsonWebKey;
  runId: string;
  role: ContractRole;
  maxBodyBytes?: number;
}): Server {
  if (!LOOPBACK_HOSTS.has(options.listen.host)) {
    throw new Error(
      `ac-otlp-forward refuses a non-loopback bind (got ${options.listen.host}); ` +
        "the forwarder must listen on the literal 127.0.0.1 or ::1 only",
    );
  }
  const maxBody = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;

  // Unseal once, at startup, under this forwarder's declared (runId, role).
  // The plaintext lives only in this closure — never in a response or log.
  const token = openSealJwk(options.servicesPrivateKeyJwk, options.sealedToken, {
    runId: options.runId,
    role: options.role,
  });
  const target = options.targetBaseUrl.replace(/\/$/, "");

  return createServer(async (req: IncomingMessage, res: ServerResponse) => {
    try {
      const url = new URL(req.url ?? "/", "http://loopback.invalid");
      if (req.method !== "POST" || !url.pathname.startsWith("/v1/")) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "not_found" }));
        return;
      }
      const chunks: Buffer[] = [];
      let size = 0;
      let tooLarge = false;
      for await (const chunk of req) {
        size += (chunk as Buffer).byteLength;
        if (size > maxBody) { tooLarge = true; break; }
        chunks.push(chunk as Buffer);
      }
      if (tooLarge) {
        res.writeHead(413, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "payload_too_large" }));
        return;
      }
      const body = Buffer.concat(chunks);

      const upstream = await fetch(`${target}${url.pathname}`, {
        method: "POST",
        headers: {
          "content-type": req.headers["content-type"] ?? "application/json",
          authorization: `Bearer ${token}`,
        },
        body,
      });
      const upstreamBody = Buffer.from(await upstream.arrayBuffer());

      // M4: the sink's reply must name OUR run. A reply for another run is
      // not evidence of our write and is not relayed.
      try {
        const reply = JSON.parse(upstreamBody.toString("utf8")) as { runId?: unknown };
        if (typeof reply.runId === "string" && reply.runId !== options.runId) {
          res.writeHead(502, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "runid_mismatch" }));
          return;
        }
      } catch { /* non-JSON upstream replies are relayed untouched */ }

      res.writeHead(upstream.status, { "content-type": upstream.headers.get("content-type") ?? "application/json" });
      res.end(upstreamBody);
    } catch {
      res.writeHead(502, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "upstream_unreachable" }));
    }
  });
}
