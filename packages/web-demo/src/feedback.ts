/** Feedback validation/shaping - pure (no I/O), so it is unit-testable. */

const firstHeader = (h: string | string[] | undefined): string =>
  (Array.isArray(h) ? h[0] : h) ?? "";

/**
 * Validate + shape a feedback submission. Captures the Cloudflare Access identity
 * automatically when present (header `cf-access-authenticated-user-email`).
 * Returns `{ error }` when neither a valid rating nor a message is provided.
 */
export function buildFeedbackRecord(
  body: Record<string, unknown>,
  headers: Record<string, string | string[] | undefined>,
  nowMs: number,
): { record?: Record<string, unknown>; error?: string } {
  const r = body.rating;
  const rating = typeof r === "number" && Number.isInteger(r) && r >= 1 && r <= 5 ? r : null;
  const message = typeof body.message === "string" ? body.message.trim().slice(0, 4000) : "";
  const role = typeof body.role === "string" ? body.role.trim().slice(0, 200) : "";
  if (rating === null && message.length === 0) {
    return { error: "a rating (1-5) or a message is required" };
  }
  const email = firstHeader(headers["cf-access-authenticated-user-email"]).slice(0, 320);
  return {
    record: {
      ts: new Date(nowMs).toISOString(),
      rating,
      message,
      role,
      email, // populated automatically when behind Cloudflare Access
    },
  };
}
