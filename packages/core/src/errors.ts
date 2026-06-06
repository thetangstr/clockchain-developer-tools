/**
 * Typed errors for the Clockchain client.
 *
 * Core never retries automatically — these errors are surfaced so the caller
 * can decide whether to back off, retry, or fail.
 */

/** Generic API error (non-2xx response that does not match a more specific case). */
export class ApiError extends Error {
  readonly status: number;
  readonly body: unknown;

  constructor(message: string, status: number, body?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

/** Gateway rate limiting: HTTP 429 or body containing "Rate limit exceeded". */
export class RateLimitError extends ApiError {
  constructor(message = "Rate limit exceeded", status = 429, body?: unknown) {
    super(message, status, body);
    this.name = "RateLimitError";
  }
}

/** Logging credit exhaustion: "No enough tokens to facilitate this logging". */
export class InsufficientCreditsError extends ApiError {
  constructor(
    message = "No enough tokens to facilitate this logging",
    status = 402,
    body?: unknown,
  ) {
    super(message, status, body);
    this.name = "InsufficientCreditsError";
  }
}

/** Authentication failure: HTTP 401 (bad or missing x-api-key). */
export class AuthError extends ApiError {
  constructor(message = "Authentication failed", status = 401, body?: unknown) {
    super(message, status, body);
    this.name = "AuthError";
  }
}
