export type IdentityErrorCode =
  | "invalid_input"
  | "conflict"
  | "not_found"
  | "invalid_state"
  | "rate_limited"
  | "verification_failed"
  | "storage_corrupt";

export class IdentityError extends Error {
  readonly code: IdentityErrorCode;
  readonly retryAfter?: number;

  constructor(
    code: IdentityErrorCode,
    message: string,
    options: { readonly cause?: unknown; readonly retryAfter?: number } = {},
  ) {
    super(message, options.cause === undefined ? undefined : options);
    this.name = "IdentityError";
    this.code = code;
    if (options.retryAfter !== undefined) {
      this.retryAfter = options.retryAfter;
    }
  }
}
