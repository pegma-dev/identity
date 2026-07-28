import { caseFold } from "unicode-case-folding";

import { IdentityError } from "./errors.js";
import { assertBoundedString } from "./validation.js";

const FORBIDDEN =
  /[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2060\u2066-\u2069\uFEFF]/u;
const DEFAULT_IGNORABLE = /\p{Default_Ignorable_Code_Point}/gu;
const ASCII_DOMAIN_LABEL = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u;

function canonicalDomain(value: string): string {
  if (
    value.length === 0 ||
    value.length > 253 ||
    /[\s/\\:?#@[\]]/u.test(value)
  ) {
    throw new IdentityError("invalid_input", "Email is invalid.");
  }
  let hostname: string;
  try {
    const url = new URL(`https://${value}`);
    if (
      url.username !== "" ||
      url.password !== "" ||
      url.port !== "" ||
      url.pathname !== "/" ||
      url.search !== "" ||
      url.hash !== ""
    ) {
      throw new Error("domain was not an origin");
    }
    hostname = url.hostname.toLowerCase();
  } catch {
    throw new IdentityError("invalid_input", "Email is invalid.");
  }
  const labels = hostname.split(".");
  if (
    hostname.length === 0 ||
    hostname.length > 253 ||
    hostname.startsWith(".") ||
    hostname.endsWith(".") ||
    labels.some(
      (label) =>
        label.length === 0 ||
        label.length > 63 ||
        !ASCII_DOMAIN_LABEL.test(label),
    )
  ) {
    throw new IdentityError("invalid_input", "Email is invalid.");
  }
  return hostname;
}

/**
 * The one canonical email normalization function used by every lookup and
 * write path.
 *
 * Identity deliberately folds the complete address: this component treats
 * email as a contact/lookup value, not an SMTP routing implementation.
 */
export function normalizeEmail(value: unknown): string {
  const input = assertBoundedString(value, "Email", 1_024);
  if (FORBIDDEN.test(input)) {
    throw new IdentityError("invalid_input", "Email is invalid.");
  }
  const normalized = caseFold(input.normalize("NFKC"))
    .replace(DEFAULT_IGNORABLE, "")
    .trim()
    .normalize("NFKC");
  if (
    normalized.length === 0 ||
    FORBIDDEN.test(normalized) ||
    /\s/u.test(normalized) ||
    normalized.startsWith("@") ||
    normalized.endsWith("@") ||
    normalized.split("@").length !== 2
  ) {
    throw new IdentityError("invalid_input", "Email is invalid.");
  }
  const [local, domain] = normalized.split("@");
  if (
    local === undefined ||
    domain === undefined ||
    local.length > 64 ||
    local.length === 0
  ) {
    throw new IdentityError("invalid_input", "Email is invalid.");
  }
  const result = `${local}@${canonicalDomain(domain)}`;
  if (result.length > 254) {
    throw new IdentityError("invalid_input", "Email is invalid.");
  }
  return result;
}
