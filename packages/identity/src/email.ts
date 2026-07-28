import { toASCII } from "tr46";
import unorm from "unorm";
import { caseFold } from "unicode-case-folding";

import { IdentityError } from "./errors.js";
import { assertBoundedString } from "./validation.js";

const FORBIDDEN =
  /[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2060\u2066-\u2069\uFEFF]/u;
const DEFAULT_IGNORABLE = /[\u00AD\u034F]/gu;
const ASCII_DOMAIN_LABEL = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u;

function inPinnedRepertoire(codePoint: number): boolean {
  return (
    (codePoint >= 0x20 && codePoint <= 0x7e) ||
    (codePoint >= 0xa0 && codePoint <= 0x24f) ||
    (codePoint >= 0x300 && codePoint <= 0x52f) ||
    (codePoint >= 0x1f00 && codePoint <= 0x1fff) ||
    (codePoint >= 0xff01 && codePoint <= 0xff5e)
  );
}

function pinnedNfkcCaseFold(value: string): string {
  for (const symbol of value) {
    const codePoint = symbol.codePointAt(0);
    if (codePoint === undefined || !inPinnedRepertoire(codePoint)) {
      throw new IdentityError("invalid_input", "Email is invalid.");
    }
  }
  return unorm
    .nfkc(caseFold(unorm.nfkc(value)).replace(DEFAULT_IGNORABLE, ""))
    .trim();
}

function canonicalDomain(value: string): string {
  if (
    value.length === 0 ||
    value.length > 253 ||
    /[\s/\\:?#@[\]]/u.test(value)
  ) {
    throw new IdentityError("invalid_input", "Email is invalid.");
  }
  let hostname: string | undefined;
  try {
    hostname = toASCII(value, {
      checkBidi: true,
      checkHyphens: true,
      checkJoiners: true,
      transitionalProcessing: false,
      useSTD3ASCIIRules: true,
      verifyDNSLength: true,
    })?.toLowerCase();
  } catch {
    throw new IdentityError("invalid_input", "Email is invalid.");
  }
  if (hostname === undefined) {
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
  const normalized = pinnedNfkcCaseFold(input);
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
