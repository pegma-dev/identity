import type { RateLimiter } from "@pegma/rate-limit";
import { systemClock, type Clock, type PrincipalId } from "@pegma/spine";
import type { Store } from "@pegma/storage-core";

import {
  createChallengeService,
  createMemoryChallengeRetention,
  type ChallengeRetention,
  type ChallengeRetentionReference,
  type ChallengeSweepResult,
} from "./challenges.js";
import { normalizeEmail } from "./email.js";
import { IdentityError, type IdentityErrorCode } from "./errors.js";
import {
  createPasskeyService,
  type AuthenticationStart,
  type FinishAuthenticationInput,
  type FinishRegistrationInput,
  type Passkey,
  type RegistrationStart,
} from "./passkeys.js";
import {
  createUserService,
  type ProvisionVerifiedUserInput,
  type User,
  type VerifiedIdentityClaims,
} from "./users.js";
import {
  assertBoundedString,
  copyDataOnly,
  isLocalDevelopmentHostname,
} from "./validation.js";

export interface IdentityOptions {
  readonly store: Store;
  readonly issuer: string;
  readonly rpName: string;
  readonly rpID: string;
  readonly origins: readonly string[];
  readonly registrationLimiter: RateLimiter;
  readonly authenticationLimiter: RateLimiter;
  readonly challengeRetention: ChallengeRetention;
  readonly clock?: Clock;
  readonly newId?: () => string;
  readonly challengeTtlMs?: number;
  readonly challengeMaxAttempts?: number;
  readonly repairDelayMs?: number;
}

export interface Identity {
  provisionVerifiedUser(input: ProvisionVerifiedUserInput): Promise<User>;
  repairUserByEmail(email: string): Promise<User>;
  findUserByEmail(email: string): Promise<User | null>;
  getUser(principalId: PrincipalId): Promise<User | null>;
  claimsFor(principalId: PrincipalId): Promise<VerifiedIdentityClaims>;
  beginPasskeyRegistration(
    principalId: PrincipalId,
    rateLimitKey: string,
  ): Promise<RegistrationStart>;
  finishPasskeyRegistration(input: FinishRegistrationInput): Promise<Passkey>;
  beginPasskeyAuthentication(
    rateLimitKey: string,
  ): Promise<AuthenticationStart>;
  finishPasskeyAuthentication(
    input: FinishAuthenticationInput,
  ): Promise<VerifiedIdentityClaims>;
  listPasskeys(principalId: PrincipalId): Promise<readonly Passkey[]>;
  removePasskey(
    principalId: PrincipalId,
    credentialId: string,
  ): Promise<boolean>;
  repairPasskey(credentialId: string): Promise<Passkey | null>;
  sweepChallenges(limit?: number): Promise<ChallengeSweepResult>;
}

function positiveBoundedInteger(
  value: number | undefined,
  fallback: number,
  maximum: number,
  label: string,
): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < 1 || result > maximum) {
    throw new IdentityError("invalid_input", `${label} is invalid.`);
  }
  return result;
}

const IDENTITY_OPTION_KEYS = new Set([
  "store",
  "issuer",
  "rpName",
  "rpID",
  "origins",
  "registrationLimiter",
  "authenticationLimiter",
  "challengeRetention",
  "clock",
  "newId",
  "challengeTtlMs",
  "challengeMaxAttempts",
  "repairDelayMs",
]);

function snapshotOptions(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new IdentityError("invalid_input", "Identity options are invalid.");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new IdentityError("invalid_input", "Identity options are invalid.");
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    Reflect.ownKeys(descriptors).some(
      (key) => typeof key === "symbol" || !IDENTITY_OPTION_KEYS.has(key),
    )
  ) {
    throw new IdentityError("invalid_input", "Identity options are invalid.");
  }
  const snapshot: Record<string, unknown> = Object.create(null);
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (!descriptor.enumerable || !("value" in descriptor)) {
      throw new IdentityError("invalid_input", "Identity options are invalid.");
    }
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}

function validateOrigins(values: unknown): readonly string[] {
  if (!Array.isArray(values) || values.length === 0 || values.length > 16) {
    throw new IdentityError("invalid_input", "Origins are invalid.");
  }
  const origins = values.map((value) => {
    const input = assertBoundedString(value, "Origin", 2_048);
    let url: URL;
    try {
      url = new URL(input);
    } catch (cause) {
      throw new IdentityError("invalid_input", "Origin is invalid.", { cause });
    }
    const local = isLocalDevelopmentHostname(url.hostname);
    if (
      url.origin !== input ||
      (url.protocol !== "https:" && !(local && url.protocol === "http:")) ||
      url.username !== "" ||
      url.password !== "" ||
      url.pathname !== "/" ||
      url.search !== "" ||
      url.hash !== ""
    ) {
      throw new IdentityError("invalid_input", "Origin is invalid.");
    }
    return url.origin;
  });
  return Object.freeze([...new Set(origins)]);
}

function retentionMethod(
  value: object,
  name: keyof ChallengeRetention,
): ((...arguments_: unknown[]) => unknown) | null {
  let current: object | null = value;
  while (current !== null) {
    const descriptor = Object.getOwnPropertyDescriptor(current, name);
    if (descriptor !== undefined) {
      return "value" in descriptor && typeof descriptor.value === "function"
        ? (descriptor.value as (...arguments_: unknown[]) => unknown)
        : null;
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  return null;
}

function validateRetention(value: unknown): ChallengeRetention {
  if (typeof value !== "object" || value === null) {
    throw new IdentityError("invalid_input", "Challenge retention is invalid.");
  }
  const track = retentionMethod(value, "track");
  const candidates = retentionMethod(value, "candidates");
  const complete = retentionMethod(value, "complete");
  if (track === null || candidates === null || complete === null) {
    throw new IdentityError("invalid_input", "Challenge retention is invalid.");
  }
  return Object.freeze({
    track: track.bind(value) as ChallengeRetention["track"],
    candidates: candidates.bind(value) as ChallengeRetention["candidates"],
    complete: complete.bind(value) as ChallengeRetention["complete"],
  });
}

export function createIdentity(options: IdentityOptions): Identity {
  const safe = snapshotOptions(options);
  const issuer = assertBoundedString(safe.issuer, "Issuer", 1_024);
  const rpName = assertBoundedString(safe.rpName, "Relying-party name", 100);
  const rpID = assertBoundedString(
    safe.rpID,
    "Relying-party identifier",
    253,
  ).toLowerCase();
  let canonicalRpID = false;
  try {
    canonicalRpID = new URL(`https://${rpID}`).hostname === rpID;
  } catch {
    canonicalRpID = false;
  }
  if (
    rpID.includes("/") ||
    rpID.includes(":") ||
    rpID.startsWith(".") ||
    rpID.endsWith(".") ||
    !canonicalRpID
  ) {
    throw new IdentityError(
      "invalid_input",
      "Relying-party identifier is invalid.",
    );
  }
  const origins = validateOrigins(copyDataOnly(safe.origins));
  const challengeRetention = validateRetention(safe.challengeRetention);
  if (
    !origins.every((origin) => {
      const hostname = new URL(origin).hostname;
      return hostname === rpID || hostname.endsWith(`.${rpID}`);
    })
  ) {
    throw new IdentityError(
      "invalid_input",
      "Every origin must belong to the relying-party identifier.",
    );
  }
  const clock = (safe.clock as Clock | undefined) ?? systemClock;
  const newId =
    (safe.newId as (() => string) | undefined) ?? (() => crypto.randomUUID());
  const challengeTtlMs = positiveBoundedInteger(
    safe.challengeTtlMs as number | undefined,
    5 * 60_000,
    15 * 60_000,
    "Challenge TTL",
  );
  const challengeMaxAttempts = positiveBoundedInteger(
    safe.challengeMaxAttempts as number | undefined,
    3,
    10,
    "Challenge attempt limit",
  );
  const repairDelayMs = positiveBoundedInteger(
    safe.repairDelayMs as number | undefined,
    60_000,
    24 * 60 * 60_000,
    "Repair delay",
  );
  const users = createUserService({
    store: safe.store as Store,
    clock,
    issuer,
    newId,
    repairDelayMs,
  });
  const challenges = createChallengeService({
    store: safe.store as Store,
    clock,
    newId,
    ttlMs: challengeTtlMs,
    maxAttempts: challengeMaxAttempts,
    retention: challengeRetention,
  });
  const passkeys = createPasskeyService({
    store: safe.store as Store,
    clock,
    rpName,
    rpID,
    origins,
    registrationLimiter: safe.registrationLimiter as RateLimiter,
    authenticationLimiter: safe.authenticationLimiter as RateLimiter,
    challengeService: challenges,
    users,
    newId,
  });

  return Object.freeze({
    provisionVerifiedUser: users.provisionVerifiedUser,
    repairUserByEmail: users.repairUserByEmail,
    findUserByEmail: users.findUserByEmail,
    getUser: users.getUser,
    claimsFor: users.claimsFor,
    beginPasskeyRegistration: passkeys.beginRegistration,
    finishPasskeyRegistration: passkeys.finishRegistration,
    beginPasskeyAuthentication: passkeys.beginAuthentication,
    finishPasskeyAuthentication: passkeys.finishAuthentication,
    listPasskeys: passkeys.listPasskeys,
    removePasskey: passkeys.removePasskey,
    repairPasskey: passkeys.repairPasskey,
    sweepChallenges: challenges.sweep,
  });
}

export { createMemoryChallengeRetention, IdentityError, normalizeEmail };
export type {
  AuthenticationStart,
  ChallengeSweepResult,
  ChallengeRetention,
  ChallengeRetentionReference,
  FinishAuthenticationInput,
  FinishRegistrationInput,
  IdentityErrorCode,
  Passkey,
  ProvisionVerifiedUserInput,
  RegistrationStart,
  User,
  VerifiedIdentityClaims,
};
