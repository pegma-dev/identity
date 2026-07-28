import type { DurableRateLimiter, RateLimiter } from "@pegma/rate-limit";
import { systemClock, type Clock, type PrincipalId } from "@pegma/spine";
import type { Store } from "@pegma/storage-core";

import {
  createChallengeService,
  type ChallengeSweepResult,
} from "./challenges.js";
import type { EmailCodeProtector } from "./crypto.js";
import {
  createEmailCodeService,
  type EmailCodeStart,
  type EmailOperationSweepResult,
  type FinishEmailChangeInput,
  type FinishEmailCodeInput,
  type IdentityMailRenderer,
  type IdentityMailContent,
} from "./email-codes.js";
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
  createIdentityMailService,
  type AcknowledgeTerminalMail,
  type AuthenticatedMailCallback,
  type IdentityMailWorkerOptions,
  type MailPageOptions,
  type MailProvider,
  type MailReconciliationPort,
  type MailWorker,
  type SweepTerminalMailOptions,
  type SweepTerminalMailResult,
} from "./identity-mail.js";
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
  readonly emailCodeProtector: EmailCodeProtector;
  readonly emailCodeRequestLimiter: DurableRateLimiter;
  readonly emailCodeVerificationLimiter: DurableRateLimiter;
  readonly clock?: Clock;
  readonly newId?: () => string;
  readonly challengeTtlMs?: number;
  readonly challengeMaxAttempts?: number;
  readonly repairDelayMs?: number;
  readonly emailCodeTtlMs?: number;
  readonly emailCodeMaxAttempts?: number;
  readonly emailOperationRetentionMs?: number;
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
  sweepChallenges(
    limit?: number,
    cursor?: string,
  ): Promise<ChallengeSweepResult>;
  beginAccountCreation(
    email: string,
    rateLimitKey: string,
  ): Promise<EmailCodeStart>;
  finishAccountCreation(
    input: FinishEmailCodeInput,
  ): Promise<VerifiedIdentityClaims>;
  beginEmailSignIn(
    email: string,
    rateLimitKey: string,
  ): Promise<EmailCodeStart>;
  finishEmailSignIn(
    input: FinishEmailCodeInput,
  ): Promise<VerifiedIdentityClaims>;
  beginRecovery(email: string, rateLimitKey: string): Promise<EmailCodeStart>;
  finishRecovery(input: FinishEmailCodeInput): Promise<VerifiedIdentityClaims>;
  beginEmailChange(
    principalId: PrincipalId,
    newEmail: string,
    rateLimitKey: string,
  ): Promise<EmailCodeStart>;
  finishEmailChange(input: FinishEmailChangeInput): Promise<User>;
  createMailWorker(options: IdentityMailWorkerOptions): MailWorker;
  applyAuthenticatedMailCallback(
    callback: AuthenticatedMailCallback,
  ): ReturnType<
    ReturnType<typeof createIdentityMailService>["applyAuthenticatedCallback"]
  >;
  acknowledgeTerminalMail(
    acknowledgement: AcknowledgeTerminalMail,
  ): ReturnType<
    ReturnType<typeof createIdentityMailService>["acknowledgeTerminal"]
  >;
  sweepMail(
    options: SweepTerminalMailOptions,
  ): Promise<SweepTerminalMailResult>;
  sweepEmailOperations(
    limit?: number,
    cursor?: string,
  ): Promise<EmailOperationSweepResult>;
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
  "emailCodeProtector",
  "emailCodeRequestLimiter",
  "emailCodeVerificationLimiter",
  "clock",
  "newId",
  "challengeTtlMs",
  "challengeMaxAttempts",
  "repairDelayMs",
  "emailCodeTtlMs",
  "emailCodeMaxAttempts",
  "emailOperationRetentionMs",
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

function hasDataMethods(value: unknown, names: readonly string[]): boolean {
  if (
    (typeof value !== "object" && typeof value !== "function") ||
    value === null
  ) {
    return false;
  }
  return names.every((name) => {
    let current: object | null = value;
    for (let depth = 0; current !== null && depth < 8; depth += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(current, name);
      if (descriptor !== undefined) {
        return "value" in descriptor && typeof descriptor.value === "function";
      }
      current = Object.getPrototypeOf(current);
    }
    return false;
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
  const emailCodeTtlMs = positiveBoundedInteger(
    safe.emailCodeTtlMs as number | undefined,
    10 * 60_000,
    15 * 60_000,
    "Email-code TTL",
  );
  const emailCodeMaxAttempts = positiveBoundedInteger(
    safe.emailCodeMaxAttempts as number | undefined,
    5,
    10,
    "Email-code attempt limit",
  );
  const emailOperationRetentionMs = positiveBoundedInteger(
    safe.emailOperationRetentionMs as number | undefined,
    7 * 24 * 60 * 60_000,
    90 * 24 * 60 * 60_000,
    "Email operation retention",
  );
  if (
    !hasDataMethods(safe.emailCodeProtector, [
      "deriveCode",
      "verifier",
      "matches",
    ]) ||
    !hasDataMethods(safe.emailCodeRequestLimiter, ["allow", "sweep"]) ||
    !hasDataMethods(safe.emailCodeVerificationLimiter, ["allow", "sweep"])
  ) {
    throw new IdentityError(
      "invalid_input",
      "Email-code security options are invalid.",
    );
  }
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
  const emailCodes = createEmailCodeService({
    store: safe.store as Store,
    clock,
    newId,
    users,
    protector: safe.emailCodeProtector as EmailCodeProtector,
    requestLimiter: safe.emailCodeRequestLimiter as DurableRateLimiter,
    verificationLimiter:
      safe.emailCodeVerificationLimiter as DurableRateLimiter,
    ttlMs: emailCodeTtlMs,
    maxAttempts: emailCodeMaxAttempts,
    retentionMs: emailOperationRetentionMs,
  });
  const mail = createIdentityMailService({
    store: safe.store as Store,
    clock,
    emailCodes,
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
    beginAccountCreation: emailCodes.beginAccountCreation,
    finishAccountCreation: emailCodes.finishAccountCreation,
    beginEmailSignIn: emailCodes.beginEmailSignIn,
    finishEmailSignIn: emailCodes.finishEmailSignIn,
    beginRecovery: emailCodes.beginRecovery,
    finishRecovery: emailCodes.finishRecovery,
    beginEmailChange: emailCodes.beginEmailChange,
    finishEmailChange: emailCodes.finishEmailChange,
    createMailWorker: mail.createWorker,
    applyAuthenticatedMailCallback: mail.applyAuthenticatedCallback,
    acknowledgeTerminalMail: mail.acknowledgeTerminal,
    sweepMail: mail.sweep,
    sweepEmailOperations: emailCodes.sweep,
  });
}

export { createHmacEmailCodeProtector } from "./crypto.js";
export { IdentityError } from "./errors.js";
export { normalizeEmail } from "./email.js";
export type {
  AuthenticationStart,
  ChallengeSweepResult,
  FinishAuthenticationInput,
  FinishRegistrationInput,
  IdentityErrorCode,
  Passkey,
  ProvisionVerifiedUserInput,
  RegistrationStart,
  User,
  VerifiedIdentityClaims,
  EmailCodeProtector,
  EmailCodeStart,
  EmailOperationSweepResult,
  FinishEmailChangeInput,
  FinishEmailCodeInput,
  IdentityMailRenderer,
  IdentityMailContent,
  IdentityMailWorkerOptions,
  AcknowledgeTerminalMail,
  AuthenticatedMailCallback,
  MailWorker,
  MailPageOptions,
  MailProvider,
  MailReconciliationPort,
  SweepTerminalMailOptions,
  SweepTerminalMailResult,
};
