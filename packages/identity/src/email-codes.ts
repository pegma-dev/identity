import type { MailPreparationRequest, PreparedMail } from "@pegma/mail";
import type { Clock, PrincipalId } from "@pegma/spine";
import type { DurableRateLimiter } from "@pegma/rate-limit";
import type { Store, TransactionAction } from "@pegma/storage-core";

import {
  emailCodeHandleHash,
  emailHash,
  principalHash,
  type EmailCodeProtector,
} from "./crypto.js";
import {
  emailOperationKey,
  emailOperationsCollection,
  identityMail,
  type EmailCodeOperationRecord,
  type EmailCodePurpose,
  type IdentityEmailOperationRecord,
  type SuppressedMailRecord,
} from "./email-operation-records.js";
import { normalizeEmail } from "./email.js";
import { IdentityError } from "./errors.js";
import type { User, UserService, VerifiedIdentityClaims } from "./users.js";
import {
  addMilliseconds,
  assertBoundedString,
  assertPrincipalId,
  copyDataOnly,
  dataField,
  timestampFromClock,
} from "./validation.js";

export interface EmailCodeStart {
  readonly codeHandle: string;
  readonly expiresAt: string;
}

export interface FinishEmailCodeInput {
  readonly codeHandle: string;
  readonly code: string;
  readonly rateLimitKey: string;
}

export interface FinishEmailChangeInput extends FinishEmailCodeInput {
  readonly principalId: PrincipalId;
}

export interface IdentityMailContent {
  readonly purpose: EmailCodePurpose | "email_changed";
  readonly code?: string;
  readonly expiresAt?: string;
  readonly newEmail?: string;
  readonly expired: boolean;
}

export interface IdentityMailRenderer {
  render(content: IdentityMailContent): Promise<{
    readonly subject: string;
    readonly text: string;
    readonly html?: string;
    readonly headers?: Readonly<Record<string, string>>;
  }>;
}

export interface EmailOperationSweepResult {
  readonly inspected: number;
  readonly repaired: number;
  readonly failed: number;
  readonly rejected: number;
  readonly deleted: number;
  readonly cursor: string | null;
  readonly hasMore: boolean;
}

interface EmailCodeServiceOptions {
  readonly store: Store;
  readonly clock: Clock;
  readonly newId: () => string;
  readonly users: UserService;
  readonly protector: EmailCodeProtector;
  readonly requestLimiter: DurableRateLimiter;
  readonly verificationLimiter: DurableRateLimiter;
  readonly ttlMs: number;
  readonly maxAttempts: number;
  readonly retentionMs: number;
}

export interface EmailCodeService {
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
  prepareMail(
    request: MailPreparationRequest,
    renderer: IdentityMailRenderer,
  ): Promise<PreparedMail>;
  sweep(limit?: number, cursor?: string): Promise<EmailOperationSweepResult>;
}

function verificationFailure(): IdentityError {
  return new IdentityError("verification_failed", "Email verification failed.");
}

function limiterKey(input: unknown): string {
  return assertBoundedString(input, "Rate-limit key", 512);
}

function retryAfter(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    return 60_000;
  }
  return value;
}

async function enforceBoth(
  limiter: DurableRateLimiter,
  first: string,
  second: string,
): Promise<void> {
  const results = await Promise.allSettled([
    limiter.allow(first),
    limiter.allow(second),
  ]);
  let denied = false;
  let wait = 0;
  for (const result of results) {
    if (
      result.status === "rejected" ||
      typeof result.value !== "object" ||
      result.value === null ||
      result.value.allowed !== true
    ) {
      denied = true;
      wait = Math.max(
        wait,
        result.status === "fulfilled"
          ? retryAfter(result.value.retryAfter)
          : 60_000,
      );
    }
  }
  if (denied) {
    throw new IdentityError("rate_limited", "Email request was rate limited.", {
      retryAfter: wait || 60_000,
    });
  }
}

function publicStart(codeHandle: string, expiresAt: string): EmailCodeStart {
  return Object.freeze({ codeHandle, expiresAt });
}

function contentRef(
  purpose: EmailCodePurpose | "email_changed",
  handleHash: string,
): string {
  return `pegma-identity-code:v1:${purpose}:${handleHash}`;
}

function parseContentRef(value: string): {
  readonly purpose: EmailCodePurpose | "email_changed";
  readonly handleHash: string;
} {
  const parts = value.split(":");
  if (
    parts.length !== 4 ||
    parts[0] !== "pegma-identity-code" ||
    parts[1] !== "v1" ||
    !/^[0-9a-f]{64}$/u.test(parts[3] ?? "")
  ) {
    throw new IdentityError(
      "invalid_state",
      "Identity mail content reference is invalid.",
    );
  }
  const purpose = parts[2];
  if (
    purpose !== "account_creation" &&
    purpose !== "email_sign_in" &&
    purpose !== "recovery" &&
    purpose !== "email_change" &&
    purpose !== "email_changed"
  ) {
    throw new IdentityError(
      "invalid_state",
      "Identity mail content reference is invalid.",
    );
  }
  return { purpose, handleHash: parts[3]! };
}

export function createEmailCodeService(
  options: EmailCodeServiceOptions,
): EmailCodeService {
  const records = options.store.collection(emailOperationsCollection);

  async function validateOperationBindings(
    operation: EmailCodeOperationRecord,
  ): Promise<void> {
    const checks: Promise<boolean>[] = [
      emailHash(operation.targetEmail).then(
        (digest) =>
          normalizeEmail(operation.targetEmail) === operation.targetEmail &&
          digest === operation.targetEmailHash,
      ),
    ];
    if (operation.principalId !== null && operation.principalHash !== null) {
      checks.push(
        principalHash(operation.principalId).then(
          (digest) => digest === operation.principalHash,
        ),
      );
    }
    if (
      operation.proposedPrincipalId !== null &&
      operation.proposedPrincipalHash !== null
    ) {
      checks.push(
        principalHash(operation.proposedPrincipalId).then(
          (digest) => digest === operation.proposedPrincipalHash,
        ),
      );
    }
    if (operation.oldEmail !== null && operation.oldEmailHash !== null) {
      checks.push(
        emailHash(operation.oldEmail).then(
          (digest) =>
            normalizeEmail(operation.oldEmail!) === operation.oldEmail &&
            digest === operation.oldEmailHash,
        ),
      );
    }
    if (
      operation.resultPrincipalId !== null &&
      operation.resultPrincipalHash !== null
    ) {
      checks.push(
        principalHash(operation.resultPrincipalId).then(
          (digest) => digest === operation.resultPrincipalHash,
        ),
      );
    }
    const results = await Promise.allSettled(checks);
    if (
      results.some(
        (result) => result.status === "rejected" || result.value !== true,
      )
    ) {
      throw new IdentityError(
        "storage_corrupt",
        "Stored email operation binding is malformed.",
      );
    }
  }

  async function activeUser(email: string): Promise<User | null> {
    return options.users.activeUserForEmail(email);
  }

  async function begin(
    purpose: EmailCodePurpose,
    inputEmail: unknown,
    inputRateLimitKey: unknown,
    principalInput?: unknown,
  ): Promise<EmailCodeStart> {
    const email = normalizeEmail(inputEmail);
    const rateKey = limiterKey(inputRateLimitKey);
    const targetEmailHash = await emailHash(email);
    await enforceBoth(
      options.requestLimiter,
      `source:${rateKey}`,
      `address:${targetEmailHash}`,
    );
    const known = await activeUser(email);

    let principalId: string | null = known?.principalId ?? null;
    const bindingDigest = await principalHash(
      principalId ?? `email-decoy-binding:${targetEmailHash}`,
    );
    let principalDigest: string | null =
      principalId === null ? null : bindingDigest;
    let oldEmail: string | null = null;
    let oldEmailHash: string | null = null;
    if (purpose === "email_change") {
      const requestedPrincipal = assertPrincipalId(principalInput);
      const current = await options.users.getUser(requestedPrincipal);
      if (
        current === null ||
        current.status !== "active" ||
        !current.emailVerified
      ) {
        throw verificationFailure();
      }
      principalId = requestedPrincipal;
      principalDigest = await principalHash(requestedPrincipal);
      oldEmail = current.email;
      oldEmailHash = await emailHash(current.email);
      if (oldEmailHash === targetEmailHash) {
        throw new IdentityError(
          "invalid_input",
          "New email must differ from the current email.",
        );
      }
    }

    for (let allocation = 0; allocation < 4; allocation += 1) {
      const codeHandle = assertBoundedString(
        options.newId(),
        "Generated email-code handle",
        256,
      );
      const handleHash = await emailCodeHandleHash(codeHandle);
      const code = await options.protector.deriveCode(handleHash);
      const codeVerifier = await options.protector.verifier(handleHash, code);
      if (
        typeof code !== "string" ||
        typeof codeVerifier !== "string" ||
        !/^\d{8}$/u.test(code) ||
        !/^[0-9a-f]{64}$/u.test(codeVerifier)
      ) {
        throw new IdentityError(
          "invalid_state",
          "Email code protector returned malformed material.",
        );
      }
      const { value: now, milliseconds } = timestampFromClock(options.clock);
      const expiresAt = addMilliseconds(milliseconds, options.ttlMs);
      let proposedPrincipalId: string | null = null;
      let proposedPrincipalHash: string | null = null;
      if (purpose === "account_creation") {
        const candidatePrincipalId = assertPrincipalId(options.newId());
        const candidatePrincipalHash =
          await principalHash(candidatePrincipalId);
        if (principalId === null) {
          proposedPrincipalId = candidatePrincipalId;
          proposedPrincipalHash = candidatePrincipalHash;
        }
      }
      const deliverable =
        purpose === "account_creation" ||
        purpose === "email_change" ||
        principalId !== null;
      const partition = emailOperationKey(handleHash).partition;
      const mailJobId = "verification-mail";
      const operation: EmailCodeOperationRecord = {
        kind: "operation",
        schemaVersion: 1,
        partition,
        id: handleHash,
        purpose,
        handleHash,
        codeVerifier,
        targetEmail: email,
        targetEmailHash,
        principalId,
        principalHash: principalDigest,
        proposedPrincipalId,
        proposedPrincipalHash,
        oldEmail,
        oldEmailHash,
        state: "pending",
        attempts: 0,
        maxAttempts: options.maxAttempts,
        effectState: "none",
        resultPrincipalId: null,
        resultPrincipalHash: null,
        deliverable,
        mailJobId,
        notificationJobId: null,
        createdAt: now,
        expiresAt,
        consumedAt: null,
        updatedAt: now,
        completedAt: null,
      };
      const deliver = identityMail.action({
        partition,
        id: mailJobId,
        recipientRef: email,
        contentRef: contentRef(purpose, handleHash),
        createdAt: now,
        maxAttempts: 5,
      });
      const suppressed: SuppressedMailRecord = {
        kind: "suppressed_mail",
        partition,
        id: mailJobId,
        handleHash,
        createdAt: now,
      };
      const outcome = await records.transact(partition, [
        { action: "insert", value: operation },
        deliverable
          ? deliver
          : {
              action: "insert",
              value: suppressed as IdentityEmailOperationRecord,
            },
      ]);
      if (outcome.committed) {
        return publicStart(codeHandle, expiresAt);
      }
    }
    throw new IdentityError(
      "invalid_state",
      "Could not allocate an email verification operation.",
    );
  }

  async function claim(
    expectedPurpose: EmailCodePurpose,
    input: FinishEmailCodeInput,
    principalInput?: unknown,
  ): Promise<EmailCodeOperationRecord> {
    let safe: unknown;
    let malformed = false;
    try {
      safe = copyDataOnly(input);
      if (
        typeof safe !== "object" ||
        safe === null ||
        Array.isArray(safe) ||
        Object.keys(safe).sort().join(",") !==
          (principalInput === undefined
            ? "code,codeHandle,rateLimitKey"
            : "code,codeHandle,principalId,rateLimitKey")
      ) {
        malformed = true;
      }
    } catch {
      safe = Object.create(null);
      malformed = true;
    }
    let handle = "invalid-email-code-handle";
    let code = "";
    let rateKey = "invalid-email-code-source";
    let requestedPrincipal: PrincipalId | null = null;
    try {
      handle = assertBoundedString(
        dataField(safe, "codeHandle"),
        "Email-code handle",
        256,
      );
      const candidate = dataField(safe, "code");
      if (
        typeof candidate !== "string" ||
        candidate.length > 32 ||
        !candidate.isWellFormed()
      ) {
        malformed = true;
      } else {
        code = candidate;
      }
      rateKey = limiterKey(dataField(safe, "rateLimitKey"));
      if (principalInput !== undefined) {
        requestedPrincipal = assertPrincipalId(dataField(safe, "principalId"));
      }
    } catch {
      malformed = true;
    }
    const handleHash = await emailCodeHandleHash(handle);
    await enforceBoth(
      options.verificationLimiter,
      `source:${rateKey}`,
      `operation:${handleHash}`,
    );
    if (malformed) {
      throw verificationFailure();
    }
    const key = emailOperationKey(handleHash);
    for (let attempt = 0; attempt < 10; attempt += 1) {
      const seen = await records.getVersioned(key);
      const operation =
        seen?.value.kind === "operation" &&
        seen.value.purpose === expectedPurpose &&
        seen.value.handleHash === handleHash &&
        seen.value.state === "pending"
          ? seen.value
          : null;
      if (operation === null || seen === null) {
        throw verificationFailure();
      }
      await validateOperationBindings(operation);
      const matchResult: unknown = await options.protector.matches(
        operation.codeVerifier,
        handleHash,
        code,
      );
      if (typeof matchResult !== "boolean") {
        throw new IdentityError(
          "invalid_state",
          "Email code protector returned malformed material.",
        );
      }
      const candidateMatches = matchResult === true;
      const { value: now, milliseconds } = timestampFromClock(options.clock);
      const expired = Date.parse(operation.expiresAt) <= milliseconds;
      const nextAttempts = Math.min(
        operation.maxAttempts,
        operation.attempts + 1,
      );
      const principalMatches =
        requestedPrincipal === null ||
        operation.principalId === requestedPrincipal;
      const next: EmailCodeOperationRecord =
        expired || !candidateMatches || !principalMatches
          ? {
              ...operation,
              state:
                expired || nextAttempts >= operation.maxAttempts
                  ? "failed"
                  : operation.state,
              attempts: nextAttempts,
              consumedAt:
                expired || nextAttempts >= operation.maxAttempts
                  ? now
                  : operation.consumedAt,
              updatedAt: now,
            }
          : {
              ...operation,
              state: "consumed",
              attempts: nextAttempts,
              effectState:
                expectedPurpose === "account_creation" ||
                expectedPurpose === "email_change"
                  ? "pending"
                  : "complete",
              consumedAt: now,
              updatedAt: now,
              completedAt:
                expectedPurpose === "account_creation" ||
                expectedPurpose === "email_change"
                  ? null
                  : now,
            };
      if (!(await records.putIfUnchanged(next, seen.version))) {
        continue;
      }
      if (!candidateMatches || !principalMatches || next.state !== "consumed") {
        throw verificationFailure();
      }
      return next;
    }
    throw verificationFailure();
  }

  async function completeOperation(
    operation: EmailCodeOperationRecord,
    user: User,
    notification = false,
  ): Promise<void> {
    const userHash = await principalHash(user.principalId);
    for (let attempt = 0; attempt < 10; attempt += 1) {
      const versioned = await records.getVersioned(
        emailOperationKey(operation.handleHash),
      );
      if (versioned === null || versioned.value.kind !== "operation") {
        throw new IdentityError(
          "invalid_state",
          "Email operation disappeared during repair.",
        );
      }
      if (versioned.value.effectState === "complete") {
        return;
      }
      const now = timestampFromClock(options.clock).value;
      const completed: EmailCodeOperationRecord = {
        ...versioned.value,
        effectState: "complete",
        resultPrincipalId: user.principalId,
        resultPrincipalHash: userHash,
        notificationJobId: notification
          ? "old-address-notification"
          : versioned.value.notificationJobId,
        updatedAt: now,
        completedAt: now,
      };
      const actions: TransactionAction<IdentityEmailOperationRecord>[] = [
        {
          action: "putIfUnchanged",
          value: completed,
          version: versioned.version,
        },
      ];
      if (
        notification &&
        versioned.value.oldEmail !== null &&
        versioned.value.notificationJobId === null
      ) {
        actions.push(
          identityMail.action({
            partition: operation.partition,
            id: "old-address-notification",
            recipientRef: versioned.value.oldEmail,
            contentRef: contentRef("email_changed", operation.handleHash),
            createdAt: now,
            maxAttempts: 5,
          }),
        );
      }
      const outcome = await records.transact(operation.partition, actions);
      if (outcome.committed) {
        return;
      }
    }
    throw new IdentityError(
      "invalid_state",
      "Email operation repair did not converge.",
    );
  }

  async function failOperation(
    operation: EmailCodeOperationRecord,
  ): Promise<void> {
    const now = timestampFromClock(options.clock).value;
    await records.update(
      emailOperationKey(operation.handleHash),
      (current) =>
        current?.kind === "operation" &&
        current.state === "consumed" &&
        (current.effectState === "pending" ||
          current.effectState === "applying")
          ? {
              action: "write",
              value: {
                ...current,
                effectState: "failed",
                updatedAt: now,
                completedAt: now,
              },
            }
          : { action: "keep" },
      { maxAttempts: 10 },
    );
  }

  function terminalEffectFailure(error: unknown): boolean {
    return (
      error instanceof IdentityError &&
      (error.code === "verification_failed" || error.code === "conflict")
    );
  }

  async function repair(
    operation: EmailCodeOperationRecord,
  ): Promise<User | null> {
    await validateOperationBindings(operation);
    if (operation.state !== "consumed") {
      return null;
    }
    if (operation.effectState === "failed") {
      return null;
    }
    if (operation.effectState === "complete") {
      if (operation.resultPrincipalId === null) {
        return null;
      }
      if (
        operation.purpose === "email_change" &&
        operation.principalId !== null
      ) {
        return options.users.finalizeVerifiedEmailChange({
          principalId: operation.principalId as PrincipalId,
          newEmail: operation.targetEmail,
          operationHash: operation.handleHash,
        });
      }
      return options.users.getUser(operation.resultPrincipalId as PrincipalId);
    }
    if (operation.purpose === "account_creation") {
      let user: User;
      if (operation.principalId !== null) {
        const active = await activeUser(operation.targetEmail);
        if (active === null || active.principalId !== operation.principalId) {
          throw verificationFailure();
        }
        user = active;
      } else {
        if (operation.proposedPrincipalId === null) {
          throw new IdentityError(
            "storage_corrupt",
            "Creation operation has no proposed principal.",
          );
        }
        user = await options.users.provisionVerifiedUser({
          principalId: operation.proposedPrincipalId as PrincipalId,
          email: operation.targetEmail,
        });
      }
      await completeOperation(operation, user);
      return user;
    }
    if (operation.purpose === "email_change") {
      if (operation.principalId === null || operation.oldEmailHash === null) {
        throw new IdentityError(
          "storage_corrupt",
          "Email change operation has no owner.",
        );
      }
      const user = await options.users.changeVerifiedEmail({
        principalId: operation.principalId as PrincipalId,
        oldEmailHash: operation.oldEmailHash,
        newEmail: operation.targetEmail,
        operationHash: operation.handleHash,
      });
      await completeOperation(operation, user, true);
      return options.users.finalizeVerifiedEmailChange({
        principalId: operation.principalId as PrincipalId,
        newEmail: operation.targetEmail,
        operationHash: operation.handleHash,
      });
    }
    return null;
  }

  async function finishClaims(
    purpose: "email_sign_in" | "recovery",
    input: FinishEmailCodeInput,
  ): Promise<VerifiedIdentityClaims> {
    const operation = await claim(purpose, input);
    if (operation.principalId === null || !operation.deliverable) {
      throw verificationFailure();
    }
    const active = await activeUser(operation.targetEmail);
    if (
      active === null ||
      active.principalId !== operation.principalId ||
      !active.emailVerified ||
      active.status !== "active"
    ) {
      throw verificationFailure();
    }
    return options.users.claimsFor(operation.principalId as PrincipalId);
  }

  return {
    beginAccountCreation: (email, rateKey) =>
      begin("account_creation", email, rateKey),
    async finishAccountCreation(input) {
      const operation = await claim("account_creation", input);
      let user: User | null;
      try {
        user = await repair(operation);
      } catch (error) {
        if (terminalEffectFailure(error)) {
          await failOperation(operation);
          throw verificationFailure();
        }
        throw error;
      }
      if (user === null) {
        throw verificationFailure();
      }
      return options.users.claimsFor(user.principalId);
    },
    beginEmailSignIn: (email, rateKey) =>
      begin("email_sign_in", email, rateKey),
    finishEmailSignIn: (input) => finishClaims("email_sign_in", input),
    beginRecovery: (email, rateKey) => begin("recovery", email, rateKey),
    finishRecovery: (input) => finishClaims("recovery", input),
    beginEmailChange: (principalId, newEmail, rateKey) =>
      begin("email_change", newEmail, rateKey, principalId),
    async finishEmailChange(input) {
      const operation = await claim("email_change", input, true);
      if (operation.principalId === null) {
        throw verificationFailure();
      }
      const principalId = operation.principalId as PrincipalId;
      let user: User | null;
      try {
        user = await repair(operation);
      } catch (error) {
        if (terminalEffectFailure(error)) {
          await failOperation(operation);
          throw verificationFailure();
        }
        throw error;
      }
      if (user === null || user.principalId !== principalId) {
        throw verificationFailure();
      }
      return user;
    },
    async prepareMail(request, renderer) {
      const reference = parseContentRef(request.contentRef);
      const operation = await records.get(
        emailOperationKey(reference.handleHash),
      );
      if (operation === null || operation.kind !== "operation") {
        throw new IdentityError(
          "invalid_state",
          "Identity mail operation is unavailable.",
        );
      }
      await validateOperationBindings(operation);
      const notification = reference.purpose === "email_changed";
      const bound =
        request.partition === operation.partition &&
        (notification
          ? request.jobId === operation.notificationJobId &&
            request.jobId === "old-address-notification" &&
            request.recipientRef === operation.oldEmail &&
            operation.purpose === "email_change" &&
            operation.state === "consumed" &&
            operation.effectState === "complete" &&
            operation.completedAt !== null
          : request.jobId === operation.mailJobId &&
            request.jobId === "verification-mail" &&
            request.recipientRef === operation.targetEmail &&
            reference.purpose === operation.purpose &&
            operation.deliverable);
      if (!bound) {
        throw new IdentityError(
          "storage_corrupt",
          "Identity mail binding is malformed.",
        );
      }
      const now = timestampFromClock(options.clock).milliseconds;
      const expired =
        operation.state !== "pending" || Date.parse(operation.expiresAt) <= now;
      const rendered = notification
        ? await renderer.render({
            purpose: "email_changed",
            newEmail: operation.targetEmail,
            expired: false,
          })
        : await renderer.render({
            purpose: operation.purpose,
            ...(expired
              ? {}
              : {
                  code: await options.protector
                    .deriveCode(operation.handleHash)
                    .then((code) => {
                      if (typeof code !== "string" || !/^\d{8}$/u.test(code)) {
                        throw new IdentityError(
                          "invalid_state",
                          "Email code protector returned malformed material.",
                        );
                      }
                      return code;
                    }),
                }),
            expiresAt: operation.expiresAt,
            expired,
          });
      return {
        recipient: request.recipientRef,
        ...rendered,
      };
    },
    async sweep(limitInput = 100, cursorInput) {
      if (
        !Number.isSafeInteger(limitInput) ||
        limitInput < 1 ||
        limitInput > 1_000
      ) {
        throw new IdentityError("invalid_input", "Sweep limit is invalid.");
      }
      const cursor =
        cursorInput === undefined
          ? undefined
          : assertBoundedString(cursorInput, "Sweep cursor", 16_384);
      const page = await records.scan({
        limit: limitInput,
        ...(cursor === undefined ? {} : { cursor }),
      });
      const now = timestampFromClock(options.clock).milliseconds;
      let repaired = 0;
      let failed = 0;
      let rejected = 0;
      let deleted = 0;
      for (const row of page.records) {
        if (row.value.kind === "invalid") {
          rejected += 1;
          continue;
        }
        if (row.value.kind !== "operation") {
          continue;
        }
        const operation = row.value;
        try {
          await validateOperationBindings(operation);
        } catch {
          rejected += 1;
          continue;
        }
        const pendingEffect =
          operation.effectState === "pending" ||
          operation.effectState === "applying";
        const finalizationHandoff =
          operation.effectState === "complete" &&
          operation.purpose === "email_change";
        if (
          operation.state === "consumed" &&
          (pendingEffect || finalizationHandoff)
        ) {
          let repairSucceeded = false;
          try {
            if ((await repair(operation)) !== null) {
              repaired += 1;
              repairSucceeded = true;
            }
          } catch (error) {
            if (terminalEffectFailure(error)) {
              await failOperation(operation);
            }
            failed += 1;
          }
          if (pendingEffect || !repairSucceeded) {
            continue;
          }
        }
        if (
          operation.state === "pending" &&
          Date.parse(operation.expiresAt) <= now
        ) {
          const updated = await records.update(
            emailOperationKey(operation.handleHash),
            (current) =>
              current?.kind === "operation" &&
              current.state === "pending" &&
              Date.parse(current.expiresAt) <= now
                ? {
                    action: "write",
                    value: {
                      ...current,
                      state: "failed",
                      consumedAt: timestampFromClock(options.clock).value,
                      updatedAt: timestampFromClock(options.clock).value,
                    },
                  }
                : { action: "keep" },
            { maxAttempts: 10 },
          );
          if (updated.written) {
            failed += 1;
          }
          continue;
        }
        const terminalAt =
          operation.completedAt ?? operation.consumedAt ?? operation.updatedAt;
        if (
          operation.state !== "pending" &&
          Date.parse(terminalAt) + options.retentionMs <= now
        ) {
          const siblings = await records.listVersioned(operation.partition);
          const liveMail = siblings.some(
            ({ value: sibling }) =>
              sibling.kind === "mail" &&
              sibling.job.status !== "delivered" &&
              sibling.job.status !== "dead_letter" &&
              sibling.job.status !== "terminal_unknown",
          );
          if (!liveMail) {
            for (const sibling of siblings) {
              if (
                sibling.value.kind === "suppressed_mail" &&
                sibling.value.handleHash === operation.handleHash
              ) {
                await records.deleteIfUnchanged(
                  {
                    partition: sibling.value.partition,
                    id: sibling.value.id,
                  },
                  sibling.version,
                );
              }
            }
            if (await records.deleteIfUnchanged(row.key, row.version)) {
              deleted += 1;
            }
          }
        }
      }
      return Object.freeze({
        inspected: page.records.length,
        repaired,
        failed,
        rejected,
        deleted,
        cursor: page.nextCursor,
        hasMore: page.nextCursor !== null,
      });
    },
  };
}
