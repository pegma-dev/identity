import {
  defineMail,
  mailIdempotencyKey,
  type MailJob,
  type MailStatus,
} from "@pegma/mail";
import { defineCollection, type StoredRecord } from "@pegma/storage-core";

import { IdentityError } from "./errors.js";
import {
  assertCanonicalTimestamp,
  assertHash,
  readDataProperty,
  storedBoolean,
  storedNullableString,
  storedSafeInteger,
  storedString,
} from "./validation.js";

export type EmailCodePurpose =
  "account_creation" | "email_sign_in" | "recovery" | "email_change";
export type EmailCodeState = "pending" | "consumed" | "failed";
export type EmailCodeEffectState =
  "none" | "pending" | "applying" | "complete" | "failed";

export interface EmailCodeOperationRecord {
  readonly kind: "operation";
  readonly schemaVersion: 1;
  readonly partition: string;
  readonly id: string;
  readonly purpose: EmailCodePurpose;
  readonly handleHash: string;
  readonly codeVerifier: string;
  readonly targetEmail: string;
  readonly targetEmailHash: string;
  readonly principalId: string | null;
  readonly principalHash: string | null;
  readonly proposedPrincipalId: string | null;
  readonly proposedPrincipalHash: string | null;
  readonly oldEmail: string | null;
  readonly oldEmailHash: string | null;
  readonly state: EmailCodeState;
  readonly attempts: number;
  readonly maxAttempts: number;
  readonly effectState: EmailCodeEffectState;
  readonly resultPrincipalId: string | null;
  readonly resultPrincipalHash: string | null;
  readonly deliverable: boolean;
  readonly mailJobId: string;
  readonly notificationJobId: string | null;
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly consumedAt: string | null;
  readonly updatedAt: string;
  readonly completedAt: string | null;
}

export interface IdentityMailRecord {
  readonly kind: "mail";
  readonly partition: string;
  readonly id: string;
  readonly job: MailJob;
}

export interface SuppressedMailRecord {
  readonly kind: "suppressed_mail";
  readonly partition: string;
  readonly id: string;
  readonly handleHash: string;
  readonly createdAt: string;
}

export interface InvalidIdentityEmailRecord {
  readonly kind: "invalid";
  readonly partition: "invalid";
  readonly id: "invalid";
}

export type IdentityEmailOperationRecord =
  | EmailCodeOperationRecord
  | IdentityMailRecord
  | SuppressedMailRecord
  | InvalidIdentityEmailRecord;

const PURPOSES: readonly EmailCodePurpose[] = [
  "account_creation",
  "email_sign_in",
  "recovery",
  "email_change",
];
const CODE_STATES: readonly EmailCodeState[] = [
  "pending",
  "consumed",
  "failed",
];
const EFFECT_STATES: readonly EmailCodeEffectState[] = [
  "none",
  "pending",
  "applying",
  "complete",
  "failed",
];
const MAIL_STATUSES: readonly MailStatus[] = [
  "pending",
  "sending",
  "retrying",
  "accepted",
  "reconciling",
  "delivered",
  "dead_letter",
  "terminal_unknown",
];

function timestamp(record: StoredRecord, name: string): string {
  return assertCanonicalTimestamp(readDataProperty(record, name), name);
}

function nullableTimestamp(record: StoredRecord, name: string): string | null {
  const value = storedNullableString(record, name, 64);
  return value === null ? null : assertCanonicalTimestamp(value, name);
}

function enumValue<T extends string>(
  record: StoredRecord,
  name: string,
  values: readonly T[],
): T {
  const value = storedString(record, name, 64);
  if (!values.includes(value as T)) {
    throw new IdentityError(
      "storage_corrupt",
      `Stored property ${name} is malformed.`,
    );
  }
  return value as T;
}

function partitionFor(handleHash: string): string {
  return `email-operation-${handleHash}`;
}

export function emailOperationKey(handleHash: string) {
  return { partition: partitionFor(handleHash), id: handleHash };
}

function decodeOperation(record: StoredRecord): EmailCodeOperationRecord {
  const handleHash = assertHash(
    storedString(record, "handleHash", 64),
    "handleHash",
  );
  const targetEmailHash = assertHash(
    storedString(record, "targetEmailHash", 64),
    "targetEmailHash",
  );
  const principalId = storedNullableString(record, "principalId", 512);
  const principalHashValue = storedNullableString(record, "principalHash", 64);
  const proposedPrincipalId = storedNullableString(
    record,
    "proposedPrincipalId",
    512,
  );
  const proposedPrincipalHashValue = storedNullableString(
    record,
    "proposedPrincipalHash",
    64,
  );
  const oldEmail = storedNullableString(record, "oldEmail", 254);
  const oldEmailHashValue = storedNullableString(record, "oldEmailHash", 64);
  const resultPrincipalId = storedNullableString(
    record,
    "resultPrincipalId",
    512,
  );
  const resultPrincipalHashValue = storedNullableString(
    record,
    "resultPrincipalHash",
    64,
  );
  const notificationJobId = storedNullableString(
    record,
    "notificationJobId",
    200,
  );
  const decoded: EmailCodeOperationRecord = {
    kind: "operation",
    schemaVersion: storedSafeInteger(record, "schemaVersion", 1) as 1,
    partition: storedString(record, "partition", 96),
    id: assertHash(storedString(record, "id", 64), "id"),
    purpose: enumValue(record, "purpose", PURPOSES),
    handleHash,
    codeVerifier: assertHash(
      storedString(record, "codeVerifier", 64),
      "codeVerifier",
    ),
    targetEmail: storedString(record, "targetEmail", 254),
    targetEmailHash,
    principalId,
    principalHash:
      principalHashValue === null
        ? null
        : assertHash(principalHashValue, "principalHash"),
    proposedPrincipalId,
    proposedPrincipalHash:
      proposedPrincipalHashValue === null
        ? null
        : assertHash(proposedPrincipalHashValue, "proposedPrincipalHash"),
    oldEmail,
    oldEmailHash:
      oldEmailHashValue === null
        ? null
        : assertHash(oldEmailHashValue, "oldEmailHash"),
    state: enumValue(record, "state", CODE_STATES),
    attempts: storedSafeInteger(record, "attempts"),
    maxAttempts: storedSafeInteger(record, "maxAttempts", 1),
    effectState: enumValue(record, "effectState", EFFECT_STATES),
    resultPrincipalId,
    resultPrincipalHash:
      resultPrincipalHashValue === null
        ? null
        : assertHash(resultPrincipalHashValue, "resultPrincipalHash"),
    deliverable: storedBoolean(record, "deliverable"),
    mailJobId: storedString(record, "mailJobId", 200),
    notificationJobId,
    createdAt: timestamp(record, "createdAt"),
    expiresAt: timestamp(record, "expiresAt"),
    consumedAt: nullableTimestamp(record, "consumedAt"),
    updatedAt: timestamp(record, "updatedAt"),
    completedAt: nullableTimestamp(record, "completedAt"),
  };
  const created = Date.parse(decoded.createdAt);
  const expires = Date.parse(decoded.expiresAt);
  const updated = Date.parse(decoded.updatedAt);
  const consumed =
    decoded.consumedAt === null ? null : Date.parse(decoded.consumedAt);
  const completed =
    decoded.completedAt === null ? null : Date.parse(decoded.completedAt);
  if (
    decoded.schemaVersion !== 1 ||
    decoded.id !== handleHash ||
    decoded.partition !== partitionFor(handleHash) ||
    decoded.attempts > decoded.maxAttempts ||
    decoded.mailJobId !== "verification-mail" ||
    (decoded.notificationJobId !== null &&
      decoded.notificationJobId !== "old-address-notification") ||
    decoded.maxAttempts > 10 ||
    expires <= created ||
    expires - created > 15 * 60_000 ||
    updated < created ||
    (decoded.state === "pending" && updated > expires) ||
    (decoded.state === "pending" && decoded.attempts >= decoded.maxAttempts) ||
    (decoded.state !== "pending" && decoded.attempts === 0) ||
    (consumed !== null && (consumed < created || consumed > updated)) ||
    (completed !== null &&
      (consumed === null || completed < consumed || completed > updated)) ||
    (principalId === null) !== (decoded.principalHash === null) ||
    (proposedPrincipalId === null) !==
      (decoded.proposedPrincipalHash === null) ||
    (oldEmail === null) !== (decoded.oldEmailHash === null) ||
    (resultPrincipalId === null) !== (decoded.resultPrincipalHash === null) ||
    (decoded.purpose === "email_change") !== (oldEmail !== null) ||
    (decoded.purpose !== "account_creation" && proposedPrincipalId !== null) ||
    (decoded.purpose === "account_creation" &&
      (principalId === null) === (proposedPrincipalId === null)) ||
    (decoded.purpose === "email_change" && principalId === null) ||
    decoded.deliverable !==
      (decoded.purpose === "account_creation" ||
        decoded.purpose === "email_change" ||
        principalId !== null) ||
    (decoded.state === "pending") !== (decoded.consumedAt === null) ||
    (decoded.effectState === "complete" || decoded.effectState === "failed") !==
      (decoded.completedAt !== null) ||
    (decoded.state === "pending" && decoded.effectState !== "none") ||
    (decoded.state === "failed" && decoded.effectState !== "none") ||
    (decoded.state === "consumed" && decoded.effectState === "none") ||
    ((decoded.purpose === "account_creation" ||
      decoded.purpose === "email_change") &&
      decoded.effectState === "complete" &&
      decoded.resultPrincipalId === null) ||
    (decoded.effectState !== "complete" &&
      decoded.resultPrincipalId !== null) ||
    (decoded.purpose === "email_change" &&
      decoded.effectState === "complete" &&
      decoded.notificationJobId === null) ||
    (decoded.purpose !== "email_change" && decoded.notificationJobId !== null)
  ) {
    throw new IdentityError(
      "storage_corrupt",
      "Stored email operation is malformed.",
    );
  }
  return decoded;
}

function optionalString(
  record: StoredRecord,
  name: string,
  maximum: number,
): string | undefined {
  const value = storedNullableString(record, name, maximum);
  return value ?? undefined;
}

function decodeMail(record: StoredRecord): IdentityMailRecord {
  const partition = storedString(record, "partition", 300);
  const id = storedString(record, "id", 200);
  const status = enumValue(record, "mailStatus", MAIL_STATUSES);
  const submissionGeneration = storedSafeInteger(
    record,
    "submissionGeneration",
    1,
  );
  const attemptCount = storedSafeInteger(record, "attemptCount");
  const maxAttempts = storedSafeInteger(record, "maxAttempts", 1);
  const claimToken = optionalString(record, "claimToken", 512);
  const leaseOwner = optionalString(record, "leaseOwner", 200);
  const leaseExpiresAt = nullableTimestamp(record, "leaseExpiresAt");
  const acceptedAt = nullableTimestamp(record, "acceptedAt");
  const acceptedDeadlineAt = nullableTimestamp(record, "acceptedDeadlineAt");
  const deliveredAt = nullableTimestamp(record, "deliveredAt");
  const terminalAt = nullableTimestamp(record, "terminalAt");
  const providerMessageRef = optionalString(record, "providerMessageRef", 512);
  const providerOccurredAt = nullableTimestamp(record, "providerOccurredAt");
  const failureCategory = optionalString(record, "failureCategory", 64);
  const acknowledgedAt = nullableTimestamp(record, "acknowledgedAt");
  const acknowledgementRef = optionalString(record, "acknowledgementRef", 512);
  const job: MailJob = {
    partition,
    id,
    submissionGeneration,
    idempotencyKey: storedString(record, "idempotencyKey", 255),
    recipientRef: storedString(record, "recipientRef", 512),
    contentRef: storedString(record, "contentRef", 512),
    status,
    attemptCount,
    maxAttempts,
    availableAt: timestamp(record, "availableAt"),
    createdAt: timestamp(record, "createdAt"),
    ...(claimToken === undefined ? {} : { claimToken }),
    ...(leaseOwner === undefined ? {} : { leaseOwner }),
    ...(leaseExpiresAt === null ? {} : { leaseExpiresAt }),
    ...(acceptedAt === null ? {} : { acceptedAt }),
    ...(acceptedDeadlineAt === null ? {} : { acceptedDeadlineAt }),
    ...(deliveredAt === null ? {} : { deliveredAt }),
    ...(terminalAt === null ? {} : { terminalAt }),
    ...(providerMessageRef === undefined ? {} : { providerMessageRef }),
    ...(providerOccurredAt === null ? {} : { providerOccurredAt }),
    ...(failureCategory === undefined ? {} : { failureCategory }),
    ...(acknowledgedAt === null ? {} : { acknowledgedAt }),
    ...(acknowledgementRef === undefined ? {} : { acknowledgementRef }),
  };
  if (
    maxAttempts > 20 ||
    attemptCount > maxAttempts ||
    submissionGeneration > maxAttempts ||
    job.idempotencyKey !==
      mailIdempotencyKey(partition, id, submissionGeneration)
  ) {
    throw new IdentityError("storage_corrupt", "Stored mail job is malformed.");
  }
  return { kind: "mail", partition, id, job: Object.freeze(job) };
}

function encodeMail(value: IdentityMailRecord): StoredRecord {
  const job = value.job;
  return {
    kind: "mail",
    partition: value.partition,
    id: value.id,
    submissionGeneration: job.submissionGeneration,
    idempotencyKey: job.idempotencyKey,
    recipientRef: job.recipientRef,
    contentRef: job.contentRef,
    mailStatus: job.status,
    attemptCount: job.attemptCount,
    maxAttempts: job.maxAttempts,
    availableAt: job.availableAt,
    createdAt: job.createdAt,
    claimToken: job.claimToken ?? null,
    leaseOwner: job.leaseOwner ?? null,
    leaseExpiresAt: job.leaseExpiresAt ?? null,
    acceptedAt: job.acceptedAt ?? null,
    acceptedDeadlineAt: job.acceptedDeadlineAt ?? null,
    deliveredAt: job.deliveredAt ?? null,
    terminalAt: job.terminalAt ?? null,
    providerMessageRef: job.providerMessageRef ?? null,
    providerOccurredAt: job.providerOccurredAt ?? null,
    failureCategory: job.failureCategory ?? null,
    acknowledgedAt: job.acknowledgedAt ?? null,
    acknowledgementRef: job.acknowledgementRef ?? null,
  };
}

export const emailOperationsCollection =
  defineCollection<IdentityEmailOperationRecord>({
    name: "pegma_identity_email_operations",
    key: (value) => ({ partition: value.partition, id: value.id }),
    codec: {
      encode(value) {
        if (value.kind === "invalid") {
          throw new IdentityError(
            "storage_corrupt",
            "Invalid email-operation records cannot be written.",
          );
        }
        if (value.kind === "mail") {
          return encodeMail(value);
        }
        if (value.kind === "suppressed_mail") {
          return { ...value };
        }
        return { ...value };
      },
      decode(record) {
        try {
          const kind = storedString(record, "kind", 32);
          if (kind === "operation") {
            return decodeOperation(record);
          }
          if (kind === "mail") {
            return decodeMail(record);
          }
          if (kind === "suppressed_mail") {
            const handleHash = assertHash(
              storedString(record, "handleHash", 64),
              "handleHash",
            );
            const decoded: SuppressedMailRecord = {
              kind,
              partition: storedString(record, "partition", 96),
              id: storedString(record, "id", 200),
              handleHash,
              createdAt: timestamp(record, "createdAt"),
            };
            if (decoded.partition !== partitionFor(handleHash)) {
              throw new IdentityError(
                "storage_corrupt",
                "Stored suppressed mail is malformed.",
              );
            }
            if (decoded.id !== "verification-mail") {
              throw new IdentityError(
                "storage_corrupt",
                "Stored suppressed mail is malformed.",
              );
            }
            return decoded;
          }
        } catch {
          // Authoritative Mail/maintenance scans must retain malformed rows
          // without allowing one poisoned record to strand later work.
        }
        return { kind: "invalid", partition: "invalid", id: "invalid" };
      },
    },
  });

export const identityMail = defineMail<IdentityEmailOperationRecord>({
  collection: emailOperationsCollection,
  key: ({ partition, jobId }) => ({ partition, id: jobId }),
  toRecord(job) {
    return {
      kind: "mail",
      partition: job.partition,
      id: job.id,
      job,
    };
  },
  toJob(record) {
    return record.kind === "mail" ? record.job : null;
  },
});
