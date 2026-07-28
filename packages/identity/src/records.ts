import { defineCollection, type StoredRecord } from "@pegma/storage-core";

import { IdentityError } from "./errors.js";
import {
  assertCanonicalTimestamp,
  assertBase64Url,
  assertHash,
  parseStringArray,
  readDataProperty,
  storedBoolean,
  storedNullableString,
  storedSafeInteger,
  storedString,
} from "./validation.js";

export type UserStatus = "pending" | "active";

export interface UserRecord {
  readonly partition: string;
  readonly id: string;
  readonly principalId: string;
  readonly principalHash: string;
  readonly email: string;
  readonly emailHash: string;
  readonly status: UserStatus;
  readonly emailVerified: boolean;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly emailChangeOperationHash: string | null;
}

export type EmailIndexState =
  | "reserved"
  | "prepared"
  | "committed"
  | "active"
  | "change_reserved"
  | "retiring";

export interface EmailIndexRecord {
  readonly partition: string;
  readonly id: string;
  readonly email: string;
  readonly emailHash: string;
  readonly principalId: string;
  readonly principalHash: string;
  readonly operationId: string;
  readonly state: EmailIndexState;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly repairAfter: string;
  readonly changeOperationHash: string | null;
  readonly replacementEmailHash: string | null;
}

export type ChallengeKind = "registration" | "authentication";
export type ChallengeState = "pending" | "verifying" | "consumed" | "failed";

export interface ChallengeRecord {
  readonly partition: string;
  readonly id: string;
  readonly handleHash: string;
  readonly challengeHash: string;
  readonly kind: ChallengeKind;
  readonly state: ChallengeState;
  readonly principalId: string | null;
  readonly principalHash: string | null;
  readonly attemptId: string | null;
  readonly attempts: number;
  readonly maxAttempts: number;
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly updatedAt: string;
}

export type PasskeyState = "active" | "revoked";

export interface PasskeyRecord {
  readonly partition: string;
  readonly id: string;
  readonly credentialHash: string;
  readonly credentialId: string;
  readonly registrationId: string;
  readonly principalId: string;
  readonly principalHash: string;
  readonly publicKey: string;
  readonly counter: number;
  readonly transports: readonly string[];
  readonly label: string;
  readonly state: PasskeyState;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly lastUsedAt: string | null;
}

export type CredentialIndexState =
  "reserved" | "active" | "counter-pending" | "revoked";

export interface CredentialIndexRecord {
  readonly partition: string;
  readonly id: string;
  readonly credentialHash: string;
  readonly credentialId: string;
  readonly registrationId: string;
  readonly registrationProofHash: string;
  readonly principalId: string;
  readonly principalHash: string;
  readonly publicKey: string;
  readonly counter: number;
  readonly nextCounter: number;
  readonly transports: readonly string[];
  readonly label: string;
  readonly state: CredentialIndexState;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface RegistrationProofRecord {
  readonly partition: string;
  readonly id: string;
  readonly registrationProofHash: string;
  readonly credentialHash: string;
  readonly credentialId: string;
  readonly registrationId: string;
  readonly principalId: string;
  readonly principalHash: string;
  readonly publicKey: string;
  readonly counter: number;
  readonly transports: readonly string[];
  readonly label: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

function enumValue<const T extends string>(
  record: StoredRecord,
  name: string,
  allowed: readonly T[],
): T {
  const value = storedString(record, name, 32);
  if (!allowed.includes(value as T)) {
    throw new IdentityError(
      "storage_corrupt",
      `Stored property ${name} is malformed.`,
    );
  }
  return value as T;
}

function timestamp(record: StoredRecord, name: string): string {
  return assertCanonicalTimestamp(readDataProperty(record, name), name);
}

function hash(record: StoredRecord, name: string): string {
  return assertHash(storedString(record, name, 64), name);
}

function decodeUser(record: StoredRecord): UserRecord {
  const decoded: UserRecord = {
    partition: storedString(record, "partition", 96),
    id: hash(record, "id"),
    principalId: storedString(record, "principalId", 512),
    principalHash: hash(record, "principalHash"),
    email: storedString(record, "email", 254),
    emailHash: hash(record, "emailHash"),
    status: enumValue(record, "status", ["pending", "active"]),
    emailVerified: storedBoolean(record, "emailVerified"),
    createdAt: timestamp(record, "createdAt"),
    updatedAt: timestamp(record, "updatedAt"),
    emailChangeOperationHash: storedNullableString(
      record,
      "emailChangeOperationHash",
      64,
    ),
  };
  if (
    decoded.id !== decoded.principalHash ||
    decoded.partition !== `principal-${decoded.principalHash.slice(0, 16)}` ||
    decoded.emailVerified !== (decoded.status === "active") ||
    (decoded.emailChangeOperationHash !== null &&
      !/^[0-9a-f]{64}$/u.test(decoded.emailChangeOperationHash))
  ) {
    throw new IdentityError(
      "storage_corrupt",
      "Stored user identity is malformed.",
    );
  }
  return decoded;
}

export const usersCollection = defineCollection<UserRecord>({
  name: "pegma_identity_users",
  key: ({ partition, id }) => ({ partition, id }),
  codec: {
    encode: (value) => ({ ...value }),
    decode: decodeUser,
  },
});

function decodeEmailIndex(record: StoredRecord): EmailIndexRecord {
  const decoded: EmailIndexRecord = {
    partition: storedString(record, "partition", 32),
    id: hash(record, "id"),
    email: storedString(record, "email", 254),
    emailHash: hash(record, "emailHash"),
    principalId: storedString(record, "principalId", 512),
    principalHash: hash(record, "principalHash"),
    operationId: storedString(record, "operationId", 256),
    state: enumValue(record, "state", [
      "reserved",
      "prepared",
      "committed",
      "active",
      "change_reserved",
      "retiring",
    ]),
    createdAt: timestamp(record, "createdAt"),
    updatedAt: timestamp(record, "updatedAt"),
    repairAfter: timestamp(record, "repairAfter"),
    changeOperationHash: storedNullableString(
      record,
      "changeOperationHash",
      64,
    ),
    replacementEmailHash: storedNullableString(
      record,
      "replacementEmailHash",
      64,
    ),
  };
  if (
    decoded.id !== decoded.emailHash ||
    decoded.partition !== `email-${decoded.emailHash.slice(0, 16)}` ||
    (decoded.changeOperationHash !== null &&
      !/^[0-9a-f]{64}$/u.test(decoded.changeOperationHash)) ||
    (decoded.replacementEmailHash !== null &&
      !/^[0-9a-f]{64}$/u.test(decoded.replacementEmailHash)) ||
    (decoded.state === "change_reserved" || decoded.state === "retiring") !==
      (decoded.changeOperationHash !== null) ||
    (decoded.state === "retiring") !== (decoded.replacementEmailHash !== null)
  ) {
    throw new IdentityError(
      "storage_corrupt",
      "Stored email index identity is malformed.",
    );
  }
  return decoded;
}

export const emailIndexesCollection = defineCollection<EmailIndexRecord>({
  name: "pegma_identity_email_indexes",
  key: ({ partition, id }) => ({ partition, id }),
  codec: {
    encode: (value) => ({ ...value }),
    decode: decodeEmailIndex,
  },
});

function decodeChallenge(record: StoredRecord): ChallengeRecord {
  const principalId = storedNullableString(record, "principalId", 512);
  const principalHashValue = storedNullableString(record, "principalHash", 64);
  const attemptIdValue = storedNullableString(record, "attemptId", 64);
  const attemptId =
    attemptIdValue === null ? null : assertHash(attemptIdValue, "attemptId");
  const decoded: ChallengeRecord = {
    partition: storedString(record, "partition", 32),
    id: hash(record, "id"),
    handleHash: hash(record, "handleHash"),
    challengeHash: hash(record, "challengeHash"),
    kind: enumValue(record, "kind", ["registration", "authentication"]),
    state: enumValue(record, "state", [
      "pending",
      "verifying",
      "consumed",
      "failed",
    ]),
    principalId,
    principalHash:
      principalHashValue === null
        ? null
        : assertHash(principalHashValue, "principalHash"),
    attemptId,
    attempts: storedSafeInteger(record, "attempts"),
    maxAttempts: storedSafeInteger(record, "maxAttempts", 1),
    createdAt: timestamp(record, "createdAt"),
    expiresAt: timestamp(record, "expiresAt"),
    updatedAt: timestamp(record, "updatedAt"),
  };
  const createdAt = Date.parse(decoded.createdAt);
  const expiresAt = Date.parse(decoded.expiresAt);
  const updatedAt = Date.parse(decoded.updatedAt);
  if (
    decoded.partition !== "challenges" ||
    decoded.id !== decoded.handleHash ||
    decoded.maxAttempts > 10 ||
    decoded.attempts > decoded.maxAttempts ||
    expiresAt <= createdAt ||
    expiresAt - createdAt > 15 * 60_000 ||
    updatedAt < createdAt ||
    ((decoded.state === "pending" || decoded.state === "verifying") &&
      updatedAt > expiresAt) ||
    ((decoded.state === "verifying" || decoded.state === "consumed") &&
      decoded.attempts === 0) ||
    (decoded.kind === "registration") !==
      (decoded.principalId !== null && decoded.principalHash !== null) ||
    (decoded.state === "verifying") !== (decoded.attemptId !== null)
  ) {
    throw new IdentityError(
      "storage_corrupt",
      "Stored challenge identity is malformed.",
    );
  }
  return decoded;
}

export const challengesCollection = defineCollection<ChallengeRecord>({
  name: "pegma_identity_challenges",
  key: ({ partition, id }) => ({ partition, id }),
  codec: {
    encode: (value) => ({ ...value }),
    decode: decodeChallenge,
  },
});

export const TRANSPORTS = new Set([
  "ble",
  "cable",
  "hybrid",
  "internal",
  "nfc",
  "smart-card",
  "usb",
]);

function passkeyFields(record: StoredRecord) {
  const transports = parseStringArray(
    storedString(record, "transports", 1_024),
    "transports",
    TRANSPORTS,
  );
  return {
    credentialHash: hash(record, "credentialHash"),
    credentialId: assertBase64Url(
      storedString(record, "credentialId", 2_048),
      "credentialId",
      2_048,
    ),
    registrationId: storedString(record, "registrationId", 256),
    principalId: storedString(record, "principalId", 512),
    principalHash: hash(record, "principalHash"),
    publicKey: assertBase64Url(
      storedString(record, "publicKey", 8_192),
      "publicKey",
      8_192,
    ),
    counter: storedSafeInteger(record, "counter"),
    transports,
    label: storedString(record, "label", 100),
    createdAt: timestamp(record, "createdAt"),
    updatedAt: timestamp(record, "updatedAt"),
  };
}

function encodePasskeyFields(
  value: PasskeyRecord | CredentialIndexRecord | RegistrationProofRecord,
): Record<string, string | number> {
  return {
    credentialHash: value.credentialHash,
    credentialId: value.credentialId,
    registrationId: value.registrationId,
    principalId: value.principalId,
    principalHash: value.principalHash,
    publicKey: value.publicKey,
    counter: value.counter,
    transports: JSON.stringify(value.transports),
    label: value.label,
    createdAt: value.createdAt,
    updatedAt: value.updatedAt,
  };
}

function decodePasskey(record: StoredRecord): PasskeyRecord {
  const fields = passkeyFields(record);
  const decoded: PasskeyRecord = {
    partition: storedString(record, "partition", 96),
    id: hash(record, "id"),
    ...fields,
    state: enumValue(record, "state", ["active", "revoked"]),
    lastUsedAt: (() => {
      const value = storedNullableString(record, "lastUsedAt", 32);
      return value === null
        ? null
        : assertCanonicalTimestamp(value, "lastUsedAt");
    })(),
  };
  if (
    decoded.id !== decoded.credentialHash ||
    decoded.partition !== `passkeys-${decoded.principalHash.slice(0, 32)}`
  ) {
    throw new IdentityError(
      "storage_corrupt",
      "Stored passkey identity is malformed.",
    );
  }
  return decoded;
}

export const passkeysCollection = defineCollection<PasskeyRecord>({
  name: "pegma_identity_passkeys",
  key: ({ partition, id }) => ({ partition, id }),
  codec: {
    encode: (value) => ({
      partition: value.partition,
      id: value.id,
      ...encodePasskeyFields(value),
      state: value.state,
      lastUsedAt: value.lastUsedAt,
    }),
    decode: decodePasskey,
  },
});

function decodeCredentialIndex(record: StoredRecord): CredentialIndexRecord {
  const fields = passkeyFields(record);
  const decoded: CredentialIndexRecord = {
    partition: storedString(record, "partition", 96),
    id: hash(record, "id"),
    ...fields,
    nextCounter: storedSafeInteger(record, "nextCounter"),
    registrationProofHash: hash(record, "registrationProofHash"),
    state: enumValue(record, "state", [
      "reserved",
      "active",
      "counter-pending",
      "revoked",
    ]),
  };
  if (
    decoded.id !== decoded.credentialHash ||
    decoded.partition !== `credential-${decoded.credentialHash.slice(0, 16)}` ||
    (decoded.state === "counter-pending"
      ? decoded.nextCounter <= decoded.counter
      : decoded.nextCounter !== decoded.counter)
  ) {
    throw new IdentityError(
      "storage_corrupt",
      "Stored credential index identity is malformed.",
    );
  }
  return decoded;
}

export const credentialIndexesCollection =
  defineCollection<CredentialIndexRecord>({
    name: "pegma_identity_credential_indexes",
    key: ({ partition, id }) => ({ partition, id }),
    codec: {
      encode: (value) => ({
        partition: value.partition,
        id: value.id,
        ...encodePasskeyFields(value),
        nextCounter: value.nextCounter,
        registrationProofHash: value.registrationProofHash,
        state: value.state,
      }),
      decode: decodeCredentialIndex,
    },
  });

function decodeRegistrationProof(
  record: StoredRecord,
): RegistrationProofRecord {
  const fields = passkeyFields(record);
  const decoded: RegistrationProofRecord = {
    partition: storedString(record, "partition", 96),
    id: hash(record, "id"),
    registrationProofHash: hash(record, "registrationProofHash"),
    ...fields,
  };
  if (
    decoded.id !== decoded.registrationProofHash ||
    decoded.partition !==
      `registration-${decoded.registrationProofHash.slice(0, 16)}`
  ) {
    throw new IdentityError(
      "storage_corrupt",
      "Stored registration proof identity is malformed.",
    );
  }
  return decoded;
}

export const registrationProofsCollection =
  defineCollection<RegistrationProofRecord>({
    name: "pegma_identity_registration_proofs",
    key: ({ partition, id }) => ({ partition, id }),
    codec: {
      encode: (value) => ({
        partition: value.partition,
        id: value.id,
        registrationProofHash: value.registrationProofHash,
        ...encodePasskeyFields(value),
      }),
      decode: decodeRegistrationProof,
    },
  });
