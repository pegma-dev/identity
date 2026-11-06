import type { RateLimiter } from "@pegma/rate-limit";
import type { Clock, PrincipalId } from "@pegma/spine";
import {
  defineCollection,
  type CollectionDefinition,
  type Store,
  type StoredRecord,
} from "@pegma/storage-core";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";

import {
  base64UrlToBytes,
  bytesToBase64Url,
  credentialHash,
  principalHash,
  registrationProofHash,
} from "./crypto.js";
import { IdentityError } from "./errors.js";
import {
  credentialIndexesCollection,
  passkeyPrincipalsCollection,
  passkeysCollection,
  registrationProofsCollection,
  TRANSPORTS,
  type CredentialIndexRecord,
  type PasskeyPrincipalRecord,
  type PasskeyRecord,
  type PasskeySlot,
  type RegistrationProofRecord,
} from "./records.js";
import type { User, UserService, VerifiedIdentityClaims } from "./users.js";
import {
  assertBase64Url,
  assertBoundedString,
  assertPrincipalId,
  copyDataOnly,
  dataField,
  readDataProperty,
  timestampFromClock,
} from "./validation.js";
import type { ChallengeService, ClaimedChallenge } from "./challenges.js";

interface PasskeyServiceOptions {
  readonly store: Store;
  readonly clock: Clock;
  readonly rpName: string;
  readonly rpID: string;
  readonly origins: readonly string[];
  readonly registrationLimiter: RateLimiter;
  readonly authenticationLimiter: RateLimiter;
  readonly challengeService: ChallengeService;
  readonly users: UserService;
  readonly newId: () => string;
  readonly maxActiveCredentials: number;
  readonly maxRetainedCredentials: number;
  readonly registrationProofRetentionMs: number;
  readonly tombstoneRetentionMs: number;
}

export interface RegistrationStart {
  readonly challengeHandle: string;
  readonly options: PublicKeyCredentialCreationOptionsJSON;
}

export interface AuthenticationStart {
  readonly challengeHandle: string;
  readonly options: PublicKeyCredentialRequestOptionsJSON;
}

export interface FinishRegistrationInput {
  readonly principalId: PrincipalId;
  readonly challengeHandle: string;
  readonly label: string;
  readonly response: RegistrationResponseJSON;
}

export interface FinishAuthenticationInput {
  readonly challengeHandle: string;
  readonly response: AuthenticationResponseJSON;
}

export interface Passkey {
  readonly credentialId: string;
  readonly label: string;
  readonly transports: readonly AuthenticatorTransportFuture[];
  readonly createdAt: string;
  readonly lastUsedAt: string | null;
}

export interface PasskeyService {
  beginRegistration(
    principalId: PrincipalId,
    rateLimitKey: string,
  ): Promise<RegistrationStart>;
  finishRegistration(input: FinishRegistrationInput): Promise<Passkey>;
  beginAuthentication(rateLimitKey: string): Promise<AuthenticationStart>;
  finishAuthentication(
    input: FinishAuthenticationInput,
  ): Promise<VerifiedIdentityClaims>;
  listPasskeys(principalId: PrincipalId): Promise<readonly Passkey[]>;
  removePasskey(
    principalId: PrincipalId,
    credentialId: string,
  ): Promise<boolean>;
  repairPasskey(credentialId: string): Promise<Passkey | null>;
  sweep(limit?: number, cursor?: string): Promise<PasskeySweepResult>;
}

export interface PasskeySweepResult {
  readonly inspected: number;
  readonly deletedProofs: number;
  readonly deletedTombstones: number;
  readonly releasedReservations: number;
  readonly rejected: number;
  readonly cursor: string | null;
  readonly hasMore: boolean;
}

interface SafePasskeyScanRecord {
  readonly key: { readonly partition: string; readonly id: string };
  readonly value: unknown;
  readonly version: string;
}

interface SafePasskeyScanPage {
  readonly records: readonly unknown[];
  readonly nextCursor: string | null;
}

function passkeyScanCollection(name: string) {
  return defineCollection<StoredRecord>({
    name,
    key: (record) => ({
      partition: String(record.partition),
      id: String(record.id),
    }),
    codec: {
      encode: (record) => record,
      decode: (record) => record,
    },
  });
}

const registrationProofScanCollection = passkeyScanCollection(
  registrationProofsCollection.name,
);
const credentialIndexScanCollection = passkeyScanCollection(
  credentialIndexesCollection.name,
);
const passkeyMirrorScanCollection = passkeyScanCollection(
  passkeysCollection.name,
);
const passkeyPrincipalScanCollection = passkeyScanCollection(
  passkeyPrincipalsCollection.name,
);

function passkeyScanOwnData(value: object, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, name);
  if (
    descriptor === undefined ||
    !descriptor.enumerable ||
    !("value" in descriptor)
  ) {
    throw new IdentityError(
      "invalid_state",
      "Passkey scan returned malformed data.",
    );
  }
  return descriptor.value;
}

function passkeyScanRecord(value: unknown): SafePasskeyScanRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new IdentityError(
      "invalid_state",
      "Passkey scan returned malformed data.",
    );
  }
  const prototype = Object.getPrototypeOf(value);
  const keys = Reflect.ownKeys(Object.getOwnPropertyDescriptors(value));
  if (
    (prototype !== Object.prototype && prototype !== null) ||
    keys.length !== 3 ||
    keys.some(
      (key) =>
        typeof key === "symbol" ||
        (key !== "key" && key !== "value" && key !== "version"),
    )
  ) {
    throw new IdentityError(
      "invalid_state",
      "Passkey scan returned malformed data.",
    );
  }
  const key = passkeyScanOwnData(value, "key");
  const record = passkeyScanOwnData(value, "value");
  const version = passkeyScanOwnData(value, "version");
  if (
    typeof key !== "object" ||
    key === null ||
    Array.isArray(key) ||
    (Object.getPrototypeOf(key) !== Object.prototype &&
      Object.getPrototypeOf(key) !== null) ||
    Reflect.ownKeys(Object.getOwnPropertyDescriptors(key)).length !== 2 ||
    typeof version !== "string" ||
    version.length === 0 ||
    version.length > 16_384
  ) {
    throw new IdentityError(
      "invalid_state",
      "Passkey scan returned malformed data.",
    );
  }
  const partition = passkeyScanOwnData(key, "partition");
  const id = passkeyScanOwnData(key, "id");
  if (
    typeof partition !== "string" ||
    partition.length === 0 ||
    partition.length > 1_024 ||
    typeof id !== "string" ||
    id.length === 0 ||
    id.length > 1_024
  ) {
    throw new IdentityError(
      "invalid_state",
      "Passkey scan returned malformed data.",
    );
  }
  return Object.freeze({
    key: Object.freeze({ partition, id }),
    value: record,
    version,
  });
}

function passkeyScanPage(value: unknown, limit: number): SafePasskeyScanPage {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new IdentityError(
      "invalid_state",
      "Passkey scan returned malformed data.",
    );
  }
  const prototype = Object.getPrototypeOf(value);
  const keys = Reflect.ownKeys(Object.getOwnPropertyDescriptors(value));
  if (
    (prototype !== Object.prototype && prototype !== null) ||
    keys.length !== 2 ||
    keys.some(
      (key) =>
        typeof key === "symbol" || (key !== "records" && key !== "nextCursor"),
    )
  ) {
    throw new IdentityError(
      "invalid_state",
      "Passkey scan returned malformed data.",
    );
  }
  const records = passkeyScanOwnData(value, "records");
  const nextCursor = passkeyScanOwnData(value, "nextCursor");
  if (
    !Array.isArray(records) ||
    records.length > limit ||
    (nextCursor !== null &&
      (typeof nextCursor !== "string" ||
        nextCursor.length === 0 ||
        nextCursor.length > 16_384))
  ) {
    throw new IdentityError(
      "invalid_state",
      "Passkey scan returned malformed data.",
    );
  }
  const descriptors = Object.getOwnPropertyDescriptors(records);
  const safeRecords: unknown[] = [];
  for (let index = 0; index < records.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (
      descriptor === undefined ||
      !descriptor.enumerable ||
      !("value" in descriptor)
    ) {
      throw new IdentityError(
        "invalid_state",
        "Passkey scan returned malformed data.",
      );
    }
    safeRecords.push(descriptor.value);
  }
  if (
    Reflect.ownKeys(descriptors).filter((key) => key !== "length").length !==
    records.length
  ) {
    throw new IdentityError(
      "invalid_state",
      "Passkey scan returned malformed data.",
    );
  }
  return Object.freeze({
    records: Object.freeze(safeRecords),
    nextCursor,
  });
}

function decodePasskeyScanRecord<T>(
  raw: unknown,
  definition: CollectionDefinition<T>,
): { readonly row: SafePasskeyScanRecord; readonly value: T } {
  const row = passkeyScanRecord(raw);
  if (
    typeof row.value !== "object" ||
    row.value === null ||
    Array.isArray(row.value)
  ) {
    throw new IdentityError(
      "storage_corrupt",
      "Stored passkey maintenance record is malformed.",
    );
  }
  const value = definition.codec.decode(row.value as StoredRecord);
  const key = definition.key(value);
  if (row.key.partition !== key.partition || row.key.id !== key.id) {
    throw new IdentityError(
      "storage_corrupt",
      "Stored passkey maintenance record is malformed.",
    );
  }
  return Object.freeze({ row, value });
}

function passkeyPartition(hash: string): string {
  return `passkeys-${hash.slice(0, 32)}`;
}

function passkeyKey(principalDigest: string, credentialDigest: string) {
  return {
    partition: passkeyPartition(principalDigest),
    id: credentialDigest,
  };
}

function passkeyPrincipalKey(principalDigest: string) {
  return {
    partition: passkeyPartition(principalDigest),
    id: principalDigest,
  };
}

function credentialKey(hash: string) {
  return { partition: `credential-${hash.slice(0, 16)}`, id: hash };
}

function registrationProofKey(hash: string) {
  return { partition: `registration-${hash.slice(0, 16)}`, id: hash };
}

function publicPasskey(record: PasskeyRecord): Passkey {
  return Object.freeze({
    credentialId: record.credentialId,
    label: record.label,
    transports: Object.freeze([
      ...record.transports,
    ]) as readonly AuthenticatorTransportFuture[],
    createdAt: record.createdAt,
    lastUsedAt: record.lastUsedAt,
  });
}

function activeUser(user: User | null): asserts user is User {
  if (user === null || user.status !== "active" || !user.emailVerified) {
    throw new IdentityError(
      "invalid_state",
      "An active verified user is required.",
    );
  }
}

async function assertCredentialOwner(
  index: Pick<CredentialIndexRecord, "principalId" | "principalHash">,
): Promise<void> {
  const principalId = readDataProperty(index, "principalId");
  const storedDigest = readDataProperty(index, "principalHash");
  if (typeof principalId !== "string" || typeof storedDigest !== "string") {
    throw new IdentityError(
      "storage_corrupt",
      "Stored credential owner is malformed.",
    );
  }
  const expectedDigest = await principalHash(principalId as PrincipalId);
  if (storedDigest !== expectedDigest) {
    throw new IdentityError(
      "storage_corrupt",
      "Stored credential owner is malformed.",
    );
  }
}

function sameRegistration(
  current: CredentialIndexRecord,
  proposed: CredentialIndexRecord,
): boolean {
  return (
    sameCredentialGeneration(current, proposed) &&
    current.counter === proposed.counter &&
    current.nextCounter === proposed.nextCounter &&
    current.updatedAt === proposed.updatedAt
  );
}

function sameCredentialGeneration(
  current: CredentialIndexRecord,
  proposed: CredentialIndexRecord,
): boolean {
  return (
    current.credentialHash === proposed.credentialHash &&
    current.credentialId === proposed.credentialId &&
    current.registrationId === proposed.registrationId &&
    current.registrationProofHash === proposed.registrationProofHash &&
    current.principalId === proposed.principalId &&
    current.principalHash === proposed.principalHash &&
    current.publicKey === proposed.publicKey &&
    current.label === proposed.label &&
    current.createdAt === proposed.createdAt &&
    current.transports.length === proposed.transports.length &&
    current.transports.every(
      (transport, index) => transport === proposed.transports[index],
    )
  );
}

function finalizedCounterTransition(
  current: CredentialIndexRecord,
  pending: CredentialIndexRecord,
): boolean {
  return (
    current.state === "active" &&
    sameCredentialGeneration(current, pending) &&
    current.counter === pending.nextCounter &&
    current.nextCounter === pending.nextCounter &&
    current.updatedAt === pending.updatedAt
  );
}

type RegistrationMaterial = Omit<
  CredentialIndexRecord,
  | "partition"
  | "id"
  | "registrationProofHash"
  | "state"
  | "nextCounter"
  | "retireAt"
>;

function after(milliseconds: number, durationMs: number): string {
  return new Date(milliseconds + durationMs).toISOString();
}

function registrationProofMaterial(material: RegistrationMaterial): string {
  return JSON.stringify([
    material.credentialHash,
    material.credentialId,
    material.registrationId,
    material.principalId,
    material.principalHash,
    material.publicKey,
    material.counter,
    [...material.transports],
    material.label,
    material.createdAt,
    material.updatedAt,
  ]);
}

function sameRegistrationProof(
  proof: RegistrationProofRecord,
  index: CredentialIndexRecord,
): boolean {
  return (
    proof.registrationProofHash === index.registrationProofHash &&
    proof.credentialHash === index.credentialHash &&
    proof.credentialId === index.credentialId &&
    proof.registrationId === index.registrationId &&
    proof.principalId === index.principalId &&
    proof.principalHash === index.principalHash &&
    proof.publicKey === index.publicKey &&
    proof.counter === index.counter &&
    proof.label === index.label &&
    proof.createdAt === index.createdAt &&
    proof.updatedAt === index.updatedAt &&
    proof.transports.length === index.transports.length &&
    proof.transports.every(
      (transport, position) => transport === index.transports[position],
    )
  );
}

function sameCredentialBinding(
  passkey: PasskeyRecord,
  index: CredentialIndexRecord,
): boolean {
  return (
    sameCredentialMaterial(passkey, index) && passkey.counter === index.counter
  );
}

function sameCredentialMaterial(
  passkey: PasskeyRecord,
  index: CredentialIndexRecord,
): boolean {
  return (
    passkey.credentialHash === index.credentialHash &&
    passkey.credentialId === index.credentialId &&
    passkey.registrationId === index.registrationId &&
    passkey.principalId === index.principalId &&
    passkey.principalHash === index.principalHash &&
    passkey.publicKey === index.publicKey &&
    passkey.label === index.label &&
    passkey.createdAt === index.createdAt &&
    passkey.transports.length === index.transports.length &&
    passkey.transports.every(
      (transport, position) => transport === index.transports[position],
    )
  );
}

async function enforce(limiter: RateLimiter, key: string): Promise<void> {
  let decision;
  try {
    decision = await limiter.allow(key);
  } catch (cause) {
    throw new IdentityError(
      "rate_limited",
      "The operation is temporarily unavailable.",
      { cause },
    );
  }
  if (!decision.allowed) {
    throw new IdentityError(
      "rate_limited",
      "The operation is temporarily unavailable.",
      decision.retryAfter === undefined
        ? {}
        : { retryAfter: decision.retryAfter },
    );
  }
}

function cleanTransports(
  value: readonly string[] | undefined,
): readonly AuthenticatorTransportFuture[] {
  if (
    value === undefined ||
    value.length > 16 ||
    !value.every((transport) => TRANSPORTS.has(transport))
  ) {
    return Object.freeze([]);
  }
  return Object.freeze([
    ...new Set(value),
  ]) as readonly AuthenticatorTransportFuture[];
}

export function validCounterTransition(
  stored: number,
  reported: number,
): boolean {
  return (
    Number.isSafeInteger(stored) &&
    stored >= 0 &&
    Number.isSafeInteger(reported) &&
    reported >= 0 &&
    ((stored === 0 && reported === 0) || reported > stored)
  );
}

export function createPasskeyService(
  options: PasskeyServiceOptions,
): PasskeyService {
  const passkeys = options.store.collection(passkeysCollection);
  const credentials = options.store.collection(credentialIndexesCollection);
  const registrationProofs = options.store.collection(
    registrationProofsCollection,
  );
  const principals = options.store.collection(passkeyPrincipalsCollection);
  const registrationProofScan = options.store.collection(
    registrationProofScanCollection,
  );
  const credentialIndexScan = options.store.collection(
    credentialIndexScanCollection,
  );
  const passkeyMirrorScan = options.store.collection(
    passkeyMirrorScanCollection,
  );
  const passkeyPrincipalScan = options.store.collection(
    passkeyPrincipalScanCollection,
  );

  async function assertPrincipalStateOwner(
    state: PasskeyPrincipalRecord,
  ): Promise<void> {
    if ((await principalHash(state.principalId)) !== state.principalHash) {
      throw new IdentityError(
        "storage_corrupt",
        "Stored passkey principal state is malformed.",
      );
    }
  }

  function slotFromPasskey(passkey: PasskeyRecord): PasskeySlot {
    return {
      credentialHash: passkey.credentialHash,
      registrationId: passkey.registrationId,
      state: passkey.state,
      expiresAt:
        passkey.state === "revoked"
          ? (passkey.retireAt ??
            after(Date.parse(passkey.updatedAt), options.tombstoneRetentionMs))
          : null,
      updatedAt: passkey.updatedAt,
    };
  }

  function sameSlots(
    left: readonly PasskeySlot[],
    right: readonly PasskeySlot[],
  ): boolean {
    return (
      left.length === right.length &&
      left.every((slot, position) => {
        const candidate = right[position];
        return (
          candidate !== undefined &&
          slot.credentialHash === candidate.credentialHash &&
          slot.registrationId === candidate.registrationId &&
          slot.state === candidate.state &&
          slot.expiresAt === candidate.expiresAt &&
          slot.updatedAt === candidate.updatedAt
        );
      })
    );
  }

  async function mergedPrincipalSlots(
    principalId: string,
    principalDigest: string,
    existing: readonly PasskeySlot[],
  ): Promise<readonly PasskeySlot[]> {
    const slots = [...existing];
    const mirrors = await passkeys.list(passkeyPartition(principalDigest));
    for (const mirror of mirrors) {
      if (
        mirror.principalId !== principalId ||
        mirror.principalHash !== principalDigest
      ) {
        throw new IdentityError(
          "storage_corrupt",
          "Stored credential binding is malformed.",
        );
      }
      const next = slotFromPasskey(mirror);
      const position = slots.findIndex(
        (slot) => slot.credentialHash === mirror.credentialHash,
      );
      if (position < 0) {
        slots.push(next);
        continue;
      }
      const current = slots[position];
      if (current?.registrationId === mirror.registrationId) {
        slots[position] = next;
        continue;
      }
      if (current?.state === "active") {
        throw new IdentityError(
          "storage_corrupt",
          "Stored passkey principal state is malformed.",
        );
      }
      if (current?.state === "reserved") {
        const index = await credentials.get(
          credentialKey(mirror.credentialHash),
        );
        if (index !== null) {
          await assertCredentialOwner(index);
        }
        if (
          index !== null &&
          index.principalId === principalId &&
          index.principalHash === principalDigest &&
          index.registrationId === mirror.registrationId &&
          index.state !== "reserved"
        ) {
          slots[position] = next;
          continue;
        }
        if (
          index !== null &&
          index.principalId === principalId &&
          index.principalHash === principalDigest &&
          index.registrationId === current.registrationId &&
          index.state === "reserved"
        ) {
          continue;
        }
        throw new IdentityError(
          "storage_corrupt",
          "Stored passkey principal state is malformed.",
        );
      } else {
        slots[position] = next;
      }
    }
    return Object.freeze(
      slots.sort((left, right) =>
        left.credentialHash.localeCompare(right.credentialHash),
      ),
    );
  }

  async function ensurePrincipalState(
    principalId: string,
    principalDigest: string,
    updatedAt: string,
  ): Promise<PasskeyPrincipalRecord> {
    const key = passkeyPrincipalKey(principalDigest);
    const result = await principals.update(
      key,
      async (current) => {
        if (current !== null) {
          await assertPrincipalStateOwner(current);
          if (
            current.principalId !== principalId ||
            current.principalHash !== principalDigest
          ) {
            return { action: "keep" };
          }
        }
        const slots = await mergedPrincipalSlots(
          principalId,
          principalDigest,
          current?.slots ?? [],
        );
        if (current !== null && sameSlots(current.slots, slots)) {
          return { action: "keep" };
        }
        return {
          action: "write",
          value: {
            ...key,
            principalId,
            principalHash: principalDigest,
            slots,
            updatedAt,
          },
        };
      },
      { maxAttempts: 10 },
    );
    if (
      result.value === null ||
      result.value.principalId !== principalId ||
      result.value.principalHash !== principalDigest
    ) {
      throw new IdentityError(
        "storage_corrupt",
        "Stored passkey principal state is malformed.",
      );
    }
    return result.value;
  }

  async function reservePrincipalSlot(
    material: RegistrationMaterial,
    expiresAt: string,
  ): Promise<void> {
    const key = passkeyPrincipalKey(material.principalHash);
    const result = await principals.update(
      key,
      async (current) => {
        if (current !== null) {
          await assertPrincipalStateOwner(current);
          if (
            current.principalId !== material.principalId ||
            current.principalHash !== material.principalHash
          ) {
            return { action: "keep" };
          }
        }
        const slots = [
          ...(await mergedPrincipalSlots(
            material.principalId,
            material.principalHash,
            current?.slots ?? [],
          )),
        ];
        const position = slots.findIndex(
          (slot) => slot.credentialHash === material.credentialHash,
        );
        const candidate = position < 0 ? undefined : slots[position];
        const active = slots.filter((slot) => slot.state !== "revoked").length;
        const mayReserve =
          (candidate === undefined || candidate.state === "revoked") &&
          active < options.maxActiveCredentials &&
          (candidate !== undefined ||
            slots.length < options.maxRetainedCredentials);
        if (mayReserve) {
          const reserved: PasskeySlot = {
            credentialHash: material.credentialHash,
            registrationId: material.registrationId,
            state: "reserved",
            expiresAt,
            updatedAt: material.updatedAt,
          };
          if (position < 0) {
            slots.push(reserved);
          } else {
            slots[position] = reserved;
          }
        }
        const normalized = Object.freeze(
          slots.sort((left, right) =>
            left.credentialHash.localeCompare(right.credentialHash),
          ),
        );
        if (
          current !== null &&
          sameSlots(current.slots, normalized) &&
          !mayReserve
        ) {
          return { action: "keep" };
        }
        return {
          action: "write",
          value: {
            ...key,
            principalId: material.principalId,
            principalHash: material.principalHash,
            slots: normalized,
            updatedAt: material.updatedAt,
          },
        };
      },
      { maxAttempts: 10 },
    );
    const slot = result.value?.slots.find(
      (candidate) =>
        candidate.credentialHash === material.credentialHash &&
        candidate.registrationId === material.registrationId &&
        candidate.state === "reserved",
    );
    if (slot !== undefined) {
      return;
    }
    const state = result.value;
    if (
      state !== null &&
      (state.slots.filter((candidate) => candidate.state !== "revoked")
        .length >= options.maxActiveCredentials ||
        state.slots.length >= options.maxRetainedCredentials)
    ) {
      throw new IdentityError("limit_exceeded", "Passkey limit reached.");
    }
    throw new IdentityError(
      "conflict",
      "Another credential registration won the race.",
    );
  }

  async function setPrincipalSlot(
    index: CredentialIndexRecord,
    state: "active" | "revoked",
    expiresAt: string | null,
  ): Promise<void> {
    const normalizedExpiresAt =
      state === "revoked"
        ? (expiresAt ??
          after(Date.parse(index.updatedAt), options.tombstoneRetentionMs))
        : null;
    const key = passkeyPrincipalKey(index.principalHash);
    const result = await principals.update(
      key,
      async (current) => {
        if (current !== null) {
          await assertPrincipalStateOwner(current);
        }
        if (
          current === null ||
          current.principalId !== index.principalId ||
          current.principalHash !== index.principalHash
        ) {
          return { action: "keep" };
        }
        const position = current.slots.findIndex(
          (slot) =>
            slot.credentialHash === index.credentialHash &&
            slot.registrationId === index.registrationId,
        );
        if (position < 0) {
          if (state !== "revoked") {
            return { action: "keep" };
          }
          return {
            action: "write",
            value: {
              ...current,
              slots: [
                ...current.slots,
                {
                  credentialHash: index.credentialHash,
                  registrationId: index.registrationId,
                  state,
                  expiresAt: normalizedExpiresAt,
                  updatedAt: index.updatedAt,
                },
              ].sort((left, right) =>
                left.credentialHash.localeCompare(right.credentialHash),
              ),
              updatedAt: index.updatedAt,
            },
          };
        }
        const slots = [...current.slots];
        slots[position] = {
          ...slots[position]!,
          state,
          expiresAt: normalizedExpiresAt,
          updatedAt: index.updatedAt,
        };
        return {
          action: "write",
          value: { ...current, slots, updatedAt: index.updatedAt },
        };
      },
      { maxAttempts: 10 },
    );
    const slot = result.value?.slots.find(
      (candidate) =>
        candidate.credentialHash === index.credentialHash &&
        candidate.registrationId === index.registrationId,
    );
    if (slot?.state !== state || slot.expiresAt !== normalizedExpiresAt) {
      throw new IdentityError(
        "storage_corrupt",
        "Stored passkey principal state is malformed.",
      );
    }
  }

  async function releasePrincipalSlot(
    principalId: string,
    principalDigest: string,
    credentialDigest: string,
    registrationId: string,
    updatedAt: string,
  ): Promise<boolean> {
    const result = await principals.update(
      passkeyPrincipalKey(principalDigest),
      async (current) => {
        if (current !== null) {
          await assertPrincipalStateOwner(current);
        }
        if (
          current === null ||
          current.principalId !== principalId ||
          current.principalHash !== principalDigest ||
          !current.slots.some(
            (slot) =>
              slot.credentialHash === credentialDigest &&
              slot.registrationId === registrationId,
          )
        ) {
          return { action: "keep" };
        }
        return {
          action: "write",
          value: {
            ...current,
            slots: current.slots.filter(
              (slot) =>
                slot.credentialHash !== credentialDigest ||
                slot.registrationId !== registrationId,
            ),
            updatedAt,
          },
        };
      },
      { maxAttempts: 10 },
    );
    return result.written;
  }

  async function assertRegistrationProof(
    index: CredentialIndexRecord,
  ): Promise<void> {
    const proof = await registrationProofs.get(
      registrationProofKey(index.registrationProofHash),
    );
    if (proof === null || !sameRegistrationProof(proof, index)) {
      throw new IdentityError(
        "storage_corrupt",
        "Stored credential registration proof is malformed.",
      );
    }
    const expectedHash = await registrationProofHash(
      registrationProofMaterial(proof),
    );
    if (expectedHash !== proof.registrationProofHash) {
      throw new IdentityError(
        "storage_corrupt",
        "Stored credential registration proof is malformed.",
      );
    }
  }

  async function persistRegistrationProof(
    material: RegistrationMaterial,
    expiresAt: string,
  ): Promise<string> {
    const proofHash = await registrationProofHash(
      registrationProofMaterial(material),
    );
    const proposed: RegistrationProofRecord = {
      ...registrationProofKey(proofHash),
      ...material,
      registrationProofHash: proofHash,
      expiresAt,
    };
    const inserted = await registrationProofs.insertIfAbsent(proposed);
    if (
      inserted.value.registrationProofHash !== proofHash ||
      !sameRegistrationProof(inserted.value, {
        ...credentialKey(material.credentialHash),
        ...material,
        nextCounter: material.counter,
        registrationProofHash: proofHash,
        state: "reserved",
        retireAt: null,
      })
    ) {
      throw new IdentityError(
        "storage_corrupt",
        "Stored credential registration proof is malformed.",
      );
    }
    return proofHash;
  }

  async function assertCredentialMirror(
    index: CredentialIndexRecord,
  ): Promise<PasskeyRecord> {
    await assertCredentialOwner(index);
    const passkey = await passkeys.get(
      passkeyKey(index.principalHash, index.credentialHash),
    );
    if (
      passkey === null ||
      passkey.state !== "active" ||
      !sameCredentialBinding(passkey, index)
    ) {
      throw new IdentityError(
        "storage_corrupt",
        "Stored credential binding is malformed.",
      );
    }
    return passkey;
  }

  async function ensurePasskey(
    index: CredentialIndexRecord,
  ): Promise<PasskeyRecord> {
    const key = passkeyKey(index.principalHash, index.credentialHash);
    const result = await passkeys.update(
      key,
      (current) => {
        if (
          current !== null &&
          (current.principalId !== index.principalId ||
            current.principalHash !== index.principalHash ||
            current.credentialId !== index.credentialId)
        ) {
          return { action: "keep" };
        }
        if (
          current?.state === "active" &&
          current.registrationId === index.registrationId &&
          sameCredentialBinding(current, index)
        ) {
          return { action: "keep" };
        }
        if (
          current !== null &&
          (index.state !== "reserved" ||
            current.registrationId === index.registrationId)
        ) {
          // A revoked generation is terminal. Only a freshly verified
          // registration with a different generation may replace it.
          return { action: "keep" };
        }
        const value: PasskeyRecord = {
          ...key,
          credentialHash: index.credentialHash,
          credentialId: index.credentialId,
          registrationId: index.registrationId,
          principalId: index.principalId,
          principalHash: index.principalHash,
          publicKey: index.publicKey,
          counter: index.counter,
          transports: index.transports,
          label: index.label,
          state: "active",
          retireAt: null,
          createdAt:
            current?.registrationId === index.registrationId
              ? current.createdAt
              : index.createdAt,
          updatedAt: index.updatedAt,
          lastUsedAt: null,
        };
        return { action: "write", value };
      },
      { maxAttempts: 10 },
    );
    if (
      result.value === null ||
      result.value.principalId !== index.principalId ||
      result.value.principalHash !== index.principalHash ||
      result.value.credentialId !== index.credentialId ||
      result.value.registrationId !== index.registrationId ||
      !sameCredentialBinding(result.value, index) ||
      result.value.state !== "active"
    ) {
      throw new IdentityError(
        "conflict",
        "Credential is already bound to another principal.",
      );
    }
    return result.value;
  }

  async function activateCredential(
    index: CredentialIndexRecord,
  ): Promise<CredentialIndexRecord> {
    const result = await credentials.update(
      credentialKey(index.credentialHash),
      async (current) => {
        if (current !== null) {
          await assertCredentialOwner(current);
        }
        if (
          current === null ||
          !sameRegistration(current, index) ||
          current.state !== "reserved"
        ) {
          return { action: "keep" };
        }
        return {
          action: "write",
          value: { ...current, state: "active" },
        };
      },
      { maxAttempts: 10 },
    );
    if (
      result.value === null ||
      result.value.state !== "active" ||
      !sameRegistration(result.value, index)
    ) {
      throw new IdentityError(
        "conflict",
        "Credential is already bound to another principal.",
      );
    }
    return result.value;
  }

  async function repair(
    index: CredentialIndexRecord,
  ): Promise<PasskeyRecord | null> {
    await assertCredentialOwner(index);
    if (index.state === "revoked") {
      const mirrored = await passkeys.update(
        passkeyKey(index.principalHash, index.credentialHash),
        (current) =>
          current === null ||
          current.principalId !== index.principalId ||
          current.principalHash !== index.principalHash ||
          current.credentialId !== index.credentialId ||
          current.registrationId !== index.registrationId ||
          current.state === "revoked"
            ? { action: "keep" }
            : {
                action: "write",
                value: {
                  ...current,
                  state: "revoked",
                  retireAt: index.retireAt,
                  updatedAt: index.updatedAt,
                },
              },
        { maxAttempts: 10 },
      );
      if (
        mirrored.value !== null &&
        (mirrored.value.state !== "revoked" ||
          !sameCredentialBinding(mirrored.value, index) ||
          mirrored.value.retireAt !== index.retireAt)
      ) {
        throw new IdentityError(
          "conflict",
          "Credential changed while it was being repaired.",
        );
      }
      await ensurePrincipalState(
        index.principalId,
        index.principalHash,
        index.updatedAt,
      );
      await setPrincipalSlot(index, "revoked", index.retireAt);
      return null;
    }
    if (index.state === "counter-pending") {
      const current = await credentials.get(
        credentialKey(index.credentialHash),
      );
      if (current !== null && finalizedCounterTransition(current, index)) {
        return assertCredentialMirror(current);
      }
      if (
        current === null ||
        current.state !== "counter-pending" ||
        !sameRegistration(current, index)
      ) {
        throw new IdentityError(
          "conflict",
          "Credential changed while it was being repaired.",
        );
      }
      const key = passkeyKey(index.principalHash, index.credentialHash);
      const mirrored = await passkeys.update(
        key,
        (passkey) => {
          if (
            passkey === null ||
            passkey.state !== "active" ||
            !sameCredentialMaterial(passkey, index) ||
            (passkey.counter !== index.counter &&
              passkey.counter !== index.nextCounter)
          ) {
            return { action: "keep" };
          }
          return passkey.counter === index.nextCounter
            ? { action: "keep" }
            : {
                action: "write",
                value: {
                  ...passkey,
                  counter: index.nextCounter,
                  updatedAt: index.updatedAt,
                  lastUsedAt: index.updatedAt,
                },
              };
        },
        { maxAttempts: 10 },
      );
      if (
        mirrored.value === null ||
        mirrored.value.state !== "active" ||
        !sameCredentialMaterial(mirrored.value, index) ||
        mirrored.value.counter !== index.nextCounter
      ) {
        throw new IdentityError(
          "storage_corrupt",
          "Stored credential binding is malformed.",
        );
      }
      const finalized = await credentials.update(
        credentialKey(index.credentialHash),
        async (candidate) => {
          if (candidate !== null) {
            await assertCredentialOwner(candidate);
          }
          if (
            candidate === null ||
            candidate.state !== "counter-pending" ||
            !sameRegistration(candidate, index)
          ) {
            return { action: "keep" };
          }
          return {
            action: "write",
            value: {
              ...candidate,
              state: "active",
              counter: candidate.nextCounter,
            },
          };
        },
        { maxAttempts: 10 },
      );
      if (
        finalized.value === null ||
        !finalizedCounterTransition(finalized.value, index)
      ) {
        throw new IdentityError(
          "conflict",
          "Credential changed while it was being repaired.",
        );
      }
      await assertCredentialMirror(finalized.value);
      await ensurePrincipalState(
        finalized.value.principalId,
        finalized.value.principalHash,
        finalized.value.updatedAt,
      );
      await setPrincipalSlot(finalized.value, "active", null);
      return mirrored.value;
    }
    const current = await credentials.get(credentialKey(index.credentialHash));
    if (
      current === null ||
      current.state !== index.state ||
      !sameRegistration(current, index)
    ) {
      throw new IdentityError(
        "conflict",
        "Credential changed while it was being repaired.",
      );
    }
    if (index.state === "reserved") {
      await assertRegistrationProof(index);
    } else {
      await assertCredentialMirror(index);
    }
    const passkey = await ensurePasskey(index);
    const active = await activateCredential(index);
    await ensurePrincipalState(
      active.principalId,
      active.principalHash,
      active.updatedAt,
    );
    await setPrincipalSlot(active, "active", null);
    return passkey;
  }

  async function persistCredential(
    material: RegistrationMaterial,
  ): Promise<PasskeyRecord> {
    const key = credentialKey(material.credentialHash);
    const existing = await credentials.get(key);
    if (existing !== null && existing.state !== "revoked") {
      await assertCredentialOwner(existing);
      if (existing.state === "reserved") {
        await repair(existing);
      }
      throw new IdentityError(
        "conflict",
        "Credential is already bound to another registration.",
      );
    }
    const proofExpiresAt = after(
      Date.parse(material.updatedAt),
      options.registrationProofRetentionMs,
    );
    await reservePrincipalSlot(material, proofExpiresAt);
    const proofHash = await persistRegistrationProof(material, proofExpiresAt);
    const proposed: CredentialIndexRecord = {
      ...key,
      ...material,
      nextCounter: material.counter,
      registrationProofHash: proofHash,
      state: "reserved",
      retireAt: null,
    };
    let index = (await credentials.insertIfAbsent(proposed)).value;
    await assertCredentialOwner(index);
    if (
      index.principalId !== material.principalId ||
      index.principalHash !== material.principalHash ||
      index.credentialId !== material.credentialId
    ) {
      throw new IdentityError(
        "conflict",
        "Credential is already bound to another principal.",
      );
    }
    if (index.state === "revoked") {
      const result = await credentials.update(
        key,
        async (current) => {
          if (current !== null) {
            await assertCredentialOwner(current);
          }
          return current === null ||
            current.principalId !== material.principalId ||
            current.principalHash !== material.principalHash ||
            current.credentialId !== material.credentialId ||
            current.state !== "revoked"
            ? { action: "keep" }
            : { action: "write", value: proposed };
        },
        { maxAttempts: 10 },
      );
      if (result.value === null || result.value.state !== "reserved") {
        throw new IdentityError(
          "conflict",
          "Credential could not be reactivated.",
        );
      }
      index = result.value;
      await assertCredentialOwner(index);
    }
    if (!sameRegistration(index, proposed)) {
      throw new IdentityError(
        "conflict",
        "Another credential registration won the race.",
      );
    }
    const repaired = await repair(index);
    if (repaired === null) {
      throw new IdentityError(
        "invalid_state",
        "Credential registration did not converge.",
      );
    }
    return repaired;
  }

  async function verificationFailed(claim: ClaimedChallenge): Promise<never> {
    try {
      await options.challengeService.releaseFailedClaim(claim);
    } catch {
      // The original verification failure remains the public result.
    }
    throw new IdentityError(
      "verification_failed",
      "WebAuthn verification failed.",
    );
  }

  return {
    async beginRegistration(principalInput, rateLimitInput) {
      const principalId = assertPrincipalId(principalInput);
      const rateLimitKey = assertBoundedString(
        rateLimitInput,
        "Rate-limit key",
        1_024,
      );
      const [user, principalDigest] = await Promise.all([
        options.users.getUser(principalId),
        principalHash(principalId),
      ]);
      activeUser(user);
      await enforce(
        options.registrationLimiter,
        `webauthn-registration:${principalDigest}:${rateLimitKey}`,
      );
      const state = await ensurePrincipalState(
        principalId,
        principalDigest,
        timestampFromClock(options.clock).value,
      );
      if (
        state.slots.filter((slot) => slot.state !== "revoked").length >=
        options.maxActiveCredentials
      ) {
        throw new IdentityError("limit_exceeded", "Passkey limit reached.");
      }
      const existing = (
        await passkeys.list(passkeyPartition(principalDigest))
      ).filter((passkey) => passkey.state === "active");
      const generated = await generateRegistrationOptions({
        rpName: options.rpName,
        rpID: options.rpID,
        userName: user.email,
        userDisplayName: "",
        userID: Uint8Array.from(principalDigest.match(/.{2}/gu) ?? [], (hex) =>
          Number.parseInt(hex, 16),
        ),
        attestationType: "none",
        timeout: 60_000,
        excludeCredentials: existing.map((passkey) => ({
          id: passkey.credentialId,
          transports: passkey.transports as AuthenticatorTransportFuture[],
        })),
        authenticatorSelection: {
          residentKey: "required",
          requireResidentKey: true,
          userVerification: "required",
        },
      });
      const challengeHandle = await options.challengeService.storeChallenge(
        "registration",
        generated.challenge,
        principalId,
      );
      return Object.freeze({ challengeHandle, options: generated });
    },

    async finishRegistration(input) {
      const safe = copyDataOnly(input);
      const principalId = assertPrincipalId(dataField(safe, "principalId"));
      const challengeHandle = assertBoundedString(
        dataField(safe, "challengeHandle"),
        "Challenge handle",
        256,
      );
      const label = assertBoundedString(dataField(safe, "label"), "Label", 100);
      const response = copyDataOnly(
        dataField(safe, "response"),
      ) as RegistrationResponseJSON;
      const claim = await options.challengeService.claimChallenge(
        challengeHandle,
        "registration",
        principalId,
      );
      let verification;
      try {
        verification = await verifyRegistrationResponse({
          response,
          expectedChallenge: (candidate) =>
            options.challengeService.matches(claim.record, candidate),
          expectedOrigin: [...options.origins],
          expectedRPID: options.rpID,
          requireUserPresence: true,
          requireUserVerification: true,
        });
      } catch {
        return verificationFailed(claim);
      }
      if (
        !verification.verified ||
        !verification.registrationInfo.userVerified
      ) {
        return verificationFailed(claim);
      }
      const credential = verification.registrationInfo.credential;
      let credentialId: string;
      try {
        credentialId = assertBase64Url(
          credential.id,
          "Credential identifier",
          2_048,
        );
      } catch {
        return verificationFailed(claim);
      }
      const credentialDigest = await credentialHash(credentialId);
      const principalDigest = await principalHash(principalId);
      const now = timestampFromClock(options.clock).value;
      if (
        !(credential.publicKey instanceof Uint8Array) ||
        credential.publicKey.byteLength === 0 ||
        credential.publicKey.byteLength > 8_192 ||
        !Number.isSafeInteger(credential.counter) ||
        credential.counter < 0
      ) {
        return verificationFailed(claim);
      }
      let stored: PasskeyRecord;
      try {
        stored = await persistCredential({
          credentialHash: credentialDigest,
          credentialId,
          registrationId: assertBoundedString(
            options.newId(),
            "Generated registration identifier",
            256,
          ),
          principalId,
          principalHash: principalDigest,
          publicKey: bytesToBase64Url(credential.publicKey),
          counter: credential.counter,
          transports: cleanTransports(credential.transports),
          label,
          createdAt: now,
          updatedAt: now,
        });
      } catch (cause) {
        throw cause instanceof IdentityError
          ? cause
          : new IdentityError(
              "invalid_state",
              "Credential registration could not be persisted.",
              { cause },
            );
      }
      try {
        await options.challengeService.consumeClaim(claim);
      } catch {
        // The credential is already durable and the verifying claim remains
        // single-flight and eligible for collection after expiry.
      }
      return publicPasskey(stored);
    },

    async beginAuthentication(rateLimitInput) {
      const rateLimitKey = assertBoundedString(
        rateLimitInput,
        "Rate-limit key",
        1_024,
      );
      await enforce(
        options.authenticationLimiter,
        `webauthn-authentication:${rateLimitKey}`,
      );
      const generated = await generateAuthenticationOptions({
        rpID: options.rpID,
        timeout: 60_000,
        userVerification: "required",
      });
      const challengeHandle = await options.challengeService.storeChallenge(
        "authentication",
        generated.challenge,
      );
      return Object.freeze({ challengeHandle, options: generated });
    },

    async finishAuthentication(input) {
      const safe = copyDataOnly(input);
      const challengeHandle = assertBoundedString(
        dataField(safe, "challengeHandle"),
        "Challenge handle",
        256,
      );
      const response = copyDataOnly(
        dataField(safe, "response"),
      ) as AuthenticationResponseJSON;
      const credentialId = assertBase64Url(
        dataField(response, "id"),
        "Credential identifier",
        2_048,
        "invalid_input",
      );
      const credentialDigest = await credentialHash(credentialId);
      let index = await credentials.get(credentialKey(credentialDigest));
      if (
        index !== null &&
        index.state === "counter-pending" &&
        index.credentialId === credentialId
      ) {
        await repair(index);
        index = await credentials.get(credentialKey(credentialDigest));
      }
      if (
        index !== null &&
        index.state === "active" &&
        index.credentialId === credentialId
      ) {
        await assertCredentialMirror(index);
      }
      const claim = await options.challengeService.claimChallenge(
        challengeHandle,
        "authentication",
      );
      if (
        index === null ||
        index.state !== "active" ||
        index.credentialId !== credentialId
      ) {
        return verificationFailed(claim);
      }
      let verification;
      try {
        verification = await verifyAuthenticationResponse({
          response,
          expectedChallenge: (candidate) =>
            options.challengeService.matches(claim.record, candidate),
          expectedOrigin: [...options.origins],
          expectedRPID: options.rpID,
          requireUserVerification: true,
          credential: {
            id: index.credentialId,
            publicKey: base64UrlToBytes(index.publicKey),
            counter: index.counter,
            transports: index.transports as AuthenticatorTransportFuture[],
          },
        });
      } catch {
        return verificationFailed(claim);
      }
      if (
        !verification.verified ||
        !verification.authenticationInfo.userVerified ||
        verification.authenticationInfo.credentialID !== credentialId
      ) {
        return verificationFailed(claim);
      }
      const newCounter = verification.authenticationInfo.newCounter;
      const now = timestampFromClock(options.clock).value;
      let advanced = false;
      const updated = await credentials.update(
        credentialKey(credentialDigest),
        async (current) => {
          if (current?.state === "active") {
            await assertCredentialMirror(current);
          }
          if (
            current === null ||
            current.state !== "active" ||
            current.credentialId !== credentialId ||
            current.principalId !== index.principalId ||
            current.principalHash !== index.principalHash ||
            current.registrationId !== index.registrationId ||
            !validCounterTransition(current.counter, newCounter)
          ) {
            return { action: "keep" };
          }
          advanced = true;
          return {
            action: "write",
            value:
              current.counter === newCounter
                ? { ...current, updatedAt: now }
                : {
                    ...current,
                    state: "counter-pending",
                    nextCounter: newCounter,
                    updatedAt: now,
                  },
          };
        },
        { maxAttempts: 10 },
      );
      if (!advanced || !updated.written || updated.value === null) {
        return verificationFailed(claim);
      }
      if (updated.value.state === "counter-pending") {
        await repair(updated.value);
      } else {
        await passkeys.update(
          passkeyKey(index.principalHash, credentialDigest),
          (current) =>
            current === null ||
            current.state !== "active" ||
            current.principalId !== index.principalId ||
            current.principalHash !== index.principalHash ||
            current.registrationId !== index.registrationId ||
            !sameCredentialBinding(current, index)
              ? { action: "keep" }
              : {
                  action: "write",
                  value: {
                    ...current,
                    updatedAt: now,
                    lastUsedAt: now,
                  },
                },
          { maxAttempts: 10 },
        );
      }
      const confirmed = await credentials.get(credentialKey(credentialDigest));
      if (
        confirmed === null ||
        confirmed.state !== "active" ||
        confirmed.principalId !== index.principalId ||
        confirmed.principalHash !== index.principalHash ||
        confirmed.registrationId !== index.registrationId ||
        confirmed.counter !== newCounter
      ) {
        return verificationFailed(claim);
      }
      await assertCredentialMirror(confirmed);
      await options.challengeService.consumeClaim(claim);
      return options.users.claimsFor(confirmed.principalId);
    },

    async listPasskeys(principalInput) {
      const principalId = assertPrincipalId(principalInput);
      const digest = await principalHash(principalId);
      const records = await passkeys.list(passkeyPartition(digest));
      return Object.freeze(
        records
          .filter(
            (record) =>
              record.principalId === principalId &&
              record.principalHash === digest &&
              record.state === "active",
          )
          .map(publicPasskey),
      );
    },

    async removePasskey(principalInput, credentialInput) {
      const principalId = assertPrincipalId(principalInput);
      const credentialId = assertBase64Url(
        credentialInput,
        "Credential identifier",
        2_048,
        "invalid_input",
      );
      const digest = await credentialHash(credentialId);
      const principalDigest = await principalHash(principalId);
      const startedAt = timestampFromClock(options.clock);
      await ensurePrincipalState(principalId, principalDigest, startedAt.value);
      for (let attempt = 0; attempt < 8; attempt += 1) {
        const observed = await credentials.get(credentialKey(digest));
        if (
          observed === null ||
          observed.principalId !== principalId ||
          observed.principalHash !== principalDigest ||
          observed.credentialId !== credentialId ||
          observed.state === "reserved"
        ) {
          return false;
        }
        if (observed.state === "revoked") {
          await repair(observed);
          const mirror = await passkeys.get(
            passkeyKey(principalDigest, digest),
          );
          if (
            mirror !== null &&
            (mirror.state !== "revoked" ||
              !sameCredentialBinding(mirror, observed) ||
              mirror.retireAt !== observed.retireAt)
          ) {
            throw new IdentityError(
              "conflict",
              "Passkey removal did not converge.",
            );
          }
          return false;
        }
        if (observed.state === "counter-pending") {
          try {
            await repair(observed);
          } catch (cause) {
            if (
              !(cause instanceof IdentityError) ||
              cause.code !== "conflict"
            ) {
              throw cause;
            }
          }
          continue;
        }
        const retireAt = after(
          startedAt.milliseconds,
          options.tombstoneRetentionMs,
        );
        const result = await credentials.update(
          credentialKey(digest),
          async (current) => {
            if (current?.state === "active") {
              await assertCredentialMirror(current);
            }
            if (
              current === null ||
              current.principalId !== principalId ||
              current.principalHash !== principalDigest ||
              current.credentialId !== credentialId ||
              current.registrationId !== observed.registrationId ||
              current.state !== "active"
            ) {
              return { action: "keep" };
            }
            return {
              action: "write",
              value: {
                ...current,
                state: "revoked",
                retireAt,
                updatedAt: startedAt.value,
              },
            };
          },
          { maxAttempts: 10 },
        );
        if (
          result.written &&
          result.value?.state === "revoked" &&
          result.value.principalId === principalId &&
          result.value.principalHash === principalDigest &&
          result.value.credentialId === credentialId &&
          result.value.registrationId === observed.registrationId
        ) {
          await repair(result.value);
          const [confirmed, mirror] = await Promise.all([
            credentials.get(credentialKey(digest)),
            passkeys.get(passkeyKey(principalDigest, digest)),
          ]);
          if (
            confirmed?.state === "revoked" &&
            confirmed.principalId === principalId &&
            confirmed.principalHash === principalDigest &&
            confirmed.credentialId === credentialId &&
            confirmed.registrationId === observed.registrationId &&
            mirror?.state === "revoked" &&
            mirror.principalId === principalId &&
            mirror.principalHash === principalDigest &&
            mirror.credentialId === credentialId &&
            mirror.registrationId === observed.registrationId &&
            sameCredentialBinding(mirror, confirmed) &&
            mirror.retireAt === confirmed.retireAt
          ) {
            return true;
          }
          throw new IdentityError(
            "conflict",
            "Passkey removal did not converge.",
          );
        }
        if (
          result.value?.state === "counter-pending" &&
          result.value.principalId === principalId &&
          result.value.principalHash === principalDigest &&
          result.value.credentialId === credentialId
        ) {
          try {
            await repair(result.value);
          } catch (cause) {
            if (
              !(cause instanceof IdentityError) ||
              cause.code !== "conflict"
            ) {
              throw cause;
            }
          }
          continue;
        }
        if (
          result.value === null ||
          result.value.principalId !== principalId ||
          result.value.principalHash !== principalDigest ||
          result.value.credentialId !== credentialId ||
          result.value.state === "revoked"
        ) {
          return false;
        }
      }
      throw new IdentityError("conflict", "Passkey removal did not converge.");
    },

    async repairPasskey(credentialInput) {
      const credentialId = assertBase64Url(
        credentialInput,
        "Credential identifier",
        2_048,
        "invalid_input",
      );
      const digest = await credentialHash(credentialId);
      const index = await credentials.get(credentialKey(digest));
      if (index === null || index.credentialId !== credentialId) {
        return null;
      }
      const repaired = await repair(index);
      return repaired === null ? null : publicPasskey(repaired);
    },

    async sweep(limitInput = 100, cursorInput) {
      if (
        !Number.isSafeInteger(limitInput) ||
        limitInput < 1 ||
        limitInput > 1_000
      ) {
        throw new IdentityError("invalid_input", "Sweep limit is invalid.");
      }
      const stages = ["proofs", "indexes", "mirrors", "principals"] as const;
      type Stage = (typeof stages)[number];
      let stage: Stage = "proofs";
      let adapterCursor: string | undefined;
      if (cursorInput !== undefined) {
        const cursor = assertBoundedString(cursorInput, "Sweep cursor", 16_384);
        const separator = cursor.indexOf(":");
        const candidate = cursor.slice(0, separator) as Stage;
        if (separator < 0 || !stages.includes(candidate)) {
          throw new IdentityError("invalid_input", "Sweep cursor is invalid.");
        }
        stage = candidate;
        const nested = cursor.slice(separator + 1);
        adapterCursor = nested === "" ? undefined : nested;
      }
      const now = timestampFromClock(options.clock);
      let inspected = 0;
      let deletedProofs = 0;
      let deletedTombstones = 0;
      let releasedReservations = 0;
      let rejected = 0;
      let nextAdapterCursor: string | null;

      if (stage === "proofs") {
        const page = passkeyScanPage(
          await registrationProofScan.scan({
            limit: limitInput,
            ...(adapterCursor === undefined ? {} : { cursor: adapterCursor }),
          }),
          limitInput,
        );
        inspected = page.records.length;
        nextAdapterCursor = page.nextCursor;
        for (const rawRow of page.records) {
          let row: SafePasskeyScanRecord;
          let proof: RegistrationProofRecord;
          try {
            ({ row, value: proof } = decodePasskeyScanRecord(
              rawRow,
              registrationProofsCollection,
            ));
            await assertCredentialOwner(proof);
          } catch {
            rejected += 1;
            continue;
          }
          const expiresAt =
            proof.expiresAt ??
            after(
              Date.parse(proof.updatedAt),
              options.registrationProofRetentionMs,
            );
          if (Date.parse(expiresAt) > now.milliseconds) {
            continue;
          }
          let index = await credentials.get(
            credentialKey(proof.credentialHash),
          );
          if (
            index !== null &&
            index.state === "reserved" &&
            sameRegistrationProof(proof, index)
          ) {
            try {
              await repair(index);
            } catch {
              continue;
            }
            index = await credentials.get(credentialKey(proof.credentialHash));
          }
          if (
            index !== null &&
            sameRegistrationProof(proof, index) &&
            index.state === "reserved"
          ) {
            continue;
          }
          if (
            index !== null &&
            sameRegistrationProof(proof, index) &&
            (index.state === "active" || index.state === "counter-pending")
          ) {
            try {
              if (index.state === "counter-pending") {
                await repair(index);
              } else {
                await assertCredentialMirror(index);
              }
            } catch {
              continue;
            }
          }
          if (
            await registrationProofs.deleteIfUnchanged(row.key, row.version)
          ) {
            deletedProofs += 1;
          }
        }
      } else if (stage === "indexes") {
        const page = passkeyScanPage(
          await credentialIndexScan.scan({
            limit: limitInput,
            ...(adapterCursor === undefined ? {} : { cursor: adapterCursor }),
          }),
          limitInput,
        );
        inspected = page.records.length;
        nextAdapterCursor = page.nextCursor;
        for (const rawRow of page.records) {
          let row: SafePasskeyScanRecord;
          let index: CredentialIndexRecord;
          try {
            ({ row, value: index } = decodePasskeyScanRecord(
              rawRow,
              credentialIndexesCollection,
            ));
            await assertCredentialOwner(index);
          } catch {
            rejected += 1;
            continue;
          }
          if (index.state !== "revoked") {
            continue;
          }
          const retireAt =
            index.retireAt ??
            after(Date.parse(index.updatedAt), options.tombstoneRetentionMs);
          if (Date.parse(retireAt) > now.milliseconds) {
            continue;
          }
          const mirrorKey = passkeyKey(
            index.principalHash,
            index.credentialHash,
          );
          const mirror = await passkeys.getVersioned(mirrorKey);
          if (mirror !== null) {
            const mirrorRetireAt =
              mirror.value.retireAt ??
              after(
                Date.parse(mirror.value.updatedAt),
                options.tombstoneRetentionMs,
              );
            if (
              mirror.value.state !== "revoked" ||
              !sameCredentialBinding(mirror.value, index) ||
              Date.parse(mirrorRetireAt) > now.milliseconds ||
              (mirror.value.retireAt !== null &&
                index.retireAt !== null &&
                mirror.value.retireAt !== index.retireAt)
            ) {
              continue;
            }
            if (
              !(await passkeys.deleteIfUnchanged(mirrorKey, mirror.version))
            ) {
              continue;
            }
          }
          if (await credentials.deleteIfUnchanged(row.key, row.version)) {
            deletedTombstones += 1;
            await releasePrincipalSlot(
              index.principalId,
              index.principalHash,
              index.credentialHash,
              index.registrationId,
              now.value,
            );
          }
        }
      } else if (stage === "mirrors") {
        const page = passkeyScanPage(
          await passkeyMirrorScan.scan({
            limit: limitInput,
            ...(adapterCursor === undefined ? {} : { cursor: adapterCursor }),
          }),
          limitInput,
        );
        inspected = page.records.length;
        nextAdapterCursor = page.nextCursor;
        for (const rawRow of page.records) {
          let row: SafePasskeyScanRecord;
          let mirror: PasskeyRecord;
          try {
            ({ row, value: mirror } = decodePasskeyScanRecord(
              rawRow,
              passkeysCollection,
            ));
            await assertCredentialOwner(mirror);
          } catch {
            rejected += 1;
            continue;
          }
          if (mirror.state !== "revoked") {
            continue;
          }
          const retireAt =
            mirror.retireAt ??
            after(Date.parse(mirror.updatedAt), options.tombstoneRetentionMs);
          if (Date.parse(retireAt) > now.milliseconds) {
            continue;
          }
          const index = await credentials.get(
            credentialKey(mirror.credentialHash),
          );
          if (
            index !== null &&
            index.state === "revoked" &&
            sameCredentialBinding(mirror, index)
          ) {
            continue;
          }
          if (await passkeys.deleteIfUnchanged(row.key, row.version)) {
            await releasePrincipalSlot(
              mirror.principalId,
              mirror.principalHash,
              mirror.credentialHash,
              mirror.registrationId,
              now.value,
            );
          }
        }
      } else {
        const page = passkeyScanPage(
          await passkeyPrincipalScan.scan({
            limit: limitInput,
            ...(adapterCursor === undefined ? {} : { cursor: adapterCursor }),
          }),
          limitInput,
        );
        inspected = page.records.length;
        nextAdapterCursor = page.nextCursor;
        for (const rawRow of page.records) {
          let row: SafePasskeyScanRecord;
          let current: PasskeyPrincipalRecord;
          try {
            ({ row, value: current } = decodePasskeyScanRecord(
              rawRow,
              passkeyPrincipalsCollection,
            ));
            await assertPrincipalStateOwner(current);
          } catch {
            rejected += 1;
            continue;
          }
          const retained: PasskeySlot[] = [];
          for (const slot of current.slots) {
            if (
              slot.expiresAt === null ||
              Date.parse(slot.expiresAt) > now.milliseconds
            ) {
              retained.push(slot);
              continue;
            }
            const [index, mirror] = await Promise.all([
              credentials.get(credentialKey(slot.credentialHash)),
              passkeys.get(
                passkeyKey(current.principalHash, slot.credentialHash),
              ),
            ]);
            const exactIndex =
              index !== null &&
              index.principalId === current.principalId &&
              index.principalHash === current.principalHash &&
              index.registrationId === slot.registrationId;
            const exactMirror =
              mirror !== null &&
              mirror.principalId === current.principalId &&
              mirror.principalHash === current.principalHash &&
              mirror.registrationId === slot.registrationId;
            if (slot.state === "reserved" && exactIndex) {
              try {
                await repair(index);
                const refreshed = await principals.get(row.key);
                const refreshedSlot = refreshed?.slots.find(
                  (candidate) =>
                    candidate.credentialHash === slot.credentialHash &&
                    candidate.registrationId === slot.registrationId,
                );
                if (refreshedSlot !== undefined) {
                  retained.push(refreshedSlot);
                  continue;
                }
              } catch {
                retained.push(slot);
                continue;
              }
            }
            if (exactIndex || exactMirror) {
              retained.push(slot);
              continue;
            }
            if (slot.state === "reserved") {
              releasedReservations += 1;
            }
          }
          if (!sameSlots(current.slots, retained)) {
            await principals.putIfUnchanged(
              { ...current, slots: retained, updatedAt: now.value },
              row.version,
            );
          }
        }
      }

      let cursor: string | null;
      if (nextAdapterCursor !== null) {
        cursor = `${stage}:${nextAdapterCursor}`;
      } else {
        const position = stages.indexOf(stage);
        cursor =
          position === stages.length - 1 ? null : `${stages[position + 1]}:`;
      }
      return Object.freeze({
        inspected,
        deletedProofs,
        deletedTombstones,
        releasedReservations,
        rejected,
        cursor,
        hasMore: cursor !== null,
      });
    },
  };
}
