import type { Clock, PrincipalId } from "@pegma/spine";
import {
  defineCollection,
  type CollectionStore,
  type Store,
  type StoredRecord,
} from "@pegma/storage-core";

import {
  challengeHandleHash,
  challengeValueHash,
  constantTimeHashMatch,
  principalHash,
} from "./crypto.js";
import { IdentityError } from "./errors.js";
import {
  challengesCollection,
  type ChallengeKind,
  type ChallengeRecord,
} from "./records.js";
import {
  addMilliseconds,
  assertBoundedString,
  assertPrincipalId,
  timestampFromClock,
} from "./validation.js";

interface ChallengeServiceOptions {
  readonly store: Store;
  readonly clock: Clock;
  readonly newId: () => string;
  readonly ttlMs: number;
  readonly maxAttempts: number;
}

export interface ClaimedChallenge {
  readonly record: ChallengeRecord;
  readonly attemptHash: string;
}

export interface ChallengeService {
  storeChallenge(
    kind: ChallengeKind,
    challenge: string,
    principalId?: PrincipalId,
  ): Promise<string>;
  claimChallenge(
    handle: string,
    kind: ChallengeKind,
    principalId?: PrincipalId,
  ): Promise<ClaimedChallenge>;
  releaseFailedClaim(claim: ClaimedChallenge): Promise<void>;
  consumeClaim(claim: ClaimedChallenge): Promise<void>;
  matches(record: ChallengeRecord, candidate: string): Promise<boolean>;
  sweep(limit?: number, cursor?: string): Promise<ChallengeSweepResult>;
}

export interface ChallengeSweepResult {
  readonly pulled: number;
  readonly inspected: number;
  readonly deleted: number;
  readonly rejected: number;
  readonly cursor: string | null;
  readonly hasMore: boolean;
}

interface SafeScanRecord {
  readonly key: { readonly partition: string; readonly id: string };
  readonly value: unknown;
  readonly version: string;
}

interface SafeScanPage {
  readonly records: readonly unknown[];
  readonly nextCursor: string | null;
}

function challengeKey(hash: string) {
  return { partition: "challenges", id: hash };
}

function belongsTo(
  record: ChallengeRecord,
  kind: ChallengeKind,
  principalId: string | undefined,
  principalDigest: string | null,
): boolean {
  return (
    record.kind === kind &&
    (kind === "authentication" ||
      (record.principalId === principalId &&
        record.principalHash === principalDigest))
  );
}

const challengeScanCollection = defineCollection<StoredRecord>({
  name: challengesCollection.name,
  key: (record) =>
    challengesCollection.key(challengesCollection.codec.decode(record)),
  codec: {
    encode: (record) => record,
    decode: (record) => record,
  },
});

function ownData(value: object, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, name);
  if (
    descriptor === undefined ||
    !descriptor.enumerable ||
    !("value" in descriptor)
  ) {
    throw new IdentityError(
      "invalid_state",
      "Challenge scan returned malformed data.",
    );
  }
  return descriptor.value;
}

function scanRecord(value: unknown): SafeScanRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new IdentityError(
      "invalid_state",
      "Challenge scan returned malformed data.",
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
      "Challenge scan returned malformed data.",
    );
  }
  const key = ownData(value, "key");
  const record = ownData(value, "value");
  const version = ownData(value, "version");
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
      "Challenge scan returned malformed data.",
    );
  }
  const partition = ownData(key, "partition");
  const id = ownData(key, "id");
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
      "Challenge scan returned malformed data.",
    );
  }
  return Object.freeze({
    key: Object.freeze({ partition, id }),
    value: record,
    version,
  });
}

function scanPage(value: unknown, limit: number): SafeScanPage {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new IdentityError(
      "invalid_state",
      "Challenge scan returned malformed data.",
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
      "Challenge scan returned malformed data.",
    );
  }
  const records = ownData(value, "records");
  const nextCursor = ownData(value, "nextCursor");
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
      "Challenge scan returned malformed data.",
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
        "Challenge scan returned malformed data.",
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
      "Challenge scan returned malformed data.",
    );
  }
  return Object.freeze({
    records: Object.freeze(safeRecords),
    nextCursor,
  });
}

export function createChallengeService(
  options: ChallengeServiceOptions,
): ChallengeService {
  const collection: CollectionStore<ChallengeRecord> =
    options.store.collection(challengesCollection);
  const scanCollection = options.store.collection(challengeScanCollection);

  return {
    async storeChallenge(kind, challengeInput, principalInput) {
      const challenge = assertBoundedString(
        challengeInput,
        "WebAuthn challenge",
        1_024,
      );
      const principalId =
        principalInput === undefined
          ? undefined
          : assertPrincipalId(principalInput);
      if (
        (kind === "registration" && principalId === undefined) ||
        (kind === "authentication" && principalId !== undefined)
      ) {
        throw new IdentityError(
          "invalid_input",
          "Challenge ownership is invalid.",
        );
      }
      const ownerHash =
        principalId === undefined ? null : await principalHash(principalId);
      const challengeHash = await challengeValueHash(challenge);
      const { value: now, milliseconds } = timestampFromClock(options.clock);

      for (let attempt = 0; attempt < 4; attempt += 1) {
        const handle = assertBoundedString(
          options.newId(),
          "Generated challenge handle",
          256,
        );
        const handleHash = await challengeHandleHash(handle);
        const record: ChallengeRecord = {
          ...challengeKey(handleHash),
          handleHash,
          challengeHash,
          kind,
          state: "pending",
          principalId: principalId ?? null,
          principalHash: ownerHash,
          attemptId: null,
          attempts: 0,
          maxAttempts: options.maxAttempts,
          createdAt: now,
          expiresAt: addMilliseconds(milliseconds, options.ttlMs),
          updatedAt: now,
        };
        const inserted = await collection.insertIfAbsent(record);
        if (inserted.inserted) {
          return handle;
        }
      }
      throw new IdentityError(
        "invalid_state",
        "Could not allocate a unique challenge handle.",
      );
    },

    async claimChallenge(handleInput, kind, principalInput) {
      const handle = assertBoundedString(handleInput, "Challenge handle", 256);
      const principalId =
        principalInput === undefined
          ? undefined
          : assertPrincipalId(principalInput);
      const [handleHash, ownerHash] = await Promise.all([
        challengeHandleHash(handle),
        principalId === undefined
          ? Promise.resolve(null)
          : principalHash(principalId),
      ]);
      const attemptRaw = assertBoundedString(
        options.newId(),
        "Generated verification attempt",
        256,
      );
      const attemptHash = await challengeHandleHash(
        `verification:${attemptRaw}`,
      );
      const { value: now, milliseconds } = timestampFromClock(options.clock);
      let claimed = false;
      const result = await collection.update(
        challengeKey(handleHash),
        (current) => {
          if (
            current === null ||
            current.handleHash !== handleHash ||
            !belongsTo(current, kind, principalId, ownerHash)
          ) {
            return { action: "keep" };
          }
          const expired = Date.parse(current.expiresAt) <= milliseconds;
          if (
            current.state !== "pending" ||
            current.attempts >= current.maxAttempts ||
            expired
          ) {
            if (
              current.state === "pending" &&
              (expired || current.attempts >= current.maxAttempts)
            ) {
              return {
                action: "write",
                value: {
                  ...current,
                  state: "failed",
                  attemptId: null,
                  updatedAt: now,
                },
              };
            }
            return { action: "keep" };
          }
          claimed = true;
          return {
            action: "write",
            value: {
              ...current,
              state: "verifying",
              attemptId: attemptHash,
              attempts: current.attempts + 1,
              updatedAt: now,
            },
          };
        },
        { maxAttempts: 10 },
      );
      if (
        !claimed ||
        !result.written ||
        result.value === null ||
        result.value.state !== "verifying" ||
        result.value.attemptId !== attemptHash
      ) {
        throw new IdentityError(
          "verification_failed",
          "WebAuthn verification failed.",
        );
      }
      return Object.freeze({ record: result.value, attemptHash });
    },

    async releaseFailedClaim(claim) {
      const { value: now, milliseconds } = timestampFromClock(options.clock);
      await collection.update(
        challengeKey(claim.record.handleHash),
        (current) => {
          if (
            current === null ||
            current.state !== "verifying" ||
            current.attemptId !== claim.attemptHash
          ) {
            return { action: "keep" };
          }
          const terminal =
            current.attempts >= current.maxAttempts ||
            Date.parse(current.expiresAt) <= milliseconds;
          return {
            action: "write",
            value: {
              ...current,
              state: terminal ? "failed" : "pending",
              attemptId: null,
              updatedAt: now,
            },
          };
        },
        { maxAttempts: 10 },
      );
    },

    async consumeClaim(claim) {
      const now = timestampFromClock(options.clock).value;
      let consumed = false;
      const result = await collection.update(
        challengeKey(claim.record.handleHash),
        (current) => {
          if (
            current === null ||
            current.state !== "verifying" ||
            current.attemptId !== claim.attemptHash
          ) {
            return { action: "keep" };
          }
          consumed = true;
          return {
            action: "write",
            value: {
              ...current,
              state: "consumed",
              attemptId: null,
              updatedAt: now,
            },
          };
        },
        { maxAttempts: 10 },
      );
      if (!consumed || !result.written) {
        throw new IdentityError(
          "verification_failed",
          "WebAuthn verification failed.",
        );
      }
    },

    async matches(record, candidate) {
      if (
        typeof candidate !== "string" ||
        candidate.length === 0 ||
        candidate.length > 1_024
      ) {
        return false;
      }
      return constantTimeHashMatch(
        record.challengeHash,
        "pegma.identity.challenge-value.v1",
        candidate,
      );
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
      const now = timestampFromClock(options.clock).milliseconds;
      const page = scanPage(
        await scanCollection.scan({
          limit: limitInput,
          ...(cursor === undefined ? {} : { cursor }),
        }),
        limitInput,
      );
      const pulled = page.records.length;
      let inspected = 0;
      let deleted = 0;
      let rejected = 0;

      for (const rawRow of page.records) {
        inspected += 1;
        let row: SafeScanRecord;
        let challenge: ChallengeRecord;
        try {
          row = scanRecord(rawRow);
          if (
            typeof row.value !== "object" ||
            row.value === null ||
            Array.isArray(row.value)
          ) {
            throw new IdentityError(
              "storage_corrupt",
              "Stored challenge is malformed.",
            );
          }
          challenge = challengesCollection.codec.decode(
            row.value as StoredRecord,
          );
        } catch {
          rejected += 1;
          continue;
        }
        if (
          row.key.partition !== challenge.partition ||
          row.key.id !== challenge.id ||
          challenge.partition !== "challenges" ||
          challenge.id !== challenge.handleHash
        ) {
          rejected += 1;
          continue;
        }
        const removable =
          Date.parse(challenge.expiresAt) <= now ||
          challenge.state === "consumed" ||
          challenge.state === "failed";
        if (
          removable &&
          (await collection.deleteIfUnchanged(row.key, row.version))
        ) {
          deleted += 1;
        }
      }
      return Object.freeze({
        pulled,
        inspected,
        deleted,
        rejected,
        cursor: page.nextCursor,
        hasMore: page.nextCursor !== null,
      });
    },
  };
}
