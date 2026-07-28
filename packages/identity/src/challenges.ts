import type { Clock, IsoTimestamp, PrincipalId } from "@pegma/spine";
import type { CollectionStore, Store } from "@pegma/storage-core";

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
  assertCanonicalTimestamp,
  assertHash,
  assertPrincipalId,
  copyDataOnly,
  dataField,
  timestampFromClock,
} from "./validation.js";

interface ChallengeServiceOptions {
  readonly store: Store;
  readonly clock: Clock;
  readonly newId: () => string;
  readonly ttlMs: number;
  readonly maxAttempts: number;
  readonly retention: ChallengeRetention;
}

export interface ChallengeRetentionReference {
  readonly retentionId: string;
  readonly handleHash: string;
  readonly expiresAt: IsoTimestamp;
}

/**
 * A durable, lazily-read retention index supplied by the host.
 *
 * `candidates(limit)` must not pre-materialize more than `limit` references.
 * Identity calls `next()` at most `limit` times and never enumerates the
 * challenge collection. `complete()` removes a settled reference.
 */
export interface ChallengeRetention {
  track(reference: ChallengeRetentionReference): Promise<void>;
  candidates(limit: number): AsyncIterable<unknown>;
  complete(reference: ChallengeRetentionReference): Promise<void>;
}

/** In-memory retention index for tests and non-durable development hosts. */
export function createMemoryChallengeRetention(): ChallengeRetention {
  const references = new Map<string, ChallengeRetentionReference>();
  return {
    async track(reference) {
      references.set(reference.retentionId, Object.freeze({ ...reference }));
    },
    async *candidates(limit) {
      let yielded = 0;
      for (const reference of references.values()) {
        if (yielded >= limit) {
          break;
        }
        yielded += 1;
        yield reference;
      }
    },
    async complete(reference) {
      references.delete(reference.retentionId);
    },
  };
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
  sweep(limit?: number): Promise<ChallengeSweepResult>;
}

export interface ChallengeSweepResult {
  readonly pulled: number;
  readonly inspected: number;
  readonly deleted: number;
  readonly completed: number;
  readonly rejected: number;
  readonly hasMore: boolean;
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

function retentionReference(
  value: unknown,
): ChallengeRetentionReference | null {
  try {
    const safe = copyDataOnly(value);
    const retentionId = assertHash(
      assertBoundedString(
        dataField(safe, "retentionId"),
        "Retention identifier",
        64,
      ),
      "Retention identifier",
    );
    const handleHash = assertHash(
      assertBoundedString(
        dataField(safe, "handleHash"),
        "Retention handle hash",
        64,
      ),
      "Retention handle hash",
    );
    const expiresAt = assertCanonicalTimestamp(
      dataField(safe, "expiresAt"),
      "Retention expiry",
    );
    return Object.freeze({ retentionId, handleHash, expiresAt });
  } catch {
    return null;
  }
}

export function createChallengeService(
  options: ChallengeServiceOptions,
): ChallengeService {
  const collection: CollectionStore<ChallengeRecord> =
    options.store.collection(challengesCollection);

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
        const retentionId = await challengeHandleHash(
          `retention:${assertBoundedString(
            options.newId(),
            "Generated retention identifier",
            256,
          )}`,
        );
        const record: ChallengeRecord = {
          ...challengeKey(handleHash),
          handleHash,
          retentionId,
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
        const reference = Object.freeze({
          retentionId,
          handleHash,
          expiresAt: record.expiresAt,
        });
        try {
          // Track the harmless digest reference first. A crash can leave a
          // stale reference, which sweep settles safely; it can never leave
          // an authoritative challenge with no bounded path to retention.
          await options.retention.track(reference);
        } catch (cause) {
          throw new IdentityError(
            "invalid_state",
            "Challenge retention is unavailable.",
            { cause },
          );
        }
        const inserted = await collection.insertIfAbsent(record);
        if (inserted.inserted) {
          return handle;
        }
        try {
          await options.retention.complete(reference);
        } catch {
          // A collision reference is safe to retain: its unique retention id
          // cannot match the authoritative row and sweep will settle it.
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

    async sweep(limitInput = 100) {
      if (
        !Number.isSafeInteger(limitInput) ||
        limitInput < 1 ||
        limitInput > 1_000
      ) {
        throw new IdentityError("invalid_input", "Sweep limit is invalid.");
      }
      const now = timestampFromClock(options.clock).milliseconds;
      const iterator = options.retention
        .candidates(limitInput)
        [Symbol.asyncIterator]();
      let pulled = 0;
      let inspected = 0;
      let deleted = 0;
      let completed = 0;
      let rejected = 0;
      let sourceEnded = false;
      let retryNeeded = false;

      try {
        while (pulled < limitInput) {
          const next = await iterator.next();
          if (next.done) {
            sourceEnded = true;
            break;
          }
          pulled += 1;
          const reference = retentionReference(next.value);
          if (reference === null) {
            rejected += 1;
            retryNeeded = true;
            continue;
          }
          inspected += 1;
          const row = await collection.getVersioned(
            challengeKey(reference.handleHash),
          );
          if (row === null) {
            try {
              await options.retention.complete(reference);
              completed += 1;
            } catch {
              retryNeeded = true;
            }
            continue;
          }
          const authoritative =
            row.value.partition === "challenges" &&
            row.value.id === reference.handleHash &&
            row.value.handleHash === reference.handleHash &&
            row.value.retentionId === reference.retentionId &&
            row.value.expiresAt === reference.expiresAt;
          if (!authoritative) {
            // A stale or wrong reference never supplies a delete key for a
            // different row. Settle the reference and retain the record.
            try {
              await options.retention.complete(reference);
              completed += 1;
            } catch {
              retryNeeded = true;
            }
            continue;
          }
          const removable =
            Date.parse(row.value.expiresAt) <= now ||
            row.value.state === "consumed" ||
            row.value.state === "failed";
          if (!removable) {
            retryNeeded = true;
            continue;
          }
          const removed = await collection.deleteIfUnchanged(
            challengeKey(reference.handleHash),
            row.version,
          );
          if (!removed) {
            retryNeeded = true;
            continue;
          }
          deleted += 1;
          try {
            await options.retention.complete(reference);
            completed += 1;
          } catch {
            // The now-stale reference is harmless and will be settled on
            // retry.
            retryNeeded = true;
          }
        }
      } finally {
        if (!sourceEnded && iterator.return !== undefined) {
          await iterator.return();
        }
      }
      return Object.freeze({
        pulled,
        inspected,
        deleted,
        completed,
        rejected,
        hasMore: retryNeeded || (!sourceEnded && pulled === limitInput),
      });
    },
  };
}
