import {
  createDurableLimiter,
  type DurableRateLimiter,
} from "@pegma/rate-limit";
import type { MailSendRequest } from "@pegma/mail";
import {
  fixedClock,
  type Clock,
  type IsoTimestamp,
  type PrincipalId,
} from "@pegma/spine";
import {
  createMemoryStore,
  defineCollection,
  type CollectionDefinition,
  type CollectionStore,
  type EntityKey,
  type Store,
  type StoredRecord,
  type UpdateDecider,
  type UpdateOptions,
} from "@pegma/storage-core";
import { describe, expect, it, vi } from "vitest";

import {
  createHmacEmailCodeProtector,
  createIdentity,
  IdentityError,
  type IdentityMailContent,
} from "./index.js";
import { emailCodeHandleHash, emailHash, principalHash } from "./crypto.js";
import {
  emailOperationsCollection,
  type EmailCodeOperationRecord,
} from "./email-operation-records.js";
import {
  emailIndexesCollection,
  usersCollection,
  type UserRecord,
} from "./records.js";
import { TABLE_PORT } from "../../../test/azurite.js";

const CONNECTION_STRING =
  "DefaultEndpointsProtocol=http;" +
  "AccountName=devstoreaccount1;" +
  "AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;" +
  `TableEndpoint=http://127.0.0.1:${TABLE_PORT}/devstoreaccount1;`;

function createAzuriteStore(): Store {
  const table = `identityemail${randomUUID().replaceAll("-", "")}`;
  const client = TableClient.fromConnectionString(CONNECTION_STRING, table, {
    allowInsecureConnection: true,
  });
  return createAzureTablesStore({ client });
}

function failEmailIndexInsertOnce(inner: Store): {
  readonly store: Store;
  arm(): void;
} {
  let armed = false;
  return {
    store: {
      collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
        const collection = inner.collection(definition);
        if (definition.name !== "pegma_identity_email_indexes") {
          return collection;
        }
        return new Proxy(collection, {
          get(target, property, receiver) {
            if (property === "insertIfAbsent") {
              return async (value: T) => {
                if (armed) {
                  armed = false;
                  throw new Error("simulated process loss");
                }
                return target.insertIfAbsent(value);
              };
            }
            const member = Reflect.get(target, property, receiver) as unknown;
            return typeof member === "function" ? member.bind(target) : member;
          },
        });
      },
    },
    arm() {
      armed = true;
    },
  };
}

function observeGets(inner: Store): {
  readonly store: Store;
  snapshot(): Readonly<Record<string, number>>;
  reset(): void;
} {
  const counts = new Map<string, number>();
  return {
    store: {
      collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
        const collection = inner.collection(definition);
        return new Proxy(collection, {
          get(target, property, receiver) {
            if (property === "get") {
              return async (key: { partition: string; id: string }) => {
                counts.set(
                  definition.name,
                  (counts.get(definition.name) ?? 0) + 1,
                );
                return target.get(key);
              };
            }
            const member = Reflect.get(target, property, receiver) as unknown;
            return typeof member === "function"
              ? (member as (...input: unknown[]) => unknown).bind(target)
              : member;
          },
        });
      },
    },
    snapshot() {
      return Object.freeze(Object.fromEntries(counts));
    },
    reset() {
      counts.clear();
    },
  };
}

function failEmailChangeClearOnce(inner: Store): {
  readonly store: Store;
  arm(): void;
} {
  let armed = false;
  return {
    store: {
      collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
        const collection = inner.collection(definition);
        if (definition.name !== "pegma_identity_users") {
          return collection;
        }
        return new Proxy(collection, {
          get(target, property, receiver) {
            if (property === "update") {
              return async (
                key: EntityKey,
                decide: UpdateDecider<T>,
                updateOptions?: UpdateOptions,
              ) => {
                const guarded: UpdateDecider<T> = async (current) => {
                  const decision = await decide(current);
                  const before = current as UserRecord | null;
                  const after =
                    decision.action === "write"
                      ? (decision.value as UserRecord)
                      : null;
                  if (
                    armed &&
                    before?.emailChangeOperationHash !== null &&
                    before?.emailChangeOperationHash !== undefined &&
                    after?.emailChangeOperationHash === null
                  ) {
                    armed = false;
                    throw new Error("simulated loss before claim clear");
                  }
                  return decision;
                };
                return updateOptions === undefined
                  ? target.update(key, guarded)
                  : target.update(key, guarded, updateOptions);
              };
            }
            const member = Reflect.get(target, property, receiver) as unknown;
            return typeof member === "function"
              ? (member as (...input: unknown[]) => unknown).bind(target)
              : member;
          },
        });
      },
    },
    arm() {
      armed = true;
    },
  };
}

function failEmailChangeClaimOnce(inner: Store): {
  readonly store: Store;
  arm(): void;
} {
  let armed = false;
  return {
    store: {
      collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
        const collection = inner.collection(definition);
        if (definition.name !== "pegma_identity_users") {
          return collection;
        }
        return new Proxy(collection, {
          get(target, property, receiver) {
            if (property === "update") {
              return async (
                key: EntityKey,
                decide: UpdateDecider<T>,
                updateOptions?: UpdateOptions,
              ) => {
                const guarded: UpdateDecider<T> = async (current) => {
                  const decision = await decide(current);
                  const before = current as UserRecord | null;
                  const after =
                    decision.action === "write"
                      ? (decision.value as UserRecord)
                      : null;
                  if (
                    armed &&
                    before?.emailChangeOperationHash === null &&
                    after?.emailChangeOperationHash !== null &&
                    after?.emailChangeOperationHash !== undefined
                  ) {
                    armed = false;
                    throw new Error("simulated loss before email-change claim");
                  }
                  return decision;
                };
                return updateOptions === undefined
                  ? target.update(key, guarded)
                  : target.update(key, guarded, updateOptions);
              };
            }
            const member = Reflect.get(target, property, receiver) as unknown;
            return typeof member === "function"
              ? (member as (...input: unknown[]) => unknown).bind(target)
              : member;
          },
        });
      },
    },
    arm() {
      armed = true;
    },
  };
}

function substituteOperationBeforeCas(inner: Store): {
  readonly store: Store;
  arm(codeVerifier: string): void;
} {
  let replacementVerifier: string | null = null;
  return {
    store: {
      collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
        const collection = inner.collection(definition);
        if (definition.name !== emailOperationsCollection.name) {
          return collection;
        }
        return new Proxy(collection, {
          get(target, property, receiver) {
            if (property === "putIfUnchanged") {
              return async (value: T, version: string) => {
                if (replacementVerifier !== null) {
                  const operation = value as EmailCodeOperationRecord;
                  const current = await target.get({
                    partition: operation.partition,
                    id: operation.id,
                  });
                  if (
                    current !== null &&
                    (current as EmailCodeOperationRecord).kind === "operation"
                  ) {
                    await target.put({
                      ...(current as EmailCodeOperationRecord),
                      codeVerifier: replacementVerifier,
                    } as T);
                  }
                  replacementVerifier = null;
                }
                return target.putIfUnchanged(value, version);
              };
            }
            const member = Reflect.get(target, property, receiver) as unknown;
            return typeof member === "function"
              ? (member as (...input: unknown[]) => unknown).bind(target)
              : member;
          },
        });
      },
    },
    arm(codeVerifier) {
      replacementVerifier = codeVerifier;
    },
  };
}

const allow = {
  async allow() {
    return { allowed: true as const };
  },
};
const durableAllow = {
  ...allow,
  async sweep() {
    return { scanned: 0, deleted: 0 };
  },
};

function sequence(values: string[]): () => string {
  let index = 0;
  return () => values[index++] ?? `generated-${index}`;
}

function fixture(
  store: Store = createMemoryStore(),
  options: {
    readonly newId?: () => string;
    readonly requestLimiter?: DurableRateLimiter;
    readonly verificationLimiter?: DurableRateLimiter;
    readonly protector?: ReturnType<typeof createHmacEmailCodeProtector>;
    readonly clock?: Clock;
    readonly retentionMs?: number;
  } = {},
) {
  const protector =
    options.protector ??
    createHmacEmailCodeProtector(new Uint8Array(32).fill(0x42));
  const identity = createIdentity({
    store,
    issuer: "https://issuer.example",
    rpName: "Example",
    rpID: "example.test",
    origins: ["https://example.test"],
    registrationLimiter: allow,
    authenticationLimiter: allow,
    emailCodeProtector: protector,
    emailCodeRequestLimiter: options.requestLimiter ?? durableAllow,
    emailCodeVerificationLimiter: options.verificationLimiter ?? durableAllow,
    clock: options.clock ?? fixedClock("2026-07-28T12:00:00.000Z"),
    ...(options.retentionMs === undefined
      ? {}
      : { emailOperationRetentionMs: options.retentionMs }),
    newId:
      options.newId ??
      sequence([
        "code-handle",
        "principal-created",
        "operation-id",
        "operation-id-2",
      ]),
  });
  return { identity, protector, store };
}

async function codeFor(
  protector: ReturnType<typeof createHmacEmailCodeProtector>,
  handle: string,
): Promise<string> {
  return protector.deriveCode(await emailCodeHandleHash(handle));
}

describe("email-code protection", () => {
  it("derives a stable unbiased-width code and keyed verifier", async () => {
    const protector = createHmacEmailCodeProtector(
      new Uint8Array(32).fill(0x42),
    );
    const handleHash = await emailCodeHandleHash("vector-handle");

    const code = await protector.deriveCode(handleHash);
    const verifier = await protector.verifier(handleHash, code);

    expect(handleHash).toBe(
      "80868548595185ded3ee4af84d525e70e1da402d72fac236e88335564ed9462e",
    );
    expect(code).toBe("48549513");
    expect(verifier).toBe(
      "26a380e5e2f9bf351158b87590c9c010b1ef86d3cfe204ca7564cc71a33d06c3",
    );
    await expect(protector.matches(verifier, handleHash, code)).resolves.toBe(
      true,
    );
    await expect(
      protector.matches(verifier, handleHash, "00000000"),
    ).resolves.toBe(false);
  });

  it("copies key material before asynchronous import", async () => {
    const secret = new Uint8Array(32).fill(0x31);
    const protector = createHmacEmailCodeProtector(secret);
    secret.fill(0);

    await expect(
      protector.deriveCode(await emailCodeHandleHash("copy-test")),
    ).resolves.toMatch(/^\d{8}$/u);
  });

  it("accepts a plain copy of subclass-backed decoded key bytes", async () => {
    class DecodedBytes extends Uint8Array {}
    const decoded = new DecodedBytes(32).fill(0x31);
    expect(() => createHmacEmailCodeProtector(decoded)).toThrow(IdentityError);
    const protector = createHmacEmailCodeProtector(Uint8Array.from(decoded));

    await expect(
      protector.deriveCode(await emailCodeHandleHash("decoded-copy")),
    ).resolves.toMatch(/^\d{8}$/u);
  });

  it("does not validate a verifier under a different key", async () => {
    const first = createHmacEmailCodeProtector(new Uint8Array(32).fill(0x11));
    const second = createHmacEmailCodeProtector(new Uint8Array(32).fill(0x22));
    const handleHash = await emailCodeHandleHash("rotation-test");
    const code = await first.deriveCode(handleHash);
    const verifier = await first.verifier(handleHash, code);

    await expect(second.matches(verifier, handleHash, code)).resolves.toBe(
      false,
    );
  });
});

describe("email-code flows", () => {
  it("creates a verified principal without storing the raw handle or code", async () => {
    const { identity, protector, store } = fixture();
    const started = await identity.beginAccountCreation(
      "Person@Example.TEST",
      "source",
    );
    const code = await codeFor(protector, started.codeHandle);

    const rows = await store
      .collection(emailOperationsCollection)
      .list(`email-operation-${await emailCodeHandleHash(started.codeHandle)}`);
    const encoded = rows.map((row) =>
      emailOperationsCollection.codec.encode(row),
    );
    expect(JSON.stringify(encoded)).not.toContain(started.codeHandle);
    expect(JSON.stringify(encoded)).not.toContain(code);

    await expect(
      identity.finishAccountCreation({
        codeHandle: started.codeHandle,
        code,
        rateLimitKey: "source",
      }),
    ).resolves.toEqual({
      issuer: "https://issuer.example",
      subject: "principal-created",
      emailVerified: true,
    });
  });

  it("lets exactly one concurrent correct verification consume a code", async () => {
    const { identity, protector } = fixture();
    const started = await identity.beginAccountCreation(
      "race@example.test",
      "source",
    );
    const code = await codeFor(protector, started.codeHandle);
    const results = await Promise.allSettled(
      Array.from({ length: 12 }, () =>
        identity.finishAccountCreation({
          codeHandle: started.codeHandle,
          code,
          rateLimitKey: "source",
        }),
      ),
    );

    expect(results.filter(({ status }) => status === "fulfilled")).toHaveLength(
      1,
    );
    for (const result of results) {
      if (result.status === "rejected") {
        expect(result.reason).toMatchObject({ code: "verification_failed" });
      }
    }
  });

  it("cannot consume a verifier row substituted after verification", async () => {
    const substituting = substituteOperationBeforeCas(createMemoryStore());
    const { identity, protector, store } = fixture(substituting.store);
    const started = await identity.beginAccountCreation(
      "substitution@example.test",
      "source",
    );
    const handleHash = await emailCodeHandleHash(started.codeHandle);
    const correctCode = await codeFor(protector, started.codeHandle);
    const replacementCode =
      correctCode === "00000000" ? "00000001" : "00000000";
    const replacementVerifier = await protector.verifier(
      handleHash,
      replacementCode,
    );
    substituting.arm(replacementVerifier);

    await expect(
      identity.finishAccountCreation({
        codeHandle: started.codeHandle,
        code: correctCode,
        rateLimitKey: "source",
      }),
    ).rejects.toMatchObject({ code: "verification_failed" });
    await expect(
      store.collection(emailOperationsCollection).get({
        partition: `email-operation-${handleHash}`,
        id: handleHash,
      }),
    ).resolves.toMatchObject({
      kind: "operation",
      codeVerifier: replacementVerifier,
      state: "pending",
      attempts: 1,
    });
  });

  it("fails closed when a custom protector returns a truthy non-boolean", async () => {
    const real = createHmacEmailCodeProtector(new Uint8Array(32).fill(0x42));
    const malformed = {
      ...real,
      async matches() {
        return "false" as unknown as boolean;
      },
    };
    const { identity, store } = fixture(createMemoryStore(), {
      protector: malformed,
    });
    const started = await identity.beginAccountCreation(
      "malformed-port@example.test",
      "source",
    );
    const handleHash = await emailCodeHandleHash(started.codeHandle);

    await expect(
      identity.finishAccountCreation({
        codeHandle: started.codeHandle,
        code: await codeFor(real, started.codeHandle),
        rateLimitKey: "source",
      }),
    ).rejects.toMatchObject({ code: "invalid_state" });
    await expect(
      store.collection(emailOperationsCollection).get({
        partition: `email-operation-${handleHash}`,
        id: handleHash,
      }),
    ).resolves.toMatchObject({ state: "pending", attempts: 0 });
  });

  it("repairs creation after code consumption survives a process loss", async () => {
    const failing = failEmailIndexInsertOnce(createMemoryStore());
    const { identity, protector } = fixture(failing.store);
    const started = await identity.beginAccountCreation(
      "repair@example.test",
      "source",
    );
    const code = await codeFor(protector, started.codeHandle);
    failing.arm();

    await expect(
      identity.finishAccountCreation({
        codeHandle: started.codeHandle,
        code,
        rateLimitKey: "source",
      }),
    ).rejects.toThrow("simulated process loss");

    await expect(identity.sweepEmailOperations()).resolves.toMatchObject({
      repaired: 1,
      failed: 0,
    });
    await expect(
      identity.findUserByEmail("repair@example.test"),
    ).resolves.toMatchObject({
      emailVerified: true,
      status: "active",
    });
  });

  it("keeps unknown sign-in permanently suppressed and generic", async () => {
    const { identity, protector } = fixture();
    const unknown = await identity.beginEmailSignIn(
      "unknown@example.test",
      "source",
    );
    const descriptors = Object.getOwnPropertyDescriptors(unknown);
    expect(Object.isFrozen(unknown)).toBe(true);
    expect(Object.keys(descriptors)).toEqual(["codeHandle", "expiresAt"]);
    const code = await codeFor(protector, unknown.codeHandle);

    await expect(
      identity.finishEmailSignIn({
        codeHandle: unknown.codeHandle,
        code,
        rateLimitKey: "source",
      }),
    ).rejects.toMatchObject({
      code: "verification_failed",
      message: "Email verification failed.",
    });

    await identity.provisionVerifiedUser({
      principalId: "registered-later" as PrincipalId,
      email: "unknown@example.test",
    });
    await expect(
      identity.finishEmailSignIn({
        codeHandle: unknown.codeHandle,
        code,
        rateLimitKey: "source",
      }),
    ).rejects.toMatchObject({ code: "verification_failed" });
  });

  it("keeps known and unknown begin read/allocation work shapes aligned", async () => {
    async function measure(
      known: boolean,
      purpose: "account_creation" | "email_sign_in",
    ) {
      const observed = observeGets(createMemoryStore());
      const nextId = vi.fn(() => randomUUID());
      const requestLimiter = {
        allow: vi.fn(async () => ({ allowed: true as const })),
        async sweep() {
          return { scanned: 0, deleted: 0 };
        },
      };
      const { identity } = fixture(observed.store, {
        newId: nextId,
        requestLimiter,
      });
      if (known) {
        await identity.provisionVerifiedUser({
          principalId: "shape-principal" as PrincipalId,
          email: "shape@example.test",
        });
      }
      observed.reset();
      nextId.mockClear();
      requestLimiter.allow.mockClear();

      if (purpose === "account_creation") {
        await identity.beginAccountCreation("shape@example.test", "source");
      } else {
        await identity.beginEmailSignIn("shape@example.test", "source");
      }
      return {
        reads: observed.snapshot(),
        ids: nextId.mock.calls.length,
        limiterCalls: requestLimiter.allow.mock.calls.length,
      };
    }

    for (const purpose of ["account_creation", "email_sign_in"] as const) {
      const missing = await measure(false, purpose);
      await expect(measure(true, purpose)).resolves.toEqual(missing);
    }
  });

  it("checks both limiter dimensions and keeps the maximum retry", async () => {
    const limiter = {
      allow: vi
        .fn()
        .mockResolvedValueOnce({ allowed: false, retryAfter: 1_000 })
        .mockResolvedValueOnce({ allowed: false, retryAfter: 8_000 }),
      async sweep() {
        return { scanned: 0, deleted: 0 };
      },
    };
    const { identity } = fixture(createMemoryStore(), {
      requestLimiter: limiter,
    });

    await expect(
      identity.beginRecovery("person@example.test", "source"),
    ).rejects.toMatchObject({
      code: "rate_limited",
      retryAfter: 8_000,
    });
    expect(limiter.allow).toHaveBeenCalledTimes(2);
    expect(limiter.allow.mock.calls[0]?.[0]).toBe("source:source");
    expect(limiter.allow.mock.calls[1]?.[0]).toMatch(/^address:[0-9a-f]{64}$/u);
  });

  it("rejects accessor-bearing finish input without executing getters", async () => {
    let getters = 0;
    const verificationLimiter = {
      allow: vi.fn(async () => ({ allowed: true as const })),
      async sweep() {
        return { scanned: 0, deleted: 0 };
      },
    };
    const { identity } = fixture(createMemoryStore(), {
      verificationLimiter,
    });
    const input = Object.create(null, {
      codeHandle: {
        enumerable: true,
        get() {
          getters += 1;
          return "handle";
        },
      },
      code: { enumerable: true, value: "12345678" },
      rateLimitKey: { enumerable: true, value: "source" },
    });

    await expect(identity.finishRecovery(input)).rejects.toMatchObject({
      code: "verification_failed",
      message: "Email verification failed.",
    });
    expect(getters).toBe(0);
    expect(verificationLimiter.allow).toHaveBeenCalledTimes(2);
  });

  it("rate-limits malformed email-change principals without getters", async () => {
    let getters = 0;
    const verificationLimiter = {
      allow: vi.fn(async () => ({ allowed: true as const })),
      async sweep() {
        return { scanned: 0, deleted: 0 };
      },
    };
    const { identity } = fixture(createMemoryStore(), {
      verificationLimiter,
    });
    const input = Object.create(null, {
      principalId: {
        enumerable: true,
        get() {
          getters += 1;
          return "principal";
        },
      },
      codeHandle: { enumerable: true, value: "handle" },
      code: { enumerable: true, value: "12345678" },
      rateLimitKey: { enumerable: true, value: "source" },
    });

    await expect(identity.finishEmailChange(input)).rejects.toMatchObject({
      code: "verification_failed",
      message: "Email verification failed.",
    });
    expect(getters).toBe(0);
    expect(verificationLimiter.allow).toHaveBeenCalledTimes(2);
  });

  it("uses real durable counters for the email abuse floor", async () => {
    const store = createMemoryStore();
    const requestLimiter = createDurableLimiter(
      { name: "identity-email-request-test", limit: 1, windowMs: 60_000 },
      store,
      { clock: fixedClock("2026-07-28T12:00:00.000Z") },
    );
    const { identity } = fixture(store, { requestLimiter });

    await identity.beginRecovery("unknown@example.test", "source");
    await expect(
      identity.beginRecovery("unknown@example.test", "source"),
    ).rejects.toMatchObject({ code: "rate_limited" });
  });

  it("changes email through the repairable saga and notifies the old address", async () => {
    const store = createMemoryStore();
    const { identity, protector } = fixture(store, {
      newId: sequence(["change-handle", "mail-claim"]),
    });
    const principalId = "principal-change" as PrincipalId;
    await identity.provisionVerifiedUser({
      principalId,
      email: "old@example.test",
    });
    const started = await identity.beginEmailChange(
      principalId,
      "new@example.test",
      "source",
    );
    const code = await codeFor(protector, started.codeHandle);

    await expect(
      identity.finishEmailChange({
        principalId,
        codeHandle: started.codeHandle,
        code,
        rateLimitKey: "source",
      }),
    ).resolves.toMatchObject({
      principalId,
      email: "new@example.test",
      emailVerified: true,
    });
    await expect(
      identity.findUserByEmail("old@example.test"),
    ).resolves.toBeNull();
    await expect(
      identity.findUserByEmail("new@example.test"),
    ).resolves.toMatchObject({ principalId });
    const partition = `email-operation-${await emailCodeHandleHash(
      started.codeHandle,
    )}`;
    const operationRows = await store
      .collection(emailOperationsCollection)
      .list(partition);
    expect(operationRows).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "operation",
          effectState: "complete",
          notificationJobId: "old-address-notification",
        }),
        expect.objectContaining({
          kind: "mail",
          id: "old-address-notification",
          job: expect.objectContaining({
            recipientRef: "old@example.test",
          }),
        }),
      ]),
    );
  });

  it("repairs email change after old-index retirement but before claim clear", async () => {
    const failing = failEmailChangeClearOnce(createMemoryStore());
    const { identity, protector } = fixture(failing.store, {
      newId: () => randomUUID(),
    });
    const principalId = "change-repair-principal" as PrincipalId;
    await identity.provisionVerifiedUser({
      principalId,
      email: "before@example.test",
    });
    const started = await identity.beginEmailChange(
      principalId,
      "after@example.test",
      "source",
    );
    failing.arm();
    await expect(
      identity.finishEmailChange({
        principalId,
        codeHandle: started.codeHandle,
        code: await codeFor(protector, started.codeHandle),
        rateLimitKey: "source",
      }),
    ).rejects.toThrow("simulated loss before claim clear");

    await expect(identity.sweepEmailOperations()).resolves.toMatchObject({
      repaired: 1,
      failed: 0,
    });
    await expect(identity.getUser(principalId)).resolves.toMatchObject({
      email: "after@example.test",
    });
    await expect(
      identity.findUserByEmail("before@example.test"),
    ).resolves.toBeNull();
  });

  it("retains an aged completed operation until finalization succeeds", async () => {
    let now = "2026-07-28T12:00:00.000Z" as IsoTimestamp;
    const clock: Clock = { now: () => now };
    const failing = failEmailChangeClearOnce(createMemoryStore());
    const { identity, protector } = fixture(failing.store, {
      newId: () => randomUUID(),
      clock,
      retentionMs: 1,
    });
    const principalId = "finalize-retention-principal" as PrincipalId;
    await identity.provisionVerifiedUser({
      principalId,
      email: "retention-old@example.test",
    });
    const started = await identity.beginEmailChange(
      principalId,
      "retention-new@example.test",
      "source",
    );
    failing.arm();
    await expect(
      identity.finishEmailChange({
        principalId,
        codeHandle: started.codeHandle,
        code: await codeFor(protector, started.codeHandle),
        rateLimitKey: "source",
      }),
    ).rejects.toThrow("simulated loss before claim clear");

    now = "2026-08-05T12:00:00.000Z" as IsoTimestamp;
    const worker = identity.createMailWorker({
      provider: {
        async send() {
          return { providerMessageRef: randomUUID() };
        },
      },
      reconciliation: {
        async reconcile() {
          return { status: "unknown" as const };
        },
      },
      renderer: {
        async render(content) {
          return {
            subject: "Identity notice",
            text: content.expired
              ? "This request is no longer usable."
              : "Your email changed.",
          };
        },
      },
      workerId: "retention-worker",
    });
    await worker.runSendPage({ limit: 100 });
    const handleHash = await emailCodeHandleHash(started.codeHandle);
    const partition = `email-operation-${handleHash}`;
    const operations = failing.store.collection(emailOperationsCollection);
    const accepted = (await operations.list(partition)).filter(
      (row) => row.kind === "mail" && row.job.status === "accepted",
    );
    for (const row of accepted) {
      if (row.kind !== "mail" || row.job.providerMessageRef === undefined) {
        continue;
      }
      await identity.applyAuthenticatedMailCallback({
        partition,
        jobId: row.id,
        submissionGeneration: row.job.submissionGeneration,
        providerMessageRef: row.job.providerMessageRef,
        status: "delivered",
        occurredAt: now,
      });
    }

    failing.arm();
    await expect(identity.sweepEmailOperations()).resolves.toMatchObject({
      failed: 1,
      deleted: 0,
    });
    await expect(
      operations.get({ partition, id: handleHash }),
    ).resolves.not.toBeNull();

    await expect(identity.sweepEmailOperations()).resolves.toMatchObject({
      repaired: 1,
      deleted: 1,
    });
    await expect(
      operations.get({ partition, id: handleHash }),
    ).resolves.toBeNull();
    const ownerHash = await principalHash(principalId);
    await expect(
      failing.store.collection(usersCollection).get({
        partition: `principal-${ownerHash.slice(0, 16)}`,
        id: ownerHash,
      }),
    ).resolves.toMatchObject({ emailChangeOperationHash: null });
  });

  it("serializes concurrent email changes for one principal", async () => {
    const { identity, protector } = fixture(createMemoryStore(), {
      newId: () => randomUUID(),
    });
    const principalId = "change-race-principal" as PrincipalId;
    await identity.provisionVerifiedUser({
      principalId,
      email: "race-old@example.test",
    });
    const starts = await Promise.all([
      identity.beginEmailChange(principalId, "race-a@example.test", "source-a"),
      identity.beginEmailChange(principalId, "race-b@example.test", "source-b"),
    ]);
    const results = await Promise.allSettled(
      starts.map(async (started, index) =>
        identity.finishEmailChange({
          principalId,
          codeHandle: started.codeHandle,
          code: await codeFor(protector, started.codeHandle),
          rateLimitKey: `source-${index}`,
        }),
      ),
    );

    expect(results.filter(({ status }) => status === "fulfilled")).toHaveLength(
      1,
    );
    expect(results.filter(({ status }) => status === "rejected")).toHaveLength(
      1,
    );
    const user = await identity.getUser(principalId);
    expect(["race-a@example.test", "race-b@example.test"]).toContain(
      user?.email,
    );
  });

  it("leaves no claim or reservation when the target is already owned", async () => {
    const { identity, protector, store } = fixture(createMemoryStore(), {
      newId: () => randomUUID(),
    });
    const changer = "occupied-target-changer" as PrincipalId;
    const owner = "occupied-target-owner" as PrincipalId;
    await identity.provisionVerifiedUser({
      principalId: changer,
      email: "changer-old@example.test",
    });
    await identity.provisionVerifiedUser({
      principalId: owner,
      email: "occupied@example.test",
    });
    const blocked = await identity.beginEmailChange(
      changer,
      "occupied@example.test",
      "source-blocked",
    );
    await expect(
      identity.finishEmailChange({
        principalId: changer,
        codeHandle: blocked.codeHandle,
        code: await codeFor(protector, blocked.codeHandle),
        rateLimitKey: "source-blocked",
      }),
    ).rejects.toMatchObject({ code: "verification_failed" });

    const changerHash = await principalHash(changer);
    await expect(
      store.collection(usersCollection).get({
        partition: `principal-${changerHash.slice(0, 16)}`,
        id: changerHash,
      }),
    ).resolves.toMatchObject({ emailChangeOperationHash: null });
    await expect(
      identity.findUserByEmail("occupied@example.test"),
    ).resolves.toMatchObject({ principalId: owner });

    const retry = await identity.beginEmailChange(
      changer,
      "changer-free@example.test",
      "source-retry",
    );
    await expect(
      identity.finishEmailChange({
        principalId: changer,
        codeHandle: retry.codeHandle,
        code: await codeFor(protector, retry.codeHandle),
        rateLimitKey: "source-retry",
      }),
    ).resolves.toMatchObject({ email: "changer-free@example.test" });
  });

  it("lets the losing principal recover after racing for one target", async () => {
    const { identity, protector, store } = fixture(createMemoryStore(), {
      newId: () => randomUUID(),
    });
    const principals = [
      "shared-target-a" as PrincipalId,
      "shared-target-b" as PrincipalId,
    ] as const;
    await Promise.all([
      identity.provisionVerifiedUser({
        principalId: principals[0],
        email: "shared-a-old@example.test",
      }),
      identity.provisionVerifiedUser({
        principalId: principals[1],
        email: "shared-b-old@example.test",
      }),
    ]);
    const starts = await Promise.all(
      principals.map((principalId, index) =>
        identity.beginEmailChange(
          principalId,
          "shared-target@example.test",
          `source-${index}`,
        ),
      ),
    );
    const results = await Promise.allSettled(
      starts.map(async (started, index) =>
        identity.finishEmailChange({
          principalId: principals[index]!,
          codeHandle: started.codeHandle,
          code: await codeFor(protector, started.codeHandle),
          rateLimitKey: `source-${index}`,
        }),
      ),
    );
    expect(results.filter(({ status }) => status === "fulfilled")).toHaveLength(
      1,
    );
    expect(results.filter(({ status }) => status === "rejected")).toHaveLength(
      1,
    );
    const loserIndex = results.findIndex(({ status }) => status === "rejected");
    const loser = principals[loserIndex];
    if (loser === undefined) {
      throw new Error("Expected one losing email change.");
    }
    const loserHash = await principalHash(loser);
    await expect(
      store.collection(usersCollection).get({
        partition: `principal-${loserHash.slice(0, 16)}`,
        id: loserHash,
      }),
    ).resolves.toMatchObject({ emailChangeOperationHash: null });
    const targetHash = await emailHash("shared-target@example.test");
    await expect(
      store.collection(emailIndexesCollection).get({
        partition: `email-${targetHash.slice(0, 16)}`,
        id: targetHash,
      }),
    ).resolves.toMatchObject({ state: "active" });

    const retry = await identity.beginEmailChange(
      loser,
      "shared-loser-retry@example.test",
      "loser-retry",
    );
    await expect(
      identity.finishEmailChange({
        principalId: loser,
        codeHandle: retry.codeHandle,
        code: await codeFor(protector, retry.codeHandle),
        rateLimitKey: "loser-retry",
      }),
    ).resolves.toMatchObject({ email: "shared-loser-retry@example.test" });
  });

  it("cleans a pre-existing reservation after a competing change wins", async () => {
    const failing = failEmailChangeClaimOnce(createMemoryStore());
    const { identity, protector, store } = fixture(failing.store, {
      newId: () => randomUUID(),
    });
    const principalId = "reservation-crash-principal" as PrincipalId;
    await identity.provisionVerifiedUser({
      principalId,
      email: "reservation-old@example.test",
    });
    const crashed = await identity.beginEmailChange(
      principalId,
      "reservation-crashed@example.test",
      "crashed",
    );
    failing.arm();
    await expect(
      identity.finishEmailChange({
        principalId,
        codeHandle: crashed.codeHandle,
        code: await codeFor(protector, crashed.codeHandle),
        rateLimitKey: "crashed",
      }),
    ).rejects.toThrow("simulated loss before email-change claim");

    const winner = await identity.beginEmailChange(
      principalId,
      "reservation-winner@example.test",
      "winner",
    );
    await identity.finishEmailChange({
      principalId,
      codeHandle: winner.codeHandle,
      code: await codeFor(protector, winner.codeHandle),
      rateLimitKey: "winner",
    });
    await expect(identity.sweepEmailOperations()).resolves.toMatchObject({
      failed: 1,
    });
    const crashedTargetHash = await emailHash(
      "reservation-crashed@example.test",
    );
    await expect(
      store.collection(emailIndexesCollection).get({
        partition: `email-${crashedTargetHash.slice(0, 16)}`,
        id: crashedTargetHash,
      }),
    ).resolves.toBeNull();

    const retry = await identity.beginEmailChange(
      principalId,
      "reservation-crashed@example.test",
      "retry",
    );
    await expect(
      identity.finishEmailChange({
        principalId,
        codeHandle: retry.codeHandle,
        code: await codeFor(protector, retry.codeHandle),
        rateLimitKey: "retry",
      }),
    ).resolves.toMatchObject({ email: "reservation-crashed@example.test" });
  });

  it("terminalizes a losing same-target email change without hot repair", async () => {
    const { identity, protector, store } = fixture(createMemoryStore(), {
      newId: () => randomUUID(),
    });
    const principalId = "same-target-principal" as PrincipalId;
    await identity.provisionVerifiedUser({
      principalId,
      email: "same-old@example.test",
    });
    const [winner, loser] = await Promise.all([
      identity.beginEmailChange(
        principalId,
        "same-new@example.test",
        "source-a",
      ),
      identity.beginEmailChange(
        principalId,
        "same-new@example.test",
        "source-b",
      ),
    ]);
    await identity.finishEmailChange({
      principalId,
      codeHandle: winner.codeHandle,
      code: await codeFor(protector, winner.codeHandle),
      rateLimitKey: "source-a",
    });
    await expect(
      identity.finishEmailChange({
        principalId,
        codeHandle: loser.codeHandle,
        code: await codeFor(protector, loser.codeHandle),
        rateLimitKey: "source-b",
      }),
    ).rejects.toMatchObject({ code: "verification_failed" });

    const loserPartition = `email-operation-${await emailCodeHandleHash(
      loser.codeHandle,
    )}`;
    await expect(
      store.collection(emailOperationsCollection).get({
        partition: loserPartition,
        id: await emailCodeHandleHash(loser.codeHandle),
      }),
    ).resolves.toMatchObject({
      kind: "operation",
      state: "consumed",
      effectState: "failed",
    });
    await expect(identity.sweepEmailOperations()).resolves.toMatchObject({
      failed: 0,
    });
    await expect(identity.sweepEmailOperations()).resolves.toMatchObject({
      failed: 0,
    });
  });

  it("hands durable jobs to Mail asynchronously and suppresses unknown mail", async () => {
    const { identity } = fixture(createMemoryStore(), {
      newId: sequence(["known-handle", "unknown-handle", "worker-claim"]),
    });
    await identity.provisionVerifiedUser({
      principalId: "mail-principal" as PrincipalId,
      email: "known@example.test",
    });
    await identity.beginEmailSignIn("known@example.test", "source");
    await identity.beginRecovery("unknown@example.test", "source");
    const send = vi.fn(async (_request: MailSendRequest) => ({
      providerMessageRef: "provider-1",
    }));
    const render = vi.fn(async (content: IdentityMailContent) => ({
      subject: "Continue securely",
      text:
        content.code === undefined
          ? "This request is no longer usable."
          : `Your code is ${content.code}.`,
    }));
    const worker = identity.createMailWorker({
      provider: { send },
      reconciliation: {
        async reconcile() {
          return { status: "unknown" as const };
        },
      },
      renderer: { render },
      workerId: "worker-1",
    });

    const page = await worker.runSendPage({ limit: 100 });

    expect(page.examined).toBeGreaterThanOrEqual(4);
    expect(send).toHaveBeenCalledTimes(1);
    expect(render).toHaveBeenCalledTimes(1);
    expect(send.mock.calls[0]?.[0].idempotencyKey).toMatch(/^pegma-mail:v1:/u);
    expect(send.mock.calls[0]?.[0].mail.recipient).toBe("known@example.test");
    expect(send.mock.calls[0]?.[0].mail.text).toMatch(/\d{8}/u);
  });

  it("never renders a live code for a poisoned Mail binding", async () => {
    const { identity, store } = fixture();
    await identity.provisionVerifiedUser({
      principalId: "poison-target" as PrincipalId,
      email: "victim@example.test",
    });
    const started = await identity.beginEmailSignIn(
      "victim@example.test",
      "source",
    );
    const partition = `email-operation-${await emailCodeHandleHash(
      started.codeHandle,
    )}`;
    const operations = store.collection(emailOperationsCollection);
    const rows = await operations.list(partition);
    const mail = rows.find((row) => row.kind === "mail");
    expect(mail?.kind).toBe("mail");
    if (mail?.kind !== "mail") {
      throw new Error("mail fixture was not created");
    }
    await operations.put({
      ...mail,
      job: { ...mail.job, recipientRef: "attacker@example.test" },
    });
    const send = vi.fn(async (_request: MailSendRequest) => ({
      providerMessageRef: "must-not-send",
    }));
    const render = vi.fn(async (_content: IdentityMailContent) => ({
      subject: "Must not render",
      text: "Must not render",
    }));
    const worker = identity.createMailWorker({
      provider: { send },
      reconciliation: {
        async reconcile() {
          return { status: "unknown" as const };
        },
      },
      renderer: { render },
      workerId: "worker-poison-test",
    });

    await worker.runSendPage({ limit: 100 });

    expect(render).not.toHaveBeenCalled();
    expect(send).not.toHaveBeenCalled();
  });

  it("renders only a neutral notice after the code is consumed", async () => {
    const { identity, protector } = fixture();
    await identity.provisionVerifiedUser({
      principalId: "delayed-target" as PrincipalId,
      email: "delayed@example.test",
    });
    const started = await identity.beginEmailSignIn(
      "delayed@example.test",
      "source",
    );
    await identity.finishEmailSignIn({
      codeHandle: started.codeHandle,
      code: await codeFor(protector, started.codeHandle),
      rateLimitKey: "source",
    });
    const render = vi.fn(async (content: IdentityMailContent) => ({
      subject: "Identity request",
      text: content.expired
        ? "This request is no longer usable."
        : content.code!,
    }));
    const send = vi.fn(async (_request: MailSendRequest) => ({
      providerMessageRef: "provider-delayed",
    }));
    const worker = identity.createMailWorker({
      provider: { send },
      reconciliation: {
        async reconcile() {
          return { status: "unknown" as const };
        },
      },
      renderer: { render },
      workerId: "worker-delayed-test",
    });

    await worker.runSendPage({ limit: 100 });

    expect(render).toHaveBeenCalledWith(
      expect.objectContaining({ expired: true }),
    );
    expect(render.mock.calls[0]?.[0].code).toBeUndefined();
    expect(send.mock.calls[0]?.[0].mail.text).not.toMatch(/\d{8}/u);
  });

  it("retains malformed operation rows without stranding later sweep work", async () => {
    const { identity, store } = fixture();
    const raw = defineCollection<StoredRecord>({
      name: emailOperationsCollection.name,
      key: (record) => ({
        partition: String(record.partition),
        id: String(record.id),
      }),
      codec: {
        encode: (record) => record,
        decode: (record) => record,
      },
    });
    await store.collection(raw).put({
      partition: "email-operation-poison",
      id: "poison",
      kind: "operation",
      schemaVersion: 99,
    });
    await identity.beginRecovery("unknown@example.test", "source");

    await expect(identity.sweepEmailOperations(100)).resolves.toMatchObject({
      inspected: 3,
      rejected: 1,
    });
    await expect(
      store.collection(raw).get({
        partition: "email-operation-poison",
        id: "poison",
      }),
    ).resolves.not.toBeNull();
  });

  it("retains shape-valid operations with mismatched security bindings", async () => {
    const { identity, store } = fixture(createMemoryStore(), {
      newId: () => randomUUID(),
    });
    await identity.provisionVerifiedUser({
      principalId: "binding-owner" as PrincipalId,
      email: "binding@example.test",
    });
    const starts = await Promise.all([
      identity.beginRecovery("binding@example.test", "source-a"),
      identity.beginRecovery("binding@example.test", "source-b"),
    ]);
    const raw = defineCollection<StoredRecord>({
      name: emailOperationsCollection.name,
      key: (record) => ({
        partition: String(record.partition),
        id: String(record.id),
      }),
      codec: {
        encode: (record) => record,
        decode: (record) => record,
      },
    });
    const hashes = await Promise.all(
      starts.map(({ codeHandle }) => emailCodeHandleHash(codeHandle)),
    );
    const operations = store.collection(emailOperationsCollection);
    const first = await operations.get({
      partition: `email-operation-${hashes[0]}`,
      id: hashes[0]!,
    });
    const second = await operations.get({
      partition: `email-operation-${hashes[1]}`,
      id: hashes[1]!,
    });
    if (first?.kind !== "operation" || second?.kind !== "operation") {
      throw new Error("Expected email operations.");
    }
    await store.collection(raw).put({
      ...emailOperationsCollection.codec.encode(first),
      targetEmailHash: "0".repeat(64),
    });
    await store.collection(raw).put({
      ...emailOperationsCollection.codec.encode(second),
      principalHash: "1".repeat(64),
    });

    await expect(identity.sweepEmailOperations(100)).resolves.toMatchObject({
      rejected: 2,
    });
    await expect(
      Promise.all(
        hashes.map((hash) =>
          store.collection(raw).get({
            partition: `email-operation-${hash}`,
            id: hash,
          }),
        ),
      ),
    ).resolves.toEqual([
      expect.objectContaining({ targetEmailHash: "0".repeat(64) }),
      expect.objectContaining({ principalHash: "1".repeat(64) }),
    ]);
  });

  it("rejects impossible operation attempts and chronology", async () => {
    const { identity, store } = fixture();
    await identity.provisionVerifiedUser({
      principalId: "chronology-owner" as PrincipalId,
      email: "chronology@example.test",
    });
    const started = await identity.beginRecovery(
      "chronology@example.test",
      "source",
    );
    const handleHash = await emailCodeHandleHash(started.codeHandle);
    const operation = await store.collection(emailOperationsCollection).get({
      partition: `email-operation-${handleHash}`,
      id: handleHash,
    });
    if (operation?.kind !== "operation" || operation.principalId === null) {
      throw new Error("Expected a known recovery operation.");
    }
    const encoded = emailOperationsCollection.codec.encode(operation);
    const consumed = {
      ...encoded,
      state: "consumed",
      attempts: 1,
      effectState: "complete",
      resultPrincipalId: operation.principalId,
      resultPrincipalHash: operation.principalHash,
      consumedAt: "2026-07-28T12:01:00.000Z",
      updatedAt: "2026-07-28T12:02:00.000Z",
      completedAt: "2026-07-28T12:02:00.000Z",
    };
    const impossible = [
      { ...consumed, attempts: 0 },
      {
        ...encoded,
        state: "failed",
        attempts: 0,
        consumedAt: operation.createdAt,
      },
      { ...encoded, attempts: operation.maxAttempts },
      { ...consumed, consumedAt: "2026-07-28T11:59:59.999Z" },
      { ...consumed, consumedAt: "2026-07-28T12:03:00.000Z" },
      { ...consumed, completedAt: "2026-07-28T12:00:30.000Z" },
      { ...consumed, completedAt: "2026-07-28T12:03:00.000Z" },
      {
        ...encoded,
        updatedAt: "2026-07-28T12:15:00.001Z",
      },
    ];
    for (const [index, record] of impossible.entries()) {
      expect(
        emailOperationsCollection.codec.decode(record),
        `impossible operation ${index}`,
      ).toEqual({ kind: "invalid", partition: "invalid", id: "invalid" });
    }
    expect(
      emailOperationsCollection.codec.decode({
        ...encoded,
        attempts: operation.maxAttempts - 1,
        updatedAt: operation.expiresAt,
      }),
    ).toMatchObject({ kind: "operation", state: "pending" });
    expect(
      emailOperationsCollection.codec.decode({
        ...consumed,
        consumedAt: operation.createdAt,
        updatedAt: operation.createdAt,
        completedAt: operation.createdAt,
      }),
    ).toMatchObject({ kind: "operation", state: "consumed" });
  });

  it("rejects malformed secrets", () => {
    expect(() => createHmacEmailCodeProtector(new Uint8Array(31))).toThrow(
      IdentityError,
    );
  });
});

describe.each([
  ["memory", createMemoryStore],
  ["Azurite", createAzuriteStore],
] as const)("email lifecycle over %s", (_name, makeStore) => {
  it("converges canonically equivalent concurrent creations", async () => {
    const { identity, protector } = fixture(makeStore(), {
      newId: () => randomUUID(),
    });
    const starts = await Promise.all([
      identity.beginAccountCreation("Concurrent@Example.TEST", "source-a"),
      identity.beginAccountCreation("concurrent@example.test", "source-b"),
    ]);
    const results = await Promise.all(
      starts.map(async (started, index) =>
        identity.finishAccountCreation({
          codeHandle: started.codeHandle,
          code: await codeFor(protector, started.codeHandle),
          rateLimitKey: `source-${index}`,
        }),
      ),
    );

    expect(new Set(results.map(({ subject }) => subject))).toHaveLength(1);
    await expect(
      identity.findUserByEmail("concurrent@example.test"),
    ).resolves.toMatchObject({
      principalId: results[0]?.subject,
      emailVerified: true,
      status: "active",
    });
  });
});
import { randomUUID } from "node:crypto";

import { TableClient } from "@azure/data-tables";
import { createAzureTablesStore } from "@pegma/storage-azure-tables";
