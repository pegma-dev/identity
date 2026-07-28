import { randomUUID } from "node:crypto";

import { TableClient } from "@azure/data-tables";
import { fixedClock, type PrincipalId } from "@pegma/spine";
import { createAzureTablesStore } from "@pegma/storage-azure-tables";
import {
  createMemoryStore,
  type CollectionDefinition,
  type CollectionStore,
  type Store,
} from "@pegma/storage-core";
import { describe, expect, it } from "vitest";

import { TABLE_PORT } from "../../../test/azurite.js";
import { createIdentity, IdentityError, normalizeEmail } from "./index.js";
import { emailHash, principalHash } from "./crypto.js";
import {
  challengesCollection,
  emailIndexesCollection,
  usersCollection,
} from "./records.js";

const CONNECTION_STRING =
  "DefaultEndpointsProtocol=http;" +
  "AccountName=devstoreaccount1;" +
  "AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;" +
  `TableEndpoint=http://127.0.0.1:${TABLE_PORT}/devstoreaccount1;`;

const allow = {
  async allow() {
    return { allowed: true as const };
  },
};

function createAzuriteStore(): Store {
  const table = `identity${randomUUID().replaceAll("-", "")}`;
  const client = TableClient.fromConnectionString(CONNECTION_STRING, table, {
    allowInsecureConnection: true,
  });
  return createAzureTablesStore({ client });
}

function identity(store: Store, newId = () => randomUUID()) {
  return createIdentity({
    store,
    issuer: "https://issuer.example",
    rpName: "Example",
    rpID: "example.test",
    origins: ["https://example.test"],
    registrationLimiter: allow,
    authenticationLimiter: allow,
    clock: fixedClock("2026-07-27T12:00:00.000Z"),
    newId,
  });
}

describe("identity construction", () => {
  it("rejects accessor-bearing options without executing getters", () => {
    let getters = 0;
    const options = Object.create(null, {
      store: {
        enumerable: true,
        get() {
          getters += 1;
          return createMemoryStore();
        },
      },
    });

    expect(() => createIdentity(options)).toThrow(IdentityError);
    expect(getters).toBe(0);
  });
});

describe("canonical email normalization", () => {
  it("collides case and compatibility-equivalent Unicode", () => {
    expect(normalizeEmail(" Alice@Example.TEST ")).toBe("alice@example.test");
    expect(normalizeEmail("Ａｌｉｃｅ＠Ｅｘａｍｐｌｅ．ＴＥＳＴ")).toBe(
      "alice@example.test",
    );
    expect(normalizeEmail("Person@bücher.example")).toBe(
      "person@xn--bcher-kva.example",
    );
    expect(normalizeEmail("person@XN--BCHER-KVA.EXAMPLE")).toBe(
      "person@xn--bcher-kva.example",
    );
  });

  it("applies full default Unicode case folding before IDNA conversion", () => {
    expect(normalizeEmail("Straße@bücher.example")).toBe(
      "strasse@xn--bcher-kva.example",
    );
    expect(normalizeEmail("STRASSE@XN--BCHER-KVA.EXAMPLE")).toBe(
      "strasse@xn--bcher-kva.example",
    );
    expect(normalizeEmail("ΟΣ@Παράδειγμα.example")).toBe(
      normalizeEmail("οσ@παράδειγμα.example"),
    );
    expect(normalizeEmail("ος@παράδειγμα.example")).toBe(
      normalizeEmail("οσ@παράδειγμα.example"),
    );
  });

  it("uses Unicode default rather than Turkic-tailored case folding", () => {
    expect(normalizeEmail("I@example.test")).toBe("i@example.test");
    expect(normalizeEmail("İ@example.test")).toBe("i̇@example.test");
    expect(normalizeEmail("ı@example.test")).toBe("ı@example.test");
  });

  it("applies the NFKC_Casefold default-ignorable mapping", () => {
    expect(normalizeEmail("soft\u00ADhyphen@example.test")).toBe(
      "softhyphen@example.test",
    );
  });

  it("fails closed on normalization and IDNA code points outside the pinned repertoire", () => {
    expect(normalizeEmail("xs@example.test")).toBe("xs@example.test");
    expect(() => normalizeEmail("x\uA7F1@example.test")).toThrow(IdentityError);
    expect(() => normalizeEmail("person@x\uA7F1.example")).toThrow(
      IdentityError,
    );
  });

  it.each([
    "a\u0000@example.test",
    "a\u001F@example.test",
    "a\u007F@example.test",
    "a\u200B@example.test",
    "a\u202E@example.test",
  ])("rejects control or format input %j", (email) => {
    expect(() => normalizeEmail(email)).toThrow(IdentityError);
  });

  it("rejects non-string objects without coercion", () => {
    let getters = 0;
    const value = {
      get toString() {
        getters += 1;
        return () => "alice@example.test";
      },
    };
    expect(() => normalizeEmail(value)).toThrow(IdentityError);
    expect(getters).toBe(0);
  });

  it.each([
    "person@bad_domain.example",
    "person@-leading.example",
    "person@trailing-.example",
    "person@example..test",
    "person@example.test/path",
    "person@example.test\\path",
  ])("rejects invalid IDNA/domain input %j", (email) => {
    expect(() => normalizeEmail(email)).toThrow(IdentityError);
  });
});

describe.each([
  ["memory store", createMemoryStore],
  ["Azurite", createAzuriteStore],
] as const)("user model over %s", (_name, makeStore) => {
  it("makes concurrent canonical-email creation converge on one PrincipalId", async () => {
    const service = identity(makeStore());
    const results = await Promise.all(
      Array.from({ length: 20 }, (_, index) =>
        service.provisionVerifiedUser({
          principalId: `principal-${index}` as PrincipalId,
          email:
            index % 2 === 0
              ? "Concurrent@Example.TEST"
              : "Ｃｏｎｃｕｒｒｅｎｔ＠Ｅｘａｍｐｌｅ．ＴＥＳＴ",
        }),
      ),
    );

    expect(new Set(results.map(({ principalId }) => principalId))).toHaveLength(
      1,
    );
    await expect(
      service.findUserByEmail("concurrent@example.test"),
    ).resolves.toMatchObject({
      principalId: results[0]?.principalId,
      email: "concurrent@example.test",
      emailVerified: true,
      status: "active",
    });
  });

  it("keeps PrincipalId authoritative and returns exact frozen claims", async () => {
    const service = identity(makeStore());
    const principalId = "principal-authoritative" as PrincipalId;
    await service.provisionVerifiedUser({
      principalId,
      email: "contact@example.test",
    });

    const claims = await service.claimsFor(principalId);
    expect(Object.keys(claims)).toEqual(["issuer", "subject", "emailVerified"]);
    expect(Object.getOwnPropertyDescriptors(claims)).toMatchObject({
      issuer: { value: "https://issuer.example" },
      subject: { value: principalId },
      emailVerified: { value: true },
    });
    expect(Object.isFrozen(claims)).toBe(true);
    expect(claims).toEqual({
      issuer: "https://issuer.example",
      subject: principalId,
      emailVerified: true,
    });
  });

  it("makes concurrent U-label and A-label domains collide structurally", async () => {
    const service = identity(makeStore());
    const results = await Promise.all(
      Array.from({ length: 12 }, (_, index) =>
        service.provisionVerifiedUser({
          principalId: `idna-principal-${index}` as PrincipalId,
          email:
            index % 2 === 0
              ? "Person@bücher.example"
              : "person@xn--bcher-kva.example",
        }),
      ),
    );

    expect(new Set(results.map(({ principalId }) => principalId))).toHaveLength(
      1,
    );
    expect(results[0]?.email).toBe("person@xn--bcher-kva.example");
  });

  it("makes full-fold and IDNA variants collide under concurrency", async () => {
    const service = identity(makeStore());
    const variants = [
      "Straße@bücher.example",
      "STRASSE@XN--BCHER-KVA.EXAMPLE",
      "Strasse@BÜCHER.example",
      "straße@xn--bcher-kva.example",
    ];
    const results = await Promise.all(
      Array.from({ length: 16 }, (_, index) =>
        service.provisionVerifiedUser({
          principalId: `casefold-principal-${index}` as PrincipalId,
          email: variants[index % variants.length] ?? variants[0]!,
        }),
      ),
    );

    expect(new Set(results.map(({ principalId }) => principalId))).toHaveLength(
      1,
    );
    expect(results[0]?.email).toBe("strasse@xn--bcher-kva.example");
  });
});

describe("repair and hostile input", () => {
  it("repairs a crash after prepare and converges to active", async () => {
    const inner = createMemoryStore();
    let failIndexTransition = true;
    const crashing: Store = {
      collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
        const collection = inner.collection(definition);
        if (definition.name !== "pegma_identity_email_indexes") {
          return collection;
        }
        return {
          ...collection,
          async update(key, decide, options) {
            if (failIndexTransition) {
              failIndexTransition = false;
              throw new Error("simulated crash");
            }
            return collection.update(key, decide, options);
          },
        };
      },
    };
    const service = identity(crashing);

    await expect(
      service.provisionVerifiedUser({
        principalId: "repair-principal",
        email: "repair@example.test",
      }),
    ).rejects.toThrow("simulated crash");
    await expect(
      service.repairUserByEmail("REPAIR@example.test"),
    ).resolves.toMatchObject({
      principalId: "repair-principal",
      status: "active",
      emailVerified: true,
    });
  });

  it("rejects an owner-digest substitution during an index transition", async () => {
    const inner = createMemoryStore();
    let failIndexTransition = true;
    const crashing: Store = {
      collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
        const collection = inner.collection(definition);
        if (definition.name !== "pegma_identity_email_indexes") {
          return collection;
        }
        return {
          ...collection,
          async update(key, decide, options) {
            if (failIndexTransition) {
              failIndexTransition = false;
              throw new Error("simulated crash");
            }
            return collection.update(key, decide, options);
          },
        };
      },
    };
    await expect(
      identity(crashing).provisionVerifiedUser({
        principalId: "concurrent-corruption-principal",
        email: "concurrent-corruption@example.test",
      }),
    ).rejects.toThrow("simulated crash");

    let writeDecisions = 0;
    const substituting: Store = {
      collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
        const collection = inner.collection(definition);
        if (definition.name !== "pegma_identity_email_indexes") {
          return collection;
        }
        return {
          ...collection,
          async update(key, decide, options) {
            return collection.update(
              key,
              async (current) => {
                if (current === null) {
                  return decide(current);
                }
                const corrupt = {
                  ...current,
                  principalHash: "f".repeat(64),
                };
                const decision = await decide(corrupt);
                if (decision.action === "write") {
                  writeDecisions += 1;
                }
                return decision;
              },
              options,
            );
          },
        };
      },
    };

    await expect(
      identity(substituting).repairUserByEmail(
        "concurrent-corruption@example.test",
      ),
    ).rejects.toMatchObject({ code: "storage_corrupt" });
    expect(writeDecisions).toBe(0);
  });

  it("does not follow a different coherent reservation returned from a kept transition", async () => {
    const inner = createMemoryStore();
    let failIndexTransition = true;
    const crashing: Store = {
      collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
        const collection = inner.collection(definition);
        if (definition.name !== "pegma_identity_email_indexes") {
          return collection;
        }
        return {
          ...collection,
          async update(key, decide, options) {
            if (failIndexTransition) {
              failIndexTransition = false;
              throw new Error("simulated crash");
            }
            return collection.update(key, decide, options);
          },
        };
      },
    };
    const email = "reservation-race@example.test";
    await expect(
      identity(crashing).provisionVerifiedUser({
        principalId: "original-reservation-principal",
        email,
      }),
    ).rejects.toThrow("simulated crash");

    const digest = await emailHash(email);
    const indexes = inner.collection(emailIndexesCollection);
    const key = {
      partition: `email-${digest.slice(0, 16)}`,
      id: digest,
    };
    const original = await indexes.get(key);
    if (original === null) {
      throw new Error("expected an email reservation");
    }
    const replacementPrincipal = "replacement-reservation-principal";
    const replacement = {
      ...original,
      principalId: replacementPrincipal,
      principalHash: await principalHash(replacementPrincipal),
      operationId: "replacement-operation",
    };

    let replacementReturned = false;
    let crossOperationMutations = 0;
    let transitionCalls = 0;
    const substituting: Store = {
      collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
        const collection = inner.collection(definition);
        if (definition.name === "pegma_identity_email_indexes") {
          return {
            ...collection,
            async update(_key, decide) {
              transitionCalls += 1;
              if (transitionCalls > 1) {
                throw new Error("repair followed the replacement reservation");
              }
              await expect(decide(original as T)).resolves.toMatchObject({
                action: "write",
              });
              await expect(decide(replacement as T)).resolves.toEqual({
                action: "keep",
              });
              replacementReturned = true;
              return {
                written: false,
                value: replacement as T,
                attempts: 1,
              };
            },
          };
        }
        return {
          ...collection,
          async insertIfAbsent(value) {
            if (replacementReturned) {
              crossOperationMutations += 1;
            }
            return collection.insertIfAbsent(value);
          },
          async put(value) {
            if (replacementReturned) {
              crossOperationMutations += 1;
            }
            return collection.put(value);
          },
          async putIfUnchanged(value, version) {
            if (replacementReturned) {
              crossOperationMutations += 1;
            }
            return collection.putIfUnchanged(value, version);
          },
          async update(updateKey, decide, options) {
            if (replacementReturned) {
              crossOperationMutations += 1;
            }
            return options === undefined
              ? collection.update(updateKey, decide)
              : collection.update(updateKey, decide, options);
          },
          async delete(deleteKey) {
            if (replacementReturned) {
              crossOperationMutations += 1;
            }
            return collection.delete(deleteKey);
          },
          async deleteIfUnchanged(deleteKey, version) {
            if (replacementReturned) {
              crossOperationMutations += 1;
            }
            return collection.deleteIfUnchanged(deleteKey, version);
          },
          async transact(partition, actions) {
            if (replacementReturned) {
              crossOperationMutations += 1;
            }
            return collection.transact(partition, actions);
          },
        };
      },
    };

    await expect(
      identity(substituting).repairUserByEmail(email),
    ).rejects.toMatchObject({ code: "conflict" });
    expect(replacementReturned).toBe(true);
    expect(transitionCalls).toBe(1);
    expect(crossOperationMutations).toBe(0);
    await expect(indexes.get(key)).resolves.toMatchObject({
      principalId: original.principalId,
      operationId: original.operationId,
      state: "reserved",
    });
  });

  it.each([
    ["memory store", createMemoryStore],
    ["Azurite", createAzuriteStore],
  ] as const)(
    "rejects a mismatched email-index principal hash before any repair write over %s",
    async (_name, makeStore) => {
      const inner = makeStore();
      const initial = identity(inner);
      await initial.provisionVerifiedUser({
        principalId: "principal-email-index-corruption",
        email: "corrupt-index@example.test",
      });
      const digest = await emailHash("corrupt-index@example.test");
      const indexes = inner.collection(emailIndexesCollection);
      const key = {
        partition: `email-${digest.slice(0, 16)}`,
        id: digest,
      };
      const original = await indexes.get(key);
      if (original === null) {
        throw new Error("expected an email index");
      }
      const corruptHash =
        original.principalHash === "f".repeat(64)
          ? "e".repeat(64)
          : "f".repeat(64);
      await indexes.put({ ...original, principalHash: corruptHash });

      let mutations = 0;
      const observed: Store = {
        collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
          const collection = inner.collection(definition);
          return {
            ...collection,
            async insertIfAbsent(value) {
              mutations += 1;
              return collection.insertIfAbsent(value);
            },
            async put(value) {
              mutations += 1;
              return collection.put(value);
            },
            async putIfUnchanged(value, version) {
              mutations += 1;
              return collection.putIfUnchanged(value, version);
            },
            async update(updateKey, decide, options) {
              mutations += 1;
              return options === undefined
                ? collection.update(updateKey, decide)
                : collection.update(updateKey, decide, options);
            },
            async delete(deleteKey) {
              mutations += 1;
              return collection.delete(deleteKey);
            },
            async deleteIfUnchanged(deleteKey, version) {
              mutations += 1;
              return collection.deleteIfUnchanged(deleteKey, version);
            },
            async transact(partition, actions) {
              mutations += 1;
              return collection.transact(partition, actions);
            },
          };
        },
      };

      await expect(
        identity(observed).repairUserByEmail("CORRUPT-INDEX@example.test"),
      ).rejects.toMatchObject({ code: "storage_corrupt" });
      expect(mutations).toBe(0);
      await expect(indexes.get(key)).resolves.toMatchObject({
        principalId: original.principalId,
        principalHash: corruptHash,
        state: "active",
      });
    },
  );

  it("rejects accessor-bearing inputs without executing getters", async () => {
    let getters = 0;
    const input = Object.create(null, {
      principalId: {
        enumerable: true,
        get() {
          getters += 1;
          return "attacker";
        },
      },
      email: {
        enumerable: true,
        value: "attacker@example.test",
      },
    });

    await expect(
      identity(createMemoryStore()).provisionVerifiedUser(input),
    ).rejects.toMatchObject({
      code: "invalid_input",
    });
    expect(getters).toBe(0);
  });

  it("rejects accessor-bearing storage records without executing getters", () => {
    let getters = 0;
    const record = Object.create(null, {
      partition: {
        enumerable: true,
        get() {
          getters += 1;
          return "principal-attacker";
        },
      },
    });

    expect(() => usersCollection.codec.decode(record)).toThrow(IdentityError);
    expect(getters).toBe(0);
  });

  it.each([
    { maxAttempts: 11 },
    { expiresAt: "2026-07-27T12:15:00.001Z" },
    { expiresAt: "2026-07-27T11:59:59.999Z" },
    { updatedAt: "2026-07-27T11:59:59.999Z" },
    { updatedAt: "2026-07-27T12:05:00.001Z" },
    { state: "verifying", attemptId: "a".repeat(64), attempts: 0 },
    { state: "consumed", attempts: 0 },
  ])("rejects poisoned challenge bounds %#", (override) => {
    const record = {
      partition: "challenges",
      id: "a".repeat(64),
      handleHash: "a".repeat(64),
      challengeHash: "c".repeat(64),
      kind: "authentication",
      state: "pending",
      principalId: null,
      principalHash: null,
      attemptId: null,
      attempts: 0,
      maxAttempts: 3,
      createdAt: "2026-07-27T12:00:00.000Z",
      expiresAt: "2026-07-27T12:05:00.000Z",
      updatedAt: "2026-07-27T12:00:00.000Z",
      ...override,
    };

    expect(() => challengesCollection.codec.decode(record)).toThrow(
      IdentityError,
    );
  });

  it.each([
    { state: "failed", attempts: 0 },
    { state: "consumed", attempts: 1 },
  ])(
    "accepts a $state challenge updated after its bounded expiry",
    (terminal) => {
      const record = {
        partition: "challenges",
        id: "a".repeat(64),
        handleHash: "a".repeat(64),
        challengeHash: "c".repeat(64),
        kind: "authentication",
        principalId: null,
        principalHash: null,
        attemptId: null,
        maxAttempts: 3,
        createdAt: "2026-07-27T12:00:00.000Z",
        expiresAt: "2026-07-27T12:05:00.000Z",
        updatedAt: "2026-07-27T12:06:00.000Z",
        ...terminal,
      };

      expect(challengesCollection.codec.decode(record)).toMatchObject({
        ...terminal,
        maxAttempts: 3,
      });
    },
  );
});
