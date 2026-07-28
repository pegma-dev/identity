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
import {
  createIdentity,
  createMemoryChallengeRetention,
  IdentityError,
  normalizeEmail,
} from "./index.js";
import { challengesCollection, usersCollection } from "./records.js";

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
    challengeRetention: createMemoryChallengeRetention(),
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

  it("rejects an absent challenge retention policy during construction", () => {
    expect(() =>
      createIdentity({
        store: createMemoryStore(),
        issuer: "https://issuer.example",
        rpName: "Example",
        rpID: "example.test",
        origins: ["https://example.test"],
        registrationLimiter: allow,
        authenticationLimiter: allow,
      } as never),
    ).toThrow(IdentityError);
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
      retentionId: "b".repeat(64),
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
        retentionId: "b".repeat(64),
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
