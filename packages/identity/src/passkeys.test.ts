import { randomUUID } from "node:crypto";

import { TableClient } from "@azure/data-tables";
import type { RateLimiter } from "@pegma/rate-limit";
import type { Clock, PrincipalId } from "@pegma/spine";
import { createAzureTablesStore } from "@pegma/storage-azure-tables";
import {
  createMemoryStore,
  defineCollection,
  type CollectionDefinition,
  type CollectionStore,
  type Store,
  type StoredRecord,
} from "@pegma/storage-core";
import { beforeEach, describe, expect, it, vi } from "vitest";

const ceremony = vi.hoisted(() => ({
  registrationChallenge: "registration_challenge",
  authenticationChallenge: "authentication_challenge",
  credentialId: "credential_one",
  registrationCounter: 0,
  authenticationCounter: 0,
  authenticationVerified: true,
  authenticationVerifications: 0,
}));

vi.mock("@simplewebauthn/server", () => ({
  async generateRegistrationOptions() {
    return {
      challenge: ceremony.registrationChallenge,
      rp: { id: "example.test", name: "Example" },
      user: {
        id: "dXNlcg",
        name: "person@example.test",
        displayName: "",
      },
      pubKeyCredParams: [],
      timeout: 60_000,
      attestation: "none",
      excludeCredentials: [],
      authenticatorSelection: {
        residentKey: "required",
        requireResidentKey: true,
        userVerification: "required",
      },
    };
  },
  async verifyRegistrationResponse(options: {
    expectedChallenge:
      string | ((candidate: string) => boolean | Promise<boolean>);
  }) {
    const challengeMatches =
      typeof options.expectedChallenge === "string"
        ? options.expectedChallenge === ceremony.registrationChallenge
        : await options.expectedChallenge(ceremony.registrationChallenge);
    if (!challengeMatches) {
      return { verified: false };
    }
    return {
      verified: true,
      registrationInfo: {
        userVerified: true,
        credential: {
          id: ceremony.credentialId,
          publicKey: new Uint8Array([1, 2, 3, 4]),
          counter: ceremony.registrationCounter,
          transports: ["internal"],
        },
      },
    };
  },
  async generateAuthenticationOptions() {
    return {
      challenge: ceremony.authenticationChallenge,
      timeout: 60_000,
      rpId: "example.test",
      userVerification: "required",
    };
  },
  async verifyAuthenticationResponse(options: {
    expectedChallenge:
      string | ((candidate: string) => boolean | Promise<boolean>);
  }) {
    ceremony.authenticationVerifications += 1;
    const challengeMatches =
      typeof options.expectedChallenge === "string"
        ? options.expectedChallenge === ceremony.authenticationChallenge
        : await options.expectedChallenge(ceremony.authenticationChallenge);
    return {
      verified: ceremony.authenticationVerified && challengeMatches,
      authenticationInfo: {
        credentialID: ceremony.credentialId,
        newCounter: ceremony.authenticationCounter,
        userVerified: true,
        credentialDeviceType: "multiDevice",
        credentialBackedUp: true,
        origin: "https://example.test",
        rpID: "example.test",
      },
    };
  },
}));

import {
  createIdentity,
  createMemoryChallengeRetention,
  IdentityError,
  type ChallengeRetention,
  type ChallengeRetentionLocator,
  type ChallengeRetentionReference,
} from "./index.js";
import { challengeHandleHash, credentialHash } from "./crypto.js";
import { validCounterTransition } from "./passkeys.js";
import {
  challengesCollection,
  credentialIndexesCollection,
  type CredentialIndexRecord,
} from "./records.js";
import { TABLE_PORT } from "../../../test/azurite.js";

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
  const table = `identitypasskeys${randomUUID().replaceAll("-", "")}`;
  const client = TableClient.fromConnectionString(CONNECTION_STRING, table, {
    allowInsecureConnection: true,
  });
  return createAzureTablesStore({ client });
}

function observeStore(inner: Store) {
  let armed = false;
  let mutations = 0;
  let userReads = 0;
  const store: Store = {
    collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
      const collection = inner.collection(definition);
      return {
        ...collection,
        async get(key) {
          if (armed && definition.name === "pegma_identity_users") {
            userReads += 1;
          }
          return collection.get(key);
        },
        async insertIfAbsent(value) {
          if (armed) {
            mutations += 1;
          }
          return collection.insertIfAbsent(value);
        },
        async put(value) {
          if (armed) {
            mutations += 1;
          }
          return collection.put(value);
        },
        async putIfUnchanged(value, version) {
          if (armed) {
            mutations += 1;
          }
          return collection.putIfUnchanged(value, version);
        },
        async update(key, decide, updateOptions) {
          if (armed) {
            mutations += 1;
          }
          return updateOptions === undefined
            ? collection.update(key, decide)
            : collection.update(key, decide, updateOptions);
        },
        async delete(key) {
          if (armed) {
            mutations += 1;
          }
          return collection.delete(key);
        },
        async deleteIfUnchanged(key, version) {
          if (armed) {
            mutations += 1;
          }
          return collection.deleteIfUnchanged(key, version);
        },
        async transact(partition, actions) {
          if (armed) {
            mutations += 1;
          }
          return collection.transact(partition, actions);
        },
      };
    },
  };
  return {
    store,
    arm() {
      armed = true;
    },
    mutations() {
      return mutations;
    },
    userReads() {
      return userReads;
    },
  };
}

interface InspectableRetention extends ChallengeRetention {
  corrupt(cursor: string, reference: unknown): Promise<void>;
  inject(
    cursor: string,
    locator: ChallengeRetentionLocator,
    reference: unknown,
  ): Promise<void>;
  failNextTrack(): void;
  peek(cursor: string): Promise<unknown | null>;
  cursors(): readonly string[];
}

interface RetentionHarness {
  readonly name: string;
  create(): {
    readonly store: Store;
    readonly retention: InspectableRetention;
  };
}

function createInspectableMemoryRetention(): InspectableRetention {
  const references = new Map<
    string,
    {
      readonly locator: ChallengeRetentionLocator;
      readonly reference: unknown;
      readonly expiresAt: string;
    }
  >();
  const order: string[] = [];
  let rejectNextTrack = false;
  return {
    async track(reference) {
      if (rejectNextTrack) {
        rejectNextTrack = false;
        throw new Error("retention track failed");
      }
      if (!references.has(reference.retentionId)) {
        order.unshift(reference.retentionId);
      }
      references.set(reference.retentionId, {
        locator: {
          retentionId: reference.retentionId,
          handleHash: reference.handleHash,
        },
        reference: Object.freeze({ ...reference }),
        expiresAt: reference.expiresAt,
      });
      return reference.retentionId;
    },
    async *candidates(limit, expiresThrough) {
      let yielded = 0;
      for (const cursor of order) {
        if (yielded >= limit) {
          break;
        }
        if (!references.has(cursor)) {
          continue;
        }
        const entry = references.get(cursor);
        if (entry === undefined) {
          continue;
        }
        if (entry.expiresAt > expiresThrough) {
          continue;
        }
        yielded += 1;
        yield {
          cursor,
          locator: entry.locator,
          reference: entry.reference,
        };
      }
    },
    async complete(cursor) {
      references.delete(cursor);
      const index = order.indexOf(cursor);
      if (index !== -1) {
        order.splice(index, 1);
      }
    },
    async corrupt(cursor, reference) {
      if (!references.has(cursor)) {
        throw new Error("retention cursor was not found");
      }
      const entry = references.get(cursor);
      if (entry === undefined) {
        throw new Error("retention cursor was not found");
      }
      references.set(cursor, { ...entry, reference });
    },
    async inject(cursor, locator, reference) {
      if (!references.has(cursor)) {
        order.unshift(cursor);
      }
      references.set(cursor, {
        locator,
        reference,
        expiresAt: "1970-01-01T00:00:00.000Z",
      });
    },
    failNextTrack() {
      rejectNextTrack = true;
    },
    async peek(cursor) {
      return references.get(cursor)?.reference ?? null;
    },
    cursors() {
      return [...order];
    },
  };
}

interface StoredRetentionRecord {
  readonly partition: string;
  readonly id: string;
  readonly expiresAt: string;
  readonly payload: string;
}

const storedRetentionCollection = defineCollection<StoredRetentionRecord>({
  name: "pegma_identity_test_retention",
  key: ({ partition, id }) => ({ partition, id }),
  codec: {
    encode: (value) => ({ ...value }),
    decode(record: StoredRecord) {
      const partition = Object.getOwnPropertyDescriptor(record, "partition");
      const id = Object.getOwnPropertyDescriptor(record, "id");
      const expiresAt = Object.getOwnPropertyDescriptor(record, "expiresAt");
      const payload = Object.getOwnPropertyDescriptor(record, "payload");
      if (
        partition === undefined ||
        !("value" in partition) ||
        typeof partition.value !== "string" ||
        !partition.value.startsWith("retention-") ||
        id === undefined ||
        !("value" in id) ||
        typeof id.value !== "string" ||
        expiresAt === undefined ||
        !("value" in expiresAt) ||
        typeof expiresAt.value !== "string" ||
        payload === undefined ||
        !("value" in payload) ||
        typeof payload.value !== "string"
      ) {
        throw new Error("stored retention record is malformed");
      }
      return {
        partition: partition.value,
        id: id.value,
        expiresAt: expiresAt.value,
        payload: payload.value,
      };
    },
  },
});

function storedRetentionCursor(locator: ChallengeRetentionLocator): string {
  return `${locator.retentionId}:${locator.handleHash}`;
}

function storedRetentionLocator(cursor: string): ChallengeRetentionLocator {
  const [retentionId, handleHash, extra] = cursor.split(":");
  if (
    retentionId === undefined ||
    handleHash === undefined ||
    extra !== undefined
  ) {
    throw new Error("retention cursor is malformed");
  }
  return { retentionId, handleHash };
}

function storedRetentionKey(locator: ChallengeRetentionLocator) {
  return {
    partition: `retention-${locator.retentionId}`,
    id: locator.handleHash,
  };
}

function createStoredRetention(store: Store): InspectableRetention {
  const records = store.collection(storedRetentionCollection);
  const order: string[] = [];
  const trustedExpiry = new Map<string, string>();
  let rejectNextTrack = false;
  const write = async (
    locator: ChallengeRetentionLocator,
    reference: unknown,
    expiresAt: string,
  ) => {
    const key = storedRetentionKey(locator);
    await records.put({
      ...key,
      expiresAt,
      payload: JSON.stringify(reference),
    });
  };
  return {
    async track(reference) {
      if (rejectNextTrack) {
        rejectNextTrack = false;
        throw new Error("retention track failed");
      }
      const locator = {
        retentionId: reference.retentionId,
        handleHash: reference.handleHash,
      };
      const cursor = storedRetentionCursor(locator);
      if (!order.includes(cursor)) {
        order.unshift(cursor);
      }
      trustedExpiry.set(cursor, reference.expiresAt);
      await write(locator, reference, reference.expiresAt);
      return cursor;
    },
    async *candidates(limit, expiresThrough) {
      let yielded = 0;
      for (const cursor of order) {
        if (yielded >= limit) {
          break;
        }
        const dueAt = trustedExpiry.get(cursor);
        if (dueAt === undefined || dueAt > expiresThrough) {
          continue;
        }
        const locator = storedRetentionLocator(cursor);
        const record = await records.get(storedRetentionKey(locator));
        if (record === null) {
          continue;
        }
        if (record.expiresAt > expiresThrough) {
          continue;
        }
        yielded += 1;
        yield {
          // Cursor and locator come from host metadata, never payload JSON.
          cursor: storedRetentionCursor({
            retentionId: record.partition.slice("retention-".length),
            handleHash: record.id,
          }),
          locator: {
            retentionId: record.partition.slice("retention-".length),
            handleHash: record.id,
          },
          reference: JSON.parse(record.payload) as unknown,
        };
      }
    },
    async complete(cursor) {
      await records.delete(storedRetentionKey(storedRetentionLocator(cursor)));
      trustedExpiry.delete(cursor);
      const index = order.indexOf(cursor);
      if (index !== -1) {
        order.splice(index, 1);
      }
    },
    async corrupt(cursor, reference) {
      const locator = storedRetentionLocator(cursor);
      const record = await records.get(storedRetentionKey(locator));
      if (record === null) {
        throw new Error("retention cursor was not found");
      }
      await write(locator, reference, record.expiresAt);
    },
    async inject(cursor, locator, reference) {
      if (cursor !== storedRetentionCursor(locator)) {
        throw new Error("retention cursor does not match locator metadata");
      }
      if (!order.includes(cursor)) {
        order.unshift(cursor);
      }
      trustedExpiry.set(cursor, "1970-01-01T00:00:00.000Z");
      await write(locator, reference, "1970-01-01T00:00:00.000Z");
    },
    failNextTrack() {
      rejectNextTrack = true;
    },
    async peek(cursor) {
      const record = await records.get(
        storedRetentionKey(storedRetentionLocator(cursor)),
      );
      return record === null ? null : (JSON.parse(record.payload) as unknown);
    },
    cursors() {
      return [...order];
    },
  };
}

const retentionHarnesses: readonly RetentionHarness[] = [
  {
    name: "memory",
    create() {
      return {
        store: createMemoryStore(),
        retention: createInspectableMemoryRetention(),
      };
    },
  },
  {
    name: "host-like stored adapter on Azurite",
    create() {
      const store = createAzuriteStore();
      return { store, retention: createStoredRetention(store) };
    },
  },
];

function registrationResponse() {
  return {
    id: ceremony.credentialId,
    rawId: ceremony.credentialId,
    type: "public-key" as const,
    clientExtensionResults: {},
    response: {
      clientDataJSON: "client_data",
      attestationObject: "attestation",
      transports: ["internal" as const],
    },
  };
}

function authenticationResponse() {
  return {
    id: ceremony.credentialId,
    rawId: ceremony.credentialId,
    type: "public-key" as const,
    clientExtensionResults: {},
    response: {
      clientDataJSON: "client_data",
      authenticatorData: "authenticator_data",
      signature: "signature",
      userHandle: "user_handle",
    },
  };
}

function service(
  store: Store = createMemoryStore(),
  options: {
    readonly clock?: Clock;
    readonly newId?: () => string;
    readonly authenticationLimiter?: RateLimiter;
    readonly challengeRetention?: ChallengeRetention;
  } = {},
) {
  return createIdentity({
    store,
    issuer: "https://issuer.example",
    rpName: "Example",
    rpID: "example.test",
    origins: ["https://example.test"],
    registrationLimiter: allow,
    authenticationLimiter: options.authenticationLimiter ?? allow,
    challengeRetention:
      options.challengeRetention ?? createMemoryChallengeRetention(),
    newId: options.newId ?? (() => randomUUID()),
    ...(options.clock === undefined ? {} : { clock: options.clock }),
  });
}

async function provision(identity: ReturnType<typeof service>) {
  const principalId = "principal-passkeys" as PrincipalId;
  await identity.provisionVerifiedUser({
    principalId,
    email: "person@example.test",
  });
  return principalId;
}

beforeEach(() => {
  ceremony.registrationChallenge = "registration_challenge";
  ceremony.authenticationChallenge = "authentication_challenge";
  ceremony.credentialId = "credential_one";
  ceremony.registrationCounter = 0;
  ceremony.authenticationCounter = 0;
  ceremony.authenticationVerified = true;
  ceremony.authenticationVerifications = 0;
});

describe("passkey ceremonies", () => {
  it("requires discoverable credentials and user verification", async () => {
    const identity = service();
    const principalId = await provision(identity);

    const registration = await identity.beginPasskeyRegistration(
      principalId,
      "request-origin",
    );
    expect(registration.options.authenticatorSelection).toMatchObject({
      residentKey: "required",
      requireResidentKey: true,
      userVerification: "required",
    });

    const authentication =
      await identity.beginPasskeyAuthentication("request-origin");
    expect(authentication.options.userVerification).toBe("required");
    expect(authentication.options.allowCredentials).toBeUndefined();
  });

  it("stores multiple passkeys and authenticates into exact claims", async () => {
    const identity = service();
    const principalId = await provision(identity);

    const first = await identity.beginPasskeyRegistration(
      principalId,
      "request-one",
    );
    await identity.finishPasskeyRegistration({
      principalId,
      challengeHandle: first.challengeHandle,
      label: "Phone",
      response: registrationResponse(),
    });

    ceremony.credentialId = "credential_two";
    const second = await identity.beginPasskeyRegistration(
      principalId,
      "request-two",
    );
    await identity.finishPasskeyRegistration({
      principalId,
      challengeHandle: second.challengeHandle,
      label: "Laptop",
      response: registrationResponse(),
    });

    const passkeys = await identity.listPasskeys(principalId);
    expect(passkeys.map(({ label }) => label).sort()).toEqual([
      "Laptop",
      "Phone",
    ]);

    ceremony.authenticationCounter = 0;
    const authentication =
      await identity.beginPasskeyAuthentication("request-three");
    const claims = await identity.finishPasskeyAuthentication({
      challengeHandle: authentication.challengeHandle,
      response: authenticationResponse(),
    });
    expect(claims).toEqual({
      issuer: "https://issuer.example",
      subject: principalId,
      emailVerified: true,
    });
    expect(Object.isFrozen(claims)).toBe(true);
  });

  it.each([
    ["memory store", createMemoryStore],
    ["Azurite", createAzuriteStore],
  ] as const)(
    "rejects a substituted credential owner before verification, claims, or mutation over %s",
    async (_name, makeStore) => {
      const inner = makeStore();
      const observed = observeStore(inner);
      const identity = service(observed.store);
      const principalId = await provision(identity);
      const substitutedPrincipalId =
        "principal-passkeys-substituted" as PrincipalId;
      await identity.provisionVerifiedUser({
        principalId: substitutedPrincipalId,
        email: "substituted@example.test",
      });
      const registration = await identity.beginPasskeyRegistration(
        principalId,
        "request-registration",
      );
      await identity.finishPasskeyRegistration({
        principalId,
        challengeHandle: registration.challengeHandle,
        label: "Security key",
        response: registrationResponse(),
      });

      const credentialDigest = await credentialHash(ceremony.credentialId);
      const credentials = inner.collection(credentialIndexesCollection);
      const key = {
        partition: `credential-${credentialDigest.slice(0, 16)}`,
        id: credentialDigest,
      };
      const original = await credentials.get(key);
      if (original === null) {
        throw new Error("expected a credential index");
      }
      await credentials.put({
        ...original,
        principalId: substitutedPrincipalId,
      });
      const authentication = await identity.beginPasskeyAuthentication(
        "request-authentication",
      );
      observed.arm();

      await expect(
        identity.repairPasskey(ceremony.credentialId),
      ).rejects.toMatchObject({ code: "storage_corrupt" });
      expect(observed.mutations()).toBe(0);
      await expect(
        identity.finishPasskeyAuthentication({
          challengeHandle: authentication.challengeHandle,
          response: authenticationResponse(),
        }),
      ).rejects.toMatchObject({ code: "storage_corrupt" });
      expect(ceremony.authenticationVerifications).toBe(0);
      expect(observed.userReads()).toBe(0);
      expect(observed.mutations()).toBe(0);
      await expect(credentials.get(key)).resolves.toMatchObject({
        principalId: substitutedPrincipalId,
        principalHash: original.principalHash,
        counter: original.counter,
      });
    },
  );

  it("rejects an accessor-bearing credential owner without executing it", async () => {
    const inner = createMemoryStore();
    let hostile = false;
    let getters = 0;
    const wrapped: Store = {
      collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
        const collection = inner.collection(definition);
        if (definition.name !== "pegma_identity_credential_indexes") {
          return collection;
        }
        return {
          ...collection,
          async get(key) {
            const record = await collection.get(key);
            if (!hostile || record === null) {
              return record;
            }
            const descriptors: PropertyDescriptorMap =
              Object.getOwnPropertyDescriptors(record);
            descriptors.principalId = {
              enumerable: true,
              configurable: true,
              get() {
                getters += 1;
                return "principal-passkeys-substituted";
              },
            };
            return Object.create(
              Object.getPrototypeOf(record),
              descriptors,
            ) as T;
          },
        };
      },
    };
    const identity = service(wrapped);
    const principalId = await provision(identity);
    const registration = await identity.beginPasskeyRegistration(
      principalId,
      "request-registration",
    );
    await identity.finishPasskeyRegistration({
      principalId,
      challengeHandle: registration.challengeHandle,
      label: "Security key",
      response: registrationResponse(),
    });
    const authentication = await identity.beginPasskeyAuthentication(
      "request-authentication",
    );
    hostile = true;

    await expect(
      identity.finishPasskeyAuthentication({
        challengeHandle: authentication.challengeHandle,
        response: authenticationResponse(),
      }),
    ).rejects.toMatchObject({ code: "storage_corrupt" });
    expect(getters).toBe(0);
    expect(ceremony.authenticationVerifications).toBe(0);
  });

  it.each([
    ["memory store", createMemoryStore],
    ["Azurite", createAzuriteStore],
  ] as const)(
    "rejects nonzero counter equality and regression over %s",
    async (_name, makeStore) => {
      const identity = service(makeStore());
      const principalId = await provision(identity);
      ceremony.registrationCounter = 1;
      const registration = await identity.beginPasskeyRegistration(
        principalId,
        "request-registration",
      );
      await identity.finishPasskeyRegistration({
        principalId,
        challengeHandle: registration.challengeHandle,
        label: "Security key",
        response: registrationResponse(),
      });

      for (const counter of [1, 0]) {
        ceremony.authenticationCounter = counter;
        const authentication = await identity.beginPasskeyAuthentication(
          `request-${counter}`,
        );
        await expect(
          identity.finishPasskeyAuthentication({
            challengeHandle: authentication.challengeHandle,
            response: authenticationResponse(),
          }),
        ).rejects.toMatchObject({ code: "verification_failed" });
      }
    },
  );

  it("allows only one concurrent assertion to claim an Azurite challenge", async () => {
    const identity = service(createAzuriteStore());
    const principalId = await provision(identity);
    const registration = await identity.beginPasskeyRegistration(
      principalId,
      "request-registration",
    );
    await identity.finishPasskeyRegistration({
      principalId,
      challengeHandle: registration.challengeHandle,
      label: "Security key",
      response: registrationResponse(),
    });
    const authentication = await identity.beginPasskeyAuthentication(
      "request-authentication",
    );

    const settled = await Promise.allSettled(
      Array.from({ length: 8 }, () =>
        identity.finishPasskeyAuthentication({
          challengeHandle: authentication.challengeHandle,
          response: authenticationResponse(),
        }),
      ),
    );
    expect(settled.filter(({ status }) => status === "fulfilled")).toHaveLength(
      1,
    );
    expect(settled.filter(({ status }) => status === "rejected")).toHaveLength(
      7,
    );
  });

  it("revokes the global credential lookup before removing the user copy", async () => {
    const identity = service();
    const principalId = await provision(identity);
    const registration = await identity.beginPasskeyRegistration(
      principalId,
      "request-registration",
    );
    await identity.finishPasskeyRegistration({
      principalId,
      challengeHandle: registration.challengeHandle,
      label: "Phone",
      response: registrationResponse(),
    });

    await expect(
      identity.removePasskey(principalId, ceremony.credentialId),
    ).resolves.toBe(true);
    await expect(identity.listPasskeys(principalId)).resolves.toEqual([]);
    const authentication = await identity.beginPasskeyAuthentication(
      "request-authentication",
    );
    await expect(
      identity.finishPasskeyAuthentication({
        challengeHandle: authentication.challengeHandle,
        response: authenticationResponse(),
      }),
    ).rejects.toMatchObject({ code: "verification_failed" });
  });

  it("does not let a stale repair snapshot reactivate a revoked generation", async () => {
    const inner = createMemoryStore();
    let armed = false;
    let releaseSnapshot!: () => void;
    let reportSnapshot!: () => void;
    const snapshotTaken = new Promise<void>((resolve) => {
      reportSnapshot = resolve;
    });
    const resumeSnapshot = new Promise<void>((resolve) => {
      releaseSnapshot = resolve;
    });
    const racing: Store = {
      collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
        const collection = inner.collection(definition);
        if (definition.name !== "pegma_identity_credential_indexes") {
          return collection;
        }
        return {
          ...collection,
          async get(key) {
            const snapshot = await collection.get(key);
            if (armed) {
              armed = false;
              reportSnapshot();
              await resumeSnapshot;
            }
            return snapshot;
          },
        };
      },
    };
    const identity = service(racing);
    const principalId = await provision(identity);
    const registration = await identity.beginPasskeyRegistration(
      principalId,
      "request-registration",
    );
    await identity.finishPasskeyRegistration({
      principalId,
      challengeHandle: registration.challengeHandle,
      label: "Security key",
      response: registrationResponse(),
    });

    armed = true;
    const staleRepair = identity.repairPasskey(ceremony.credentialId);
    await snapshotTaken;
    await expect(
      identity.removePasskey(principalId, ceremony.credentialId),
    ).resolves.toBe(true);
    releaseSnapshot();
    await expect(staleRepair).rejects.toMatchObject({ code: "conflict" });

    await expect(identity.listPasskeys(principalId)).resolves.toEqual([]);
    await expect(
      identity.repairPasskey(ceremony.credentialId),
    ).resolves.toBeNull();
    const authentication = await identity.beginPasskeyAuthentication(
      "request-after-revocation",
    );
    await expect(
      identity.finishPasskeyAuthentication({
        challengeHandle: authentication.challengeHandle,
        response: authenticationResponse(),
      }),
    ).rejects.toMatchObject({ code: "verification_failed" });
  });

  it("allows a freshly verified registration to replace a revoked generation", async () => {
    const identity = service();
    const principalId = await provision(identity);
    const first = await identity.beginPasskeyRegistration(
      principalId,
      "first-registration",
    );
    await identity.finishPasskeyRegistration({
      principalId,
      challengeHandle: first.challengeHandle,
      label: "Security key",
      response: registrationResponse(),
    });
    await identity.removePasskey(principalId, ceremony.credentialId);

    const second = await identity.beginPasskeyRegistration(
      principalId,
      "second-registration",
    );
    await identity.finishPasskeyRegistration({
      principalId,
      challengeHandle: second.challengeHandle,
      label: "Replacement key",
      response: registrationResponse(),
    });

    await expect(identity.listPasskeys(principalId)).resolves.toMatchObject([
      {
        credentialId: ceremony.credentialId,
        label: "Replacement key",
      },
    ]);
  });

  it.each([
    ["memory store", createMemoryStore],
    ["Azurite", createAzuriteStore],
  ] as const)(
    "lets only one concurrent re-registration own a revoked credential over %s",
    async (_name, makeStore) => {
      const inner = makeStore();
      let armed = false;
      let arrivals = 0;
      let release!: () => void;
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      const racing: Store = {
        collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
          const collection = inner.collection(definition);
          if (definition.name !== "pegma_identity_credential_indexes") {
            return collection;
          }
          return {
            ...collection,
            async update(key, decide, updateOptions) {
              const wrapped = async (current: T | null) => {
                const decision = await decide(current);
                const index = current as CredentialIndexRecord | null;
                const proposed =
                  decision.action === "write"
                    ? (decision.value as CredentialIndexRecord)
                    : null;
                if (
                  armed &&
                  index?.state === "revoked" &&
                  proposed?.state === "reserved"
                ) {
                  arrivals += 1;
                  if (arrivals === 2) {
                    release();
                  }
                  await gate;
                }
                return decision;
              };
              return updateOptions === undefined
                ? collection.update(key, wrapped)
                : collection.update(key, wrapped, updateOptions);
            },
          };
        },
      };
      let firstId = 0;
      let secondId = 0;
      const first = service(racing, {
        newId: () => `first_${(firstId += 1)}`,
      });
      const second = service(racing, {
        newId: () => `second_${(secondId += 1)}`,
      });
      const principalId = await provision(first);
      const initial = await first.beginPasskeyRegistration(
        principalId,
        "initial",
      );
      await first.finishPasskeyRegistration({
        principalId,
        challengeHandle: initial.challengeHandle,
        label: "Initial key",
        response: registrationResponse(),
      });
      await first.removePasskey(principalId, ceremony.credentialId);

      const [firstStart, secondStart] = await Promise.all([
        first.beginPasskeyRegistration(principalId, "first-race"),
        second.beginPasskeyRegistration(principalId, "second-race"),
      ]);
      armed = true;
      const settled = await Promise.allSettled([
        first.finishPasskeyRegistration({
          principalId,
          challengeHandle: firstStart.challengeHandle,
          label: "First replacement",
          response: registrationResponse(),
        }),
        second.finishPasskeyRegistration({
          principalId,
          challengeHandle: secondStart.challengeHandle,
          label: "Second replacement",
          response: registrationResponse(),
        }),
      ]);

      expect(
        settled.filter(({ status }) => status === "fulfilled"),
      ).toHaveLength(1);
      const rejected = settled.find(
        (result): result is PromiseRejectedResult =>
          result.status === "rejected",
      );
      expect(rejected?.reason).toMatchObject({ code: "conflict" });
      const [firstChallenge, secondChallenge] = await Promise.all(
        [firstStart, secondStart].map(async ({ challengeHandle }) => {
          const digest = await challengeHandleHash(challengeHandle);
          return inner
            .collection(challengesCollection)
            .get({ partition: "challenges", id: digest });
        }),
      );
      expect(firstChallenge?.state).toBe(
        settled[0]?.status === "fulfilled" ? "consumed" : "verifying",
      );
      expect(secondChallenge?.state).toBe(
        settled[1]?.status === "fulfilled" ? "consumed" : "verifying",
      );

      const listed = await first.listPasskeys(principalId);
      expect(listed).toHaveLength(1);
      const fulfilled = settled.find(
        (result): result is PromiseFulfilledResult<(typeof listed)[number]> =>
          result.status === "fulfilled",
      );
      expect(listed[0]?.label).toBe(fulfilled?.value.label);
    },
  );
});

describe("challenge controls", () => {
  it("stores only hashes of handles and WebAuthn challenges", async () => {
    const stored: unknown[] = [];
    const inner = createMemoryStore();
    const tracking: Store = {
      collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
        const collection = inner.collection(definition);
        return {
          ...collection,
          async insertIfAbsent(value) {
            if (definition.name === "pegma_identity_challenges") {
              stored.push(value);
            }
            return collection.insertIfAbsent(value);
          },
        };
      },
    };
    let id = 0;
    const identity = service(tracking, {
      newId: () => `generated_${(id += 1)}`,
    });
    const started = await identity.beginPasskeyAuthentication("request");

    const serialized = JSON.stringify(stored);
    expect(serialized).not.toContain(started.challengeHandle);
    expect(serialized).not.toContain(ceremony.authenticationChallenge);
    expect(serialized).toMatch(/[0-9a-f]{64}/u);
  });

  it("bounds attempts and makes one challenge single-flight", async () => {
    const identity = service();
    ceremony.authenticationVerified = false;
    const started = await identity.beginPasskeyAuthentication("request");

    for (let attempt = 0; attempt < 4; attempt += 1) {
      await expect(
        identity.finishPasskeyAuthentication({
          challengeHandle: started.challengeHandle,
          response: authenticationResponse(),
        }),
      ).rejects.toMatchObject({ code: "verification_failed" });
    }
  });

  it("keeps challenge material out of verification errors", async () => {
    const identity = service();
    ceremony.authenticationVerified = false;
    const started = await identity.beginPasskeyAuthentication("request");

    const error = await identity
      .finishPasskeyAuthentication({
        challengeHandle: started.challengeHandle,
        response: authenticationResponse(),
      })
      .catch((reason: unknown) => reason);
    expect(error).toBeInstanceOf(IdentityError);
    expect((error as Error & { cause?: unknown }).cause).toBeUndefined();
    expect(String(error)).not.toContain(started.challengeHandle);
    expect(String(error)).not.toContain(ceremony.authenticationChallenge);
  });

  it("sweeps expired challenges with a bounded version-conditional pass", async () => {
    let now = "2026-07-27T12:00:00.000Z";
    const identity = service(createMemoryStore(), {
      clock: { now: () => now },
    });
    await identity.beginPasskeyAuthentication("request");
    now = "2026-07-27T12:06:00.000Z";

    await expect(identity.sweepChallenges(1)).resolves.toEqual({
      pulled: 1,
      inspected: 1,
      deleted: 1,
      completed: 1,
      rejected: 0,
      hasMore: true,
    });
    await expect(identity.sweepChallenges(1)).resolves.toEqual({
      pulled: 0,
      inspected: 0,
      deleted: 0,
      completed: 0,
      rejected: 0,
      hasMore: false,
    });
  });

  it.each(retentionHarnesses)(
    "uses trusted $name due metadata when the stored expiry payload was corrupted",
    async ({ create }) => {
      let now = "2026-07-27T12:00:00.000Z";
      const { store, retention } = create();
      const identity = service(store, {
        clock: { now: () => now },
        challengeRetention: retention,
      });
      await identity.beginPasskeyAuthentication("request");
      const cursor = retention.cursors()[0];
      if (cursor === undefined) {
        throw new Error("expected a retention cursor");
      }
      const tracked = (await retention.peek(
        cursor,
      )) as ChallengeRetentionReference;
      await retention.corrupt(cursor, {
        ...tracked,
        expiresAt: "2026-07-27T12:04:00.000Z",
      });
      now = "2026-07-27T12:06:00.000Z";

      await expect(identity.sweepChallenges(1)).resolves.toMatchObject({
        pulled: 1,
        inspected: 1,
        deleted: 1,
        completed: 1,
        rejected: 0,
        hasMore: true,
      });
      await expect(retention.peek(cursor)).resolves.toBeNull();
    },
  );

  it.each(retentionHarnesses)(
    "does not let a newest-first live prefix starve an expired $name entry",
    async ({ create }) => {
      let now = "2026-07-27T12:00:00.000Z";
      const { store, retention } = create();
      const identity = service(store, {
        clock: { now: () => now },
        challengeRetention: retention,
      });
      for (const key of ["expired-one", "expired-two", "expired-three"]) {
        await identity.beginPasskeyAuthentication(key);
      }
      const expiredCursors = [...retention.cursors()];

      now = "2026-07-27T12:06:00.000Z";
      for (const key of ["live-one", "live-two", "live-three"]) {
        // The adapter is newest-first, and every pass adds another live entry
        // ahead of the remaining expired work.
        await identity.beginPasskeyAuthentication(key);
        await expect(identity.sweepChallenges(1)).resolves.toMatchObject({
          pulled: 1,
          inspected: 1,
          deleted: 1,
          completed: 1,
        });
      }

      await Promise.all(
        expiredCursors.map(async (cursor) =>
          expect(retention.peek(cursor)).resolves.toBeNull(),
        ),
      );
      expect(retention.cursors()).toHaveLength(3);
    },
  );

  it.each(retentionHarnesses)(
    "repairs and sweeps a $name entry whose payload expiry is syntactically malformed",
    async ({ create }) => {
      let now = "2026-07-27T12:00:00.000Z";
      const { store, retention } = create();
      const identity = service(store, {
        clock: { now: () => now },
        challengeRetention: retention,
      });
      await identity.beginPasskeyAuthentication("request");
      const cursor = retention.cursors()[0];
      if (cursor === undefined) {
        throw new Error("expected a retention cursor");
      }
      const tracked = (await retention.peek(
        cursor,
      )) as ChallengeRetentionReference;
      await retention.corrupt(cursor, {
        ...tracked,
        expiresAt: "not-a-timestamp",
      });
      now = "2026-07-27T12:06:00.000Z";

      await expect(identity.sweepChallenges(1)).resolves.toMatchObject({
        pulled: 1,
        inspected: 1,
        deleted: 1,
        completed: 1,
        rejected: 1,
        hasMore: true,
      });
      await expect(retention.peek(cursor)).resolves.toBeNull();
    },
  );

  it.each(retentionHarnesses)(
    "retains the $name pointer when canonical repair tracking fails",
    async ({ create }) => {
      let now = "2026-07-27T12:00:00.000Z";
      const { store, retention } = create();
      const identity = service(store, {
        clock: { now: () => now },
        challengeRetention: retention,
      });
      await identity.beginPasskeyAuthentication("request");
      const cursor = retention.cursors()[0];
      if (cursor === undefined) {
        throw new Error("expected a retention cursor");
      }
      const tracked = (await retention.peek(
        cursor,
      )) as ChallengeRetentionReference;
      const corrupted = { ...tracked, expiresAt: "not-a-timestamp" };
      await retention.corrupt(cursor, corrupted);
      retention.failNextTrack();
      now = "2026-07-27T12:06:00.000Z";

      await expect(identity.sweepChallenges(1)).resolves.toMatchObject({
        pulled: 1,
        inspected: 1,
        deleted: 0,
        completed: 0,
        rejected: 1,
        hasMore: true,
      });
      await expect(retention.peek(cursor)).resolves.toEqual(corrupted);

      await expect(identity.sweepChallenges(1)).resolves.toMatchObject({
        deleted: 1,
        completed: 1,
      });
      await expect(retention.peek(cursor)).resolves.toBeNull();
    },
  );

  it.each(retentionHarnesses)(
    "discards a malformed front entry by trusted $name cursor without starving the next challenge",
    async ({ create }) => {
      let now = "2026-07-27T12:00:00.000Z";
      const { store, retention } = create();
      const identity = service(store, {
        clock: { now: () => now },
        challengeRetention: retention,
      });
      await identity.beginPasskeyAuthentication("request");
      const challengeCursor = retention.cursors()[0];
      if (challengeCursor === undefined) {
        throw new Error("expected a retention cursor");
      }
      const malformedLocator = {
        retentionId: "d".repeat(64),
        handleHash: "e".repeat(64),
      };
      const malformedCursor = storedRetentionCursor(malformedLocator);
      await retention.inject(
        malformedCursor,
        malformedLocator,
        "malformed payload",
      );
      now = "2026-07-27T12:06:00.000Z";

      await expect(identity.sweepChallenges(1)).resolves.toMatchObject({
        pulled: 1,
        inspected: 1,
        deleted: 0,
        completed: 1,
        rejected: 1,
        hasMore: true,
      });
      await expect(retention.peek(malformedCursor)).resolves.toBeNull();

      await expect(identity.sweepChallenges(1)).resolves.toMatchObject({
        pulled: 1,
        inspected: 1,
        deleted: 1,
        completed: 1,
      });
      await expect(retention.peek(challengeCursor)).resolves.toBeNull();
    },
  );

  it.each(retentionHarnesses)(
    "uses trusted $name locator metadata when one cursor payload is fully replaced by another",
    async ({ create }) => {
      let now = "2026-07-27T12:00:00.000Z";
      const { store, retention } = create();
      const identity = service(store, {
        clock: { now: () => now },
        challengeRetention: retention,
      });
      await identity.beginPasskeyAuthentication("first");
      await identity.beginPasskeyAuthentication("second");
      const [wrongCursor, unrelatedCursor] = retention.cursors();
      if (wrongCursor === undefined || unrelatedCursor === undefined) {
        throw new Error("expected two retention cursors");
      }
      const unrelated = (await retention.peek(
        unrelatedCursor,
      )) as ChallengeRetentionReference;
      await retention.corrupt(wrongCursor, unrelated);
      now = "2026-07-27T12:06:00.000Z";

      await expect(identity.sweepChallenges(1)).resolves.toMatchObject({
        pulled: 1,
        inspected: 1,
        deleted: 1,
        completed: 1,
        hasMore: true,
      });
      await expect(retention.peek(wrongCursor)).resolves.toBeNull();
      await expect(retention.peek(unrelatedCursor)).resolves.toMatchObject(
        unrelated,
      );

      await expect(identity.sweepChallenges(1)).resolves.toMatchObject({
        deleted: 1,
        completed: 1,
      });
      await expect(retention.peek(unrelatedCursor)).resolves.toBeNull();
    },
  );

  it("pulls at most one lazy candidate for sweep(1) and never scans or deletes an unrelated row", async () => {
    const references: Array<{
      readonly retentionId: string;
      readonly handleHash: string;
      readonly expiresAt: string;
    }> = [];
    let sourcePulls = 0;
    let versionedGets = 0;
    let partitionScans = 0;
    const deletedIds: string[] = [];
    const retention: ChallengeRetention = {
      async track(reference) {
        references.push(reference);
        return reference.retentionId;
      },
      async *candidates() {
        for (const reference of references) {
          sourcePulls += 1;
          yield {
            cursor: reference.retentionId,
            locator: {
              retentionId: reference.retentionId,
              handleHash: reference.handleHash,
            },
            reference,
          };
        }
      },
      async complete() {},
    };
    const inner = createMemoryStore();
    const tracking: Store = {
      collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
        const collection = inner.collection(definition);
        if (definition.name !== "pegma_identity_challenges") {
          return collection;
        }
        return {
          ...collection,
          async getVersioned(key) {
            versionedGets += 1;
            return collection.getVersioned(key);
          },
          async listVersioned(partition) {
            partitionScans += 1;
            return collection.listVersioned(partition);
          },
          async deleteIfUnchanged(key, version) {
            deletedIds.push(key.id);
            return collection.deleteIfUnchanged(key, version);
          },
        };
      },
    };
    let now = "2026-07-27T12:00:00.000Z";
    const identity = service(tracking, {
      clock: { now: () => now },
      challengeRetention: retention,
    });
    await identity.beginPasskeyAuthentication("first");
    await identity.beginPasskeyAuthentication("second");
    now = "2026-07-27T12:06:00.000Z";

    const result = await identity.sweepChallenges(1);

    expect(sourcePulls).toBe(1);
    expect(versionedGets).toBe(1);
    expect(partitionScans).toBe(0);
    expect(deletedIds).toEqual([references[0]?.handleHash]);
    expect(deletedIds).not.toContain(references[1]?.handleHash);
    expect(result).toMatchObject({
      pulled: 1,
      inspected: 1,
      deleted: 1,
      hasMore: true,
    });
  });

  it("closes a lazy retention iterator when the sweep budget is exhausted", async () => {
    const references: Array<{
      readonly retentionId: string;
      readonly handleHash: string;
      readonly expiresAt: string;
    }> = [];
    let finalized = false;
    const retention: ChallengeRetention = {
      async track(reference) {
        references.push(reference);
        return reference.retentionId;
      },
      async *candidates() {
        try {
          for (const reference of references) {
            yield {
              cursor: reference.retentionId,
              locator: {
                retentionId: reference.retentionId,
                handleHash: reference.handleHash,
              },
              reference,
            };
          }
        } finally {
          finalized = true;
        }
      },
      async complete() {},
    };
    let now = "2026-07-27T12:00:00.000Z";
    const identity = service(createMemoryStore(), {
      clock: { now: () => now },
      challengeRetention: retention,
    });
    await identity.beginPasskeyAuthentication("first");
    await identity.beginPasskeyAuthentication("second");
    now = "2026-07-27T12:06:00.000Z";

    await identity.sweepChallenges(1);

    expect(finalized).toBe(true);
  });

  it("tracks retention before inserting an authoritative challenge", async () => {
    let challengeInserts = 0;
    const inner = createMemoryStore();
    const tracking: Store = {
      collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
        const collection = inner.collection(definition);
        if (definition.name !== "pegma_identity_challenges") {
          return collection;
        }
        return {
          ...collection,
          async insertIfAbsent(value) {
            challengeInserts += 1;
            return collection.insertIfAbsent(value);
          },
        };
      },
    };
    const retention: ChallengeRetention = {
      async track() {
        throw new Error("retention unavailable");
      },
      async *candidates() {},
      async complete() {},
    };
    const identity = service(tracking, { challengeRetention: retention });

    await expect(
      identity.beginPasskeyAuthentication("request"),
    ).rejects.toMatchObject({ code: "invalid_state" });
    expect(challengeInserts).toBe(0);
  });

  it("rejects accessor references and safely handles wrong, stale, and duplicate candidates", async () => {
    const tracked: Array<{
      readonly retentionId: string;
      readonly handleHash: string;
      readonly expiresAt: string;
    }> = [];
    let candidates: Array<{
      readonly cursor: string;
      readonly locator: ChallengeRetentionLocator;
      readonly reference: unknown;
    }> = [];
    let getters = 0;
    const retention: ChallengeRetention = {
      async track(reference) {
        tracked.push(reference);
        return reference.retentionId;
      },
      async *candidates() {
        yield* candidates;
      },
      async complete() {},
    };
    let now = "2026-07-27T12:00:00.000Z";
    const identity = service(createMemoryStore(), {
      clock: { now: () => now },
      challengeRetention: retention,
    });
    await identity.beginPasskeyAuthentication("request");
    const actual = tracked[0];
    if (actual === undefined) {
      throw new Error("expected a tracked challenge");
    }
    const accessor = Object.create(null, {
      retentionId: { enumerable: true, value: actual.retentionId },
      handleHash: {
        enumerable: true,
        get() {
          getters += 1;
          return actual.handleHash;
        },
      },
      expiresAt: { enumerable: true, value: actual.expiresAt },
    });
    candidates = [
      {
        cursor: "malformed-accessor",
        locator: {
          retentionId: actual.retentionId,
          handleHash: actual.handleHash,
        },
        reference: accessor,
      },
      {
        cursor: actual.retentionId,
        locator: {
          retentionId: actual.retentionId,
          handleHash: actual.handleHash,
        },
        reference: {
          retentionId: actual.retentionId,
          handleHash: actual.handleHash,
          expiresAt: "2026-07-27T12:04:00.000Z",
        },
      },
      {
        cursor: "wrong-reference",
        locator: {
          retentionId: "b".repeat(64),
          handleHash: "a".repeat(64),
        },
        reference: {
          retentionId: "b".repeat(64),
          handleHash: "a".repeat(64),
          expiresAt: actual.expiresAt,
        },
      },
      {
        cursor: actual.retentionId,
        locator: {
          retentionId: actual.retentionId,
          handleHash: actual.handleHash,
        },
        reference: actual,
      },
      {
        cursor: actual.retentionId,
        locator: {
          retentionId: actual.retentionId,
          handleHash: actual.handleHash,
        },
        reference: actual,
      },
    ];
    now = "2026-07-27T12:06:00.000Z";

    await expect(identity.sweepChallenges(5)).resolves.toMatchObject({
      pulled: 5,
      inspected: 5,
      deleted: 1,
      rejected: 1,
      hasMore: true,
    });
    expect(getters).toBe(0);
  });

  it("fails closed when the host rate limiter refuses", async () => {
    const identity = service(createMemoryStore(), {
      authenticationLimiter: {
        async allow() {
          return { allowed: false as const, retryAfter: 5_000 };
        },
      },
    });
    await expect(
      identity.beginPasskeyAuthentication("request"),
    ).rejects.toMatchObject({
      code: "rate_limited",
      retryAfter: 5_000,
    });
  });
});

describe("malformed inputs and counter rules", () => {
  it("rejects nested accessors before challenge lookup and executes no getter", async () => {
    let getters = 0;
    const response = Object.create(null, {
      id: {
        enumerable: true,
        get() {
          getters += 1;
          return "credential_attacker";
        },
      },
    });
    await expect(
      service().finishPasskeyAuthentication({
        challengeHandle: "unknown_challenge",
        response,
      }),
    ).rejects.toBeInstanceOf(IdentityError);
    expect(getters).toBe(0);
  });

  it.each([
    [0, 0, true],
    [0, 1, true],
    [1, 2, true],
    [1, 1, false],
    [2, 1, false],
    [1, 0, false],
  ])(
    "evaluates counter transition %i -> %i as %s",
    (stored, reported, expected) => {
      expect(validCounterTransition(stored, reported)).toBe(expected);
    },
  );
});
