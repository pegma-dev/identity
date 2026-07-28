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

import { createIdentity, IdentityError } from "./index.js";
import {
  challengeHandleHash,
  credentialHash,
  principalHash,
} from "./crypto.js";
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
    "rejects a substituted credential owner pair before verification or mutation over %s",
    async (_name, makeStore) => {
      const inner = makeStore();
      const observed = observeStore(inner);
      const identity = service(observed.store);
      const attackerPrincipalId = await provision(identity);
      const victimPrincipalId = "principal-passkeys-victim" as PrincipalId;
      await identity.provisionVerifiedUser({
        principalId: victimPrincipalId,
        email: "victim@example.test",
      });
      const registration = await identity.beginPasskeyRegistration(
        attackerPrincipalId,
        "request-registration",
      );
      await identity.finishPasskeyRegistration({
        principalId: attackerPrincipalId,
        challengeHandle: registration.challengeHandle,
        label: "Attacker key",
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
        principalId: victimPrincipalId,
        principalHash: await principalHash(victimPrincipalId),
      });
      const authentication = await identity.beginPasskeyAuthentication(
        "request-authentication",
      );
      observed.arm();

      await expect(
        identity.finishPasskeyAuthentication({
          challengeHandle: authentication.challengeHandle,
          response: authenticationResponse(),
        }),
      ).rejects.toMatchObject({ code: "storage_corrupt" });
      expect(ceremony.authenticationVerifications).toBe(0);
      expect(observed.userReads()).toBe(0);
      expect(observed.mutations()).toBe(0);
      const challengeDigest = await challengeHandleHash(
        authentication.challengeHandle,
      );
      await expect(
        inner
          .collection(challengesCollection)
          .get({ partition: "challenges", id: challengeDigest }),
      ).resolves.toMatchObject({ state: "pending", attempts: 0 });
      await expect(credentials.get(key)).resolves.toMatchObject({
        principalId: victimPrincipalId,
        counter: original.counter,
        publicKey: original.publicKey,
      });
    },
  );

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
    "repairs a crash after credential reservation but before the passkey mirror over %s",
    async (_name, makeStore) => {
      const inner = makeStore();
      let crashBeforeMirror = true;
      const crashing: Store = {
        collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
          const collection = inner.collection(definition);
          if (definition.name !== "pegma_identity_passkeys") {
            return collection;
          }
          return {
            ...collection,
            async update(key, decide, options) {
              if (crashBeforeMirror) {
                crashBeforeMirror = false;
                throw new Error("simulated reserved-before-mirror crash");
              }
              return options === undefined
                ? collection.update(key, decide)
                : collection.update(key, decide, options);
            },
          };
        },
      };
      const interrupted = service(crashing);
      const principalId = await provision(interrupted);
      const registration = await interrupted.beginPasskeyRegistration(
        principalId,
        "interrupted-registration",
      );

      await expect(
        interrupted.finishPasskeyRegistration({
          principalId,
          challengeHandle: registration.challengeHandle,
          label: "Interrupted key",
          response: registrationResponse(),
        }),
      ).rejects.toMatchObject({ code: "invalid_state" });

      const restarted = service(inner);
      await expect(
        restarted.repairPasskey(ceremony.credentialId),
      ).resolves.toMatchObject({
        credentialId: ceremony.credentialId,
        label: "Interrupted key",
      });
      await expect(
        restarted.removePasskey(principalId, ceremony.credentialId),
      ).resolves.toBe(true);

      const replacement = await restarted.beginPasskeyRegistration(
        principalId,
        "replacement-registration",
      );
      await expect(
        restarted.finishPasskeyRegistration({
          principalId,
          challengeHandle: replacement.challengeHandle,
          label: "Replacement key",
          response: registrationResponse(),
        }),
      ).resolves.toMatchObject({
        credentialId: ceremony.credentialId,
        label: "Replacement key",
      });
    },
  );

  it.each([
    ["memory store", createMemoryStore],
    ["Azurite", createAzuriteStore],
  ] as const)(
    "rejects owner-pair substitution of an interrupted reservation without writing over %s",
    async (_name, makeStore) => {
      const inner = makeStore();
      let crashBeforeMirror = true;
      const crashing: Store = {
        collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
          const collection = inner.collection(definition);
          if (definition.name !== "pegma_identity_passkeys") {
            return collection;
          }
          return {
            ...collection,
            async update(key, decide, options) {
              if (crashBeforeMirror) {
                crashBeforeMirror = false;
                throw new Error("simulated reserved-before-mirror crash");
              }
              return options === undefined
                ? collection.update(key, decide)
                : collection.update(key, decide, options);
            },
          };
        },
      };
      const interrupted = service(crashing);
      const attackerPrincipalId = await provision(interrupted);
      const registration = await interrupted.beginPasskeyRegistration(
        attackerPrincipalId,
        "interrupted-registration",
      );
      await expect(
        interrupted.finishPasskeyRegistration({
          principalId: attackerPrincipalId,
          challengeHandle: registration.challengeHandle,
          label: "Interrupted key",
          response: registrationResponse(),
        }),
      ).rejects.toMatchObject({ code: "invalid_state" });

      const credentialDigest = await credentialHash(ceremony.credentialId);
      const credentials = inner.collection(credentialIndexesCollection);
      const key = {
        partition: `credential-${credentialDigest.slice(0, 16)}`,
        id: credentialDigest,
      };
      const original = await credentials.get(key);
      if (original === null) {
        throw new Error("expected a reserved credential index");
      }
      const victimPrincipalId = "principal-reservation-victim" as PrincipalId;
      await credentials.put({
        ...original,
        principalId: victimPrincipalId,
        principalHash: await principalHash(victimPrincipalId),
      });
      const observed = observeStore(inner);
      observed.arm();

      await expect(
        service(observed.store).repairPasskey(ceremony.credentialId),
      ).rejects.toMatchObject({ code: "storage_corrupt" });
      expect(observed.mutations()).toBe(0);
      await expect(
        inner.collection(credentialIndexesCollection).get(key),
      ).resolves.toMatchObject({
        state: "reserved",
        principalId: victimPrincipalId,
      });
    },
  );

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

describe.each([
  {
    name: "memory store",
    create() {
      const store = createMemoryStore();
      return { nextStore: () => store };
    },
  },
  {
    name: "Azurite",
    create() {
      const table = `identityscan${randomUUID().replaceAll("-", "")}`;
      const client = TableClient.fromConnectionString(
        CONNECTION_STRING,
        table,
        {
          allowInsecureConnection: true,
        },
      );
      return {
        nextStore: () => createAzureTablesStore({ client }),
      };
    },
  },
])("authoritative challenge sweep over $name", ({ create }) => {
  it("reaches a quiescent cycle boundary with only live rows at limit one", async () => {
    const { nextStore } = create();
    let now = "2026-07-27T12:00:00.000Z";
    const writer = service(nextStore(), { clock: { now: () => now } });
    await writer.beginPasskeyAuthentication("live-one");
    await writer.beginPasskeyAuthentication("live-two");
    await writer.beginPasskeyAuthentication("live-three");

    let cursor: string | undefined;
    const results = [];
    do {
      const restarted = service(nextStore(), { clock: { now: () => now } });
      const result = await restarted.sweepChallenges(1, cursor);
      results.push(result);
      cursor = result.cursor ?? undefined;
    } while (results.at(-1)?.hasMore);

    expect(results).toHaveLength(3);
    expect(results.every(({ pulled }) => pulled <= 1)).toBe(true);
    expect(results.reduce((sum, { deleted }) => sum + deleted, 0)).toBe(0);
    expect(results.at(-1)).toMatchObject({ cursor: null, hasMore: false });
  });

  it("drains expired rows among live rows across restarted services", async () => {
    const { nextStore } = create();
    let now = "2026-07-27T12:00:00.000Z";
    const writer = service(nextStore(), { clock: { now: () => now } });
    await writer.beginPasskeyAuthentication("expired");
    now = "2026-07-27T12:06:00.000Z";
    await writer.beginPasskeyAuthentication("live-one");
    await writer.beginPasskeyAuthentication("live-two");

    let cursor: string | undefined;
    let deleted = 0;
    let passes = 0;
    do {
      const restarted = service(nextStore(), { clock: { now: () => now } });
      const result = await restarted.sweepChallenges(1, cursor);
      expect(result.pulled).toBeLessThanOrEqual(1);
      deleted += result.deleted;
      passes += 1;
      cursor = result.cursor ?? undefined;
      if (!result.hasMore) {
        break;
      }
    } while (passes < 10);

    expect(passes).toBeLessThan(10);
    expect(deleted).toBe(1);
    expect(cursor).toBeUndefined();
    await expect(
      nextStore().collection(challengesCollection).list("challenges"),
    ).resolves.toHaveLength(2);
  });

  it("makes concurrent sweeper replays repeat-safe", async () => {
    const { nextStore } = create();
    let now = "2026-07-27T12:00:00.000Z";
    const writer = service(nextStore(), { clock: { now: () => now } });
    await writer.beginPasskeyAuthentication("expired-one");
    await writer.beginPasskeyAuthentication("expired-two");
    now = "2026-07-27T12:06:00.000Z";
    let arrivals = 0;
    let releaseScans!: () => void;
    const bothScanned = new Promise<void>((resolve) => {
      releaseScans = resolve;
    });
    const racingStore = (): Store => {
      const inner = nextStore();
      return {
        collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
          const collection = inner.collection(definition);
          if (definition.name !== "pegma_identity_challenges") {
            return collection;
          }
          return {
            ...collection,
            async scan(options) {
              const page = await collection.scan(options);
              arrivals += 1;
              if (arrivals === 2) {
                releaseScans();
              }
              await bothScanned;
              return page;
            },
          };
        },
      };
    };

    const [first, second] = await Promise.all([
      service(racingStore(), { clock: { now: () => now } }).sweepChallenges(1),
      service(racingStore(), { clock: { now: () => now } }).sweepChallenges(1),
    ]);

    expect(first.deleted + second.deleted).toBe(1);
    expect(first.cursor).toBe(second.cursor);
    let cursor = first.cursor ?? undefined;
    let deleted = first.deleted + second.deleted;
    for (let pass = 0; pass < 5; pass += 1) {
      const result = await service(nextStore(), {
        clock: { now: () => now },
      }).sweepChallenges(1, cursor);
      deleted += result.deleted;
      cursor = result.cursor ?? undefined;
      if (!result.hasMore) {
        break;
      }
    }
    expect(deleted).toBe(2);
    expect(cursor).toBeUndefined();
  });
});

describe("authoritative challenge scan controls", () => {
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

  it("does not delete a challenge that changed after its scan page", async () => {
    const inner = createMemoryStore();
    let changeBeforeDelete = true;
    const racing: Store = {
      collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
        const collection = inner.collection(definition);
        if (definition.name !== "pegma_identity_challenges") {
          return collection;
        }
        return {
          ...collection,
          async deleteIfUnchanged(key, version) {
            if (changeBeforeDelete) {
              changeBeforeDelete = false;
              const current = await collection.get(key);
              if (current !== null) {
                await collection.put({
                  ...current,
                  expiresAt: "2026-07-27T12:10:00.000Z",
                });
              }
            }
            return collection.deleteIfUnchanged(key, version);
          },
        };
      },
    };
    let now = "2026-07-27T12:00:00.000Z";
    const identity = service(racing, { clock: { now: () => now } });
    await identity.beginPasskeyAuthentication("request");
    now = "2026-07-27T12:06:00.000Z";

    await expect(identity.sweepChallenges(1)).resolves.toMatchObject({
      pulled: 1,
      inspected: 1,
      deleted: 0,
      cursor: null,
      hasMore: false,
    });
    await expect(
      inner.collection(challengesCollection).list("challenges"),
    ).resolves.toHaveLength(1);
  });

  it("requests and receives at most the caller's bounded page", async () => {
    const inner = createMemoryStore();
    let scanCalls = 0;
    let requestedLimit = 0;
    let returnedRecords = 0;
    let partitionListings = 0;
    const tracking: Store = {
      collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
        const collection = inner.collection(definition);
        if (definition.name !== "pegma_identity_challenges") {
          return collection;
        }
        return {
          ...collection,
          async listVersioned(partition) {
            partitionListings += 1;
            return collection.listVersioned(partition);
          },
          async scan(options) {
            scanCalls += 1;
            requestedLimit = options.limit;
            const page = await collection.scan(options);
            returnedRecords = page.records.length;
            return page;
          },
        };
      },
    };
    const identity = service(tracking);
    await identity.beginPasskeyAuthentication("first");
    await identity.beginPasskeyAuthentication("second");

    await expect(identity.sweepChallenges(1)).resolves.toMatchObject({
      pulled: 1,
      inspected: 1,
      hasMore: true,
    });
    expect(scanCalls).toBe(1);
    expect(requestedLimit).toBe(1);
    expect(returnedRecords).toBe(1);
    expect(partitionListings).toBe(0);
  });

  it("rejects accessor-bearing scan pages without executing getters", async () => {
    const inner = createMemoryStore();
    let getters = 0;
    let hostile = false;
    const wrapped: Store = {
      collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
        const collection = inner.collection(definition);
        if (definition.name !== "pegma_identity_challenges") {
          return collection;
        }
        return {
          ...collection,
          async scan(options) {
            const page = await collection.scan(options);
            if (!hostile) {
              return page;
            }
            return Object.create(null, {
              records: {
                enumerable: true,
                get() {
                  getters += 1;
                  return page.records;
                },
              },
              nextCursor: {
                enumerable: true,
                value: page.nextCursor,
              },
            }) as typeof page;
          },
        };
      },
    };
    const identity = service(wrapped);
    await identity.beginPasskeyAuthentication("request");
    hostile = true;

    await expect(identity.sweepChallenges(1)).rejects.toMatchObject({
      code: "invalid_state",
    });
    expect(getters).toBe(0);
  });

  it("retains malformed physical rows without starving later valid rows", async () => {
    const inner = createMemoryStore();
    const rawChallenges = defineCollection<StoredRecord>({
      name: challengesCollection.name,
      key: (record) => ({
        partition: String(record.partition),
        id: String(record.id),
      }),
      codec: {
        encode: (record) => record,
        decode: (record) => record,
      },
    });
    await inner.collection(rawChallenges).put({
      partition: "challenges",
      id: "0".repeat(64),
      malformed: true,
    });
    let now = "2026-07-27T12:00:00.000Z";
    const identity = service(inner, { clock: { now: () => now } });
    await identity.beginPasskeyAuthentication("expired");
    now = "2026-07-27T12:06:00.000Z";

    let cursor: string | undefined;
    let rejected = 0;
    let deleted = 0;
    do {
      const result = await identity.sweepChallenges(1, cursor);
      rejected += result.rejected;
      deleted += result.deleted;
      cursor = result.cursor ?? undefined;
      if (!result.hasMore) {
        break;
      }
    } while (true);

    expect(rejected).toBe(1);
    expect(deleted).toBe(1);
    await expect(
      inner
        .collection(rawChallenges)
        .get({ partition: "challenges", id: "0".repeat(64) }),
    ).resolves.not.toBeNull();
  });

  it("rejects malformed limits and cursors", async () => {
    const identity = service();
    await expect(identity.sweepChallenges(0)).rejects.toMatchObject({
      code: "invalid_input",
    });
    await expect(
      identity.sweepChallenges(1, "not-a-scan-cursor"),
    ).rejects.toThrow();
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
