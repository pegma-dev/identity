import type { Clock, PrincipalId } from "@pegma/spine";
import type { Store } from "@pegma/storage-core";

import { emailHash, principalHash } from "./crypto.js";
import { normalizeEmail } from "./email.js";
import { IdentityError } from "./errors.js";
import {
  emailIndexesCollection,
  usersCollection,
  type EmailIndexRecord,
  type UserRecord,
} from "./records.js";
import {
  addMilliseconds,
  assertBoundedString,
  assertPrincipalId,
  copyDataOnly,
  dataField,
  readDataProperty,
  timestampFromClock,
} from "./validation.js";

export interface User {
  readonly principalId: PrincipalId;
  readonly email: string;
  readonly emailVerified: boolean;
  readonly status: "pending" | "active";
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface VerifiedIdentityClaims {
  readonly issuer: string;
  readonly subject: PrincipalId;
  readonly emailVerified: true;
}

export interface ProvisionVerifiedUserInput {
  readonly principalId: PrincipalId;
  readonly email: string;
}

interface UserServiceOptions {
  readonly store: Store;
  readonly clock: Clock;
  readonly issuer: string;
  readonly newId: () => string;
  readonly repairDelayMs: number;
}

export interface UserService {
  provisionVerifiedUser(input: ProvisionVerifiedUserInput): Promise<User>;
  repairUserByEmail(email: string): Promise<User>;
  findUserByEmail(email: string): Promise<User | null>;
  getUser(principalId: PrincipalId): Promise<User | null>;
  claimsFor(principalId: PrincipalId): Promise<VerifiedIdentityClaims>;
}

function publicUser(record: UserRecord): User {
  return Object.freeze({
    principalId: record.principalId as PrincipalId,
    email: record.email,
    emailVerified: record.emailVerified,
    status: record.status,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
  });
}

function claims(issuer: string, record: UserRecord): VerifiedIdentityClaims {
  if (record.status !== "active" || record.emailVerified !== true) {
    throw new IdentityError(
      "invalid_state",
      "Verified claims require an active verified user.",
    );
  }
  return Object.freeze({
    issuer,
    subject: record.principalId as PrincipalId,
    emailVerified: true as const,
  });
}

function userKey(hash: string) {
  return { partition: `principal-${hash.slice(0, 16)}`, id: hash };
}

function emailKey(hash: string) {
  return { partition: `email-${hash.slice(0, 16)}`, id: hash };
}

export function createUserService(options: UserServiceOptions): UserService {
  const users = options.store.collection(usersCollection);
  const indexes = options.store.collection(emailIndexesCollection);

  async function assertEmailIndexOwner(index: EmailIndexRecord): Promise<void> {
    const principalId = readDataProperty(index, "principalId");
    const storedPrincipalHash = readDataProperty(index, "principalHash");
    if (
      typeof principalId !== "string" ||
      typeof storedPrincipalHash !== "string" ||
      storedPrincipalHash !== (await principalHash(principalId))
    ) {
      throw new IdentityError(
        "storage_corrupt",
        "Email index owner is malformed.",
      );
    }
  }

  async function readUser(
    principalId: string,
    expectedHash?: string,
  ): Promise<UserRecord | null> {
    const hash = expectedHash ?? (await principalHash(principalId));
    const user = await users.get(userKey(hash));
    if (
      user !== null &&
      (user.principalId !== principalId || user.principalHash !== hash)
    ) {
      throw new IdentityError(
        "storage_corrupt",
        "Stored user does not match its lookup key.",
      );
    }
    return user;
  }

  async function prepareUser(index: EmailIndexRecord): Promise<UserRecord> {
    const proposed: UserRecord = {
      ...userKey(index.principalHash),
      principalId: index.principalId,
      principalHash: index.principalHash,
      email: index.email,
      emailHash: index.emailHash,
      status: "pending",
      emailVerified: false,
      createdAt: index.createdAt,
      updatedAt: index.updatedAt,
    };
    const inserted = await users.insertIfAbsent(proposed);
    if (
      inserted.value.principalId !== index.principalId ||
      inserted.value.principalHash !== index.principalHash ||
      inserted.value.emailHash !== index.emailHash ||
      inserted.value.email !== index.email
    ) {
      throw new IdentityError(
        "conflict",
        "PrincipalId is already bound to another user.",
      );
    }
    return inserted.value;
  }

  async function transitionIndex(
    index: EmailIndexRecord,
    from: EmailIndexRecord["state"],
    to: EmailIndexRecord["state"],
    now: string,
  ): Promise<EmailIndexRecord> {
    const result = await indexes.update(
      emailKey(index.emailHash),
      async (current) => {
        if (current === null) {
          return { action: "keep" };
        }
        await assertEmailIndexOwner(current);
        if (
          current.operationId !== index.operationId ||
          current.principalId !== index.principalId ||
          current.emailHash !== index.emailHash
        ) {
          return { action: "keep" };
        }
        if (current.state !== from) {
          return { action: "keep" };
        }
        return {
          action: "write",
          value: { ...current, state: to, updatedAt: now },
        };
      },
      { maxAttempts: 10 },
    );
    if (result.value === null) {
      throw new IdentityError(
        "invalid_state",
        "Email reservation disappeared during repair.",
      );
    }
    await assertEmailIndexOwner(result.value);
    if (
      result.value.operationId !== index.operationId ||
      result.value.principalId !== index.principalId ||
      result.value.principalHash !== index.principalHash ||
      result.value.email !== index.email ||
      result.value.emailHash !== index.emailHash
    ) {
      throw new IdentityError(
        "conflict",
        "Email reservation changed during repair.",
      );
    }
    return result.value;
  }

  async function activateUser(
    index: EmailIndexRecord,
    now: string,
  ): Promise<UserRecord> {
    const result = await users.update(
      userKey(index.principalHash),
      (current) => {
        if (current === null) {
          return { action: "keep" };
        }
        if (
          current.principalId !== index.principalId ||
          current.emailHash !== index.emailHash ||
          current.email !== index.email
        ) {
          return { action: "keep" };
        }
        if (current.status === "active" && current.emailVerified) {
          return { action: "keep" };
        }
        return {
          action: "write",
          value: {
            ...current,
            status: "active",
            emailVerified: true,
            updatedAt: now,
          },
        };
      },
      { maxAttempts: 10 },
    );
    if (
      result.value === null ||
      result.value.status !== "active" ||
      !result.value.emailVerified
    ) {
      throw new IdentityError(
        "conflict",
        "PrincipalId is already bound to another user.",
      );
    }
    return result.value;
  }

  async function repair(index: EmailIndexRecord): Promise<UserRecord> {
    let current = index;
    for (let step = 0; step < 6; step += 1) {
      await assertEmailIndexOwner(current);
      const now = timestampFromClock(options.clock).value;
      switch (current.state) {
        case "reserved": {
          try {
            await prepareUser(current);
          } catch (error) {
            const seen = await indexes.getVersioned(
              emailKey(current.emailHash),
            );
            if (
              error instanceof IdentityError &&
              error.code === "conflict" &&
              seen !== null &&
              seen.value.state === "reserved" &&
              seen.value.operationId === current.operationId
            ) {
              await assertEmailIndexOwner(seen.value);
              await indexes.deleteIfUnchanged(
                emailKey(current.emailHash),
                seen.version,
              );
            }
            throw error;
          }
          current = await transitionIndex(current, "reserved", "prepared", now);
          break;
        }
        case "prepared":
          await prepareUser(current);
          current = await transitionIndex(
            current,
            "prepared",
            "committed",
            now,
          );
          break;
        case "committed": {
          await prepareUser(current);
          const user = await activateUser(current, now);
          current = await transitionIndex(current, "committed", "active", now);
          if (current.state === "active") {
            return user;
          }
          break;
        }
        case "active": {
          await prepareUser(current);
          return activateUser(current, now);
        }
      }
    }
    throw new IdentityError(
      "invalid_state",
      "Email reservation repair did not converge.",
    );
  }

  return {
    async provisionVerifiedUser(input) {
      const safe = copyDataOnly(input);
      const requestedPrincipal = assertPrincipalId(
        dataField(safe, "principalId"),
      );
      const email = normalizeEmail(dataField(safe, "email"));
      const [emailDigest, principalDigest] = await Promise.all([
        emailHash(email),
        principalHash(requestedPrincipal),
      ]);
      const existingUser = await readUser(requestedPrincipal, principalDigest);
      if (existingUser !== null && existingUser.emailHash !== emailDigest) {
        throw new IdentityError(
          "conflict",
          "PrincipalId is already bound to another user.",
        );
      }
      const { value: now, milliseconds } = timestampFromClock(options.clock);
      const operationId = assertBoundedString(
        options.newId(),
        "Generated operation identifier",
        256,
      );
      const reservation: EmailIndexRecord = {
        ...emailKey(emailDigest),
        email,
        emailHash: emailDigest,
        principalId: requestedPrincipal,
        principalHash: principalDigest,
        operationId,
        state: "reserved",
        createdAt: now,
        updatedAt: now,
        repairAfter: addMilliseconds(milliseconds, options.repairDelayMs),
      };
      const inserted = await indexes.insertIfAbsent(reservation);
      if (
        inserted.value.email !== email ||
        inserted.value.emailHash !== emailDigest
      ) {
        throw new IdentityError(
          "storage_corrupt",
          "Email index does not match its lookup key.",
        );
      }
      return publicUser(await repair(inserted.value));
    },

    async repairUserByEmail(input) {
      const email = normalizeEmail(input);
      const digest = await emailHash(email);
      const index = await indexes.get(emailKey(digest));
      if (index === null) {
        throw new IdentityError("not_found", "No email reservation exists.");
      }
      if (index.email !== email || index.emailHash !== digest) {
        throw new IdentityError(
          "storage_corrupt",
          "Email index does not match its lookup key.",
        );
      }
      return publicUser(await repair(index));
    },

    async findUserByEmail(input) {
      const email = normalizeEmail(input);
      const digest = await emailHash(email);
      const index = await indexes.get(emailKey(digest));
      if (index === null) {
        return null;
      }
      if (index.email !== email || index.emailHash !== digest) {
        throw new IdentityError(
          "storage_corrupt",
          "Email index does not match its lookup key.",
        );
      }
      return publicUser(await repair(index));
    },

    async getUser(input) {
      const principalId = assertPrincipalId(input);
      const user = await readUser(principalId);
      return user === null ? null : publicUser(user);
    },

    async claimsFor(input) {
      const principalId = assertPrincipalId(input);
      const user = await readUser(principalId);
      if (user === null) {
        throw new IdentityError("not_found", "User was not found.");
      }
      return claims(options.issuer, user);
    },
  };
}
