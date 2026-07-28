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
  activeUserForEmail(email: string): Promise<User | null>;
  changeVerifiedEmail(input: {
    readonly principalId: PrincipalId;
    readonly oldEmailHash: string;
    readonly newEmail: string;
    readonly operationHash: string;
  }): Promise<User>;
  finalizeVerifiedEmailChange(input: {
    readonly principalId: PrincipalId;
    readonly newEmail: string;
    readonly operationHash: string;
  }): Promise<User>;
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
      emailChangeOperationHash: null,
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
        case "change_reserved":
        case "retiring":
          throw new IdentityError(
            "invalid_state",
            "Email change requires its owning repair operation.",
          );
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
        changeOperationHash: null,
        replacementEmailHash: null,
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
        // Enumeration-sensitive callers still perform one deterministic User
        // read without placing contact data in a backend key.
        const dummyHash = await principalHash(`email-decoy:${digest}`);
        await users.get(userKey(dummyHash));
        return null;
      }
      if (index.email !== email || index.emailHash !== digest) {
        throw new IdentityError(
          "storage_corrupt",
          "Email index does not match its lookup key.",
        );
      }
      await assertEmailIndexOwner(index);
      if (index.state === "change_reserved") {
        return null;
      }
      if (index.state === "retiring") {
        const user = await readUser(index.principalId, index.principalHash);
        if (user === null || user.status !== "active" || !user.emailVerified) {
          throw new IdentityError(
            "storage_corrupt",
            "Retiring email index has no owner.",
          );
        }
        return user.emailHash === index.emailHash ? publicUser(user) : null;
      }
      const user =
        index.state === "active"
          ? await readUser(index.principalId, index.principalHash)
          : await repair(index);
      if (
        user === null ||
        user.email !== index.email ||
        user.emailHash !== index.emailHash ||
        user.status !== "active" ||
        !user.emailVerified
      ) {
        throw new IdentityError(
          "storage_corrupt",
          "Active email index does not match its user.",
        );
      }
      return publicUser(user);
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

    async activeUserForEmail(input) {
      const email = normalizeEmail(input);
      const digest = await emailHash(email);
      const index = await indexes.get(emailKey(digest));
      if (index === null) {
        const dummyHash = await principalHash(`email-decoy:${digest}`);
        await users.get(userKey(dummyHash));
        return null;
      }
      if (index.email !== email || index.emailHash !== digest) {
        throw new IdentityError(
          "storage_corrupt",
          "Email index does not match its lookup key.",
        );
      }
      await assertEmailIndexOwner(index);
      if (index.state === "change_reserved") {
        await readUser(index.principalId, index.principalHash);
        return null;
      }
      if (index.state === "retiring") {
        const user = await readUser(index.principalId, index.principalHash);
        if (user === null || user.status !== "active" || !user.emailVerified) {
          throw new IdentityError(
            "storage_corrupt",
            "Retiring email index has no active owner.",
          );
        }
        return user.emailHash === index.emailHash ? publicUser(user) : null;
      }
      const user =
        index.state === "active"
          ? await readUser(index.principalId, index.principalHash)
          : await repair(index);
      if (
        user === null ||
        user.email !== index.email ||
        user.emailHash !== index.emailHash
      ) {
        throw new IdentityError(
          "storage_corrupt",
          "Active email index does not match its user.",
        );
      }
      return user.status === "active" && user.emailVerified
        ? publicUser(user)
        : null;
    },

    async changeVerifiedEmail(input) {
      const safe = copyDataOnly(input);
      const requestedPrincipal = assertPrincipalId(
        dataField(safe, "principalId"),
      );
      const expectedOldHash = assertBoundedString(
        dataField(safe, "oldEmailHash"),
        "Old email hash",
        64,
      );
      const operationHash = assertBoundedString(
        dataField(safe, "operationHash"),
        "Email change operation",
        64,
      );
      if (
        !/^[0-9a-f]{64}$/u.test(expectedOldHash) ||
        !/^[0-9a-f]{64}$/u.test(operationHash)
      ) {
        throw new IdentityError(
          "invalid_input",
          "Email change input is invalid.",
        );
      }
      const newEmail = normalizeEmail(dataField(safe, "newEmail"));
      const [ownerHash, newEmailHash] = await Promise.all([
        principalHash(requestedPrincipal),
        emailHash(newEmail),
      ]);
      const userKeyValue = userKey(ownerHash);
      async function releaseOperationReservation(): Promise<boolean> {
        const latest = await indexes.getVersioned(emailKey(newEmailHash));
        if (latest === null) {
          return true;
        }
        if (
          latest.value.state !== "change_reserved" ||
          latest.value.principalId !== requestedPrincipal ||
          latest.value.principalHash !== ownerHash ||
          latest.value.email !== newEmail ||
          latest.value.emailHash !== newEmailHash ||
          latest.value.changeOperationHash !== operationHash
        ) {
          return true;
        }
        return indexes.deleteIfUnchanged(
          emailKey(newEmailHash),
          latest.version,
        );
      }

      async function rejectBeforeClaim(): Promise<never> {
        if (!(await releaseOperationReservation())) {
          throw new IdentityError(
            "invalid_state",
            "Email change reservation cleanup did not converge.",
          );
        }
        throw new IdentityError(
          "verification_failed",
          "Email verification failed.",
        );
      }

      let currentUser = await users.get(userKeyValue);
      if (currentUser === null) {
        return rejectBeforeClaim();
      }
      if (
        currentUser.principalId !== requestedPrincipal ||
        currentUser.principalHash !== ownerHash ||
        currentUser.status !== "active" ||
        !currentUser.emailVerified
      ) {
        await rejectBeforeClaim();
      }
      if (
        currentUser.emailHash !== expectedOldHash &&
        currentUser.emailHash !== newEmailHash
      ) {
        await rejectBeforeClaim();
      }
      if (
        currentUser.emailHash === newEmailHash &&
        currentUser.emailChangeOperationHash !== operationHash
      ) {
        await rejectBeforeClaim();
      }
      const alreadySwitched = currentUser.emailHash === newEmailHash;
      const oldEmail = currentUser.email;
      const { value: now, milliseconds } = timestampFromClock(options.clock);
      const newReservation: EmailIndexRecord = {
        ...emailKey(newEmailHash),
        email: newEmail,
        emailHash: newEmailHash,
        principalId: requestedPrincipal,
        principalHash: ownerHash,
        operationId: operationHash,
        state: "change_reserved",
        createdAt: now,
        updatedAt: now,
        repairAfter: addMilliseconds(milliseconds, options.repairDelayMs),
        changeOperationHash: operationHash,
        replacementEmailHash: null,
      };
      const reserved = await indexes.insertIfAbsent(newReservation);
      const reservationMismatch =
        reserved.value.principalId !== requestedPrincipal ||
        reserved.value.principalHash !== ownerHash ||
        reserved.value.email !== newEmail ||
        reserved.value.emailHash !== newEmailHash ||
        (reserved.value.state === "change_reserved"
          ? reserved.value.changeOperationHash !== operationHash
          : !alreadySwitched || reserved.value.state !== "active");

      if (reservationMismatch) {
        await rejectBeforeClaim();
      }

      if (!alreadySwitched && expectedOldHash !== newEmailHash) {
        const oldIndex = await indexes.get(emailKey(expectedOldHash));
        const resumableState =
          oldIndex?.state === "active"
            ? oldIndex.changeOperationHash === null &&
              oldIndex.replacementEmailHash === null
            : oldIndex?.state === "retiring" &&
              oldIndex.changeOperationHash === operationHash &&
              oldIndex.replacementEmailHash === newEmailHash;
        if (
          oldIndex === null ||
          oldIndex.principalId !== requestedPrincipal ||
          oldIndex.principalHash !== ownerHash ||
          oldIndex.email !== oldEmail ||
          oldIndex.emailHash !== expectedOldHash ||
          !resumableState
        ) {
          await rejectBeforeClaim();
        }
      }

      if (currentUser.emailHash === expectedOldHash) {
        const claimed = await users.update(
          userKeyValue,
          (current) => {
            if (
              current === null ||
              current.principalId !== requestedPrincipal ||
              current.principalHash !== ownerHash ||
              current.status !== "active" ||
              !current.emailVerified ||
              current.emailHash !== expectedOldHash ||
              (current.emailChangeOperationHash !== null &&
                current.emailChangeOperationHash !== operationHash)
            ) {
              return { action: "keep" };
            }
            return {
              action: "write",
              value: {
                ...current,
                emailChangeOperationHash: operationHash,
                updatedAt: now,
              },
            };
          },
          { maxAttempts: 10 },
        );
        if (
          claimed.value === null ||
          claimed.value.emailChangeOperationHash !== operationHash
        ) {
          await rejectBeforeClaim();
        }
        currentUser = claimed.value;
      }

      if (expectedOldHash !== newEmailHash) {
        const oldIndex = await indexes.update(
          emailKey(expectedOldHash),
          (current) => {
            if (
              current === null ||
              current.principalId !== requestedPrincipal ||
              current.principalHash !== ownerHash ||
              current.email !== oldEmail ||
              current.emailHash !== expectedOldHash
            ) {
              return { action: "keep" };
            }
            if (
              current.state === "retiring" &&
              current.changeOperationHash === operationHash &&
              current.replacementEmailHash === newEmailHash
            ) {
              return { action: "keep" };
            }
            if (current.state !== "active") {
              return { action: "keep" };
            }
            return {
              action: "write",
              value: {
                ...current,
                state: "retiring",
                changeOperationHash: operationHash,
                replacementEmailHash: newEmailHash,
                updatedAt: now,
              },
            };
          },
          { maxAttempts: 10 },
        );
        if (
          oldIndex.value !== null &&
          (oldIndex.value.state !== "retiring" ||
            oldIndex.value.changeOperationHash !== operationHash ||
            oldIndex.value.replacementEmailHash !== newEmailHash)
        ) {
          throw new IdentityError(
            "invalid_state",
            "Email change repair did not retire the old lookup.",
          );
        }
        if (oldIndex.value === null && !alreadySwitched) {
          throw new IdentityError(
            "invalid_state",
            "Email change repair lost the old lookup.",
          );
        }
      }

      const switched = await users.update(
        userKeyValue,
        (current) => {
          if (
            current === null ||
            current.principalId !== requestedPrincipal ||
            current.principalHash !== ownerHash ||
            current.status !== "active" ||
            !current.emailVerified ||
            (current.emailChangeOperationHash !== operationHash &&
              current.emailHash !== newEmailHash)
          ) {
            return { action: "keep" };
          }
          if (current.emailHash === newEmailHash) {
            return { action: "keep" };
          }
          if (current.emailHash !== expectedOldHash) {
            return { action: "keep" };
          }
          return {
            action: "write",
            value: {
              ...current,
              email: newEmail,
              emailHash: newEmailHash,
              updatedAt: now,
            },
          };
        },
        { maxAttempts: 10 },
      );
      if (
        switched.value === null ||
        switched.value.email !== newEmail ||
        switched.value.emailHash !== newEmailHash
      ) {
        throw new IdentityError(
          "invalid_state",
          "Email change repair did not update the user.",
        );
      }

      const activated = await indexes.update(
        emailKey(newEmailHash),
        (current) => {
          if (
            current === null ||
            current.principalId !== requestedPrincipal ||
            current.principalHash !== ownerHash ||
            current.email !== newEmail ||
            current.emailHash !== newEmailHash
          ) {
            return { action: "keep" };
          }
          if (current.state === "active") {
            return { action: "keep" };
          }
          if (
            current.state !== "change_reserved" ||
            current.changeOperationHash !== operationHash
          ) {
            return { action: "keep" };
          }
          return {
            action: "write",
            value: {
              ...current,
              state: "active",
              changeOperationHash: null,
              replacementEmailHash: null,
              updatedAt: now,
            },
          };
        },
        { maxAttempts: 10 },
      );
      if (activated.value?.state !== "active") {
        throw new IdentityError(
          "invalid_state",
          "Email change repair did not activate the new lookup.",
        );
      }

      if (expectedOldHash !== newEmailHash) {
        const old = await indexes.getVersioned(emailKey(expectedOldHash));
        if (
          old !== null &&
          old.value.state === "retiring" &&
          old.value.changeOperationHash === operationHash &&
          old.value.replacementEmailHash === newEmailHash
        ) {
          await indexes.deleteIfUnchanged(
            emailKey(expectedOldHash),
            old.version,
          );
        }
      }

      const retained = await users.get(userKeyValue);
      if (
        retained === null ||
        retained.emailHash !== newEmailHash ||
        retained.emailChangeOperationHash !== operationHash
      ) {
        throw new IdentityError(
          "invalid_state",
          "Email change ownership was lost before durable notification.",
        );
      }
      return publicUser(retained);
    },

    async finalizeVerifiedEmailChange(input) {
      const safe = copyDataOnly(input);
      const requestedPrincipal = assertPrincipalId(
        dataField(safe, "principalId"),
      );
      const newEmail = normalizeEmail(dataField(safe, "newEmail"));
      const operationHash = assertBoundedString(
        dataField(safe, "operationHash"),
        "Email change operation",
        64,
      );
      if (!/^[0-9a-f]{64}$/u.test(operationHash)) {
        throw new IdentityError(
          "invalid_input",
          "Email change input is invalid.",
        );
      }
      const [ownerHash, newEmailHash] = await Promise.all([
        principalHash(requestedPrincipal),
        emailHash(newEmail),
      ]);
      const now = timestampFromClock(options.clock).value;
      const finalized = await users.update(
        userKey(ownerHash),
        (current) => {
          if (
            current === null ||
            current.principalId !== requestedPrincipal ||
            current.principalHash !== ownerHash ||
            current.email !== newEmail ||
            current.emailHash !== newEmailHash ||
            current.status !== "active" ||
            !current.emailVerified ||
            (current.emailChangeOperationHash !== operationHash &&
              current.emailChangeOperationHash !== null)
          ) {
            return { action: "keep" };
          }
          return current.emailChangeOperationHash === null
            ? { action: "keep" }
            : {
                action: "write",
                value: {
                  ...current,
                  emailChangeOperationHash: null,
                  updatedAt: now,
                },
              };
        },
        { maxAttempts: 10 },
      );
      if (
        finalized.value === null ||
        finalized.value.emailHash !== newEmailHash ||
        finalized.value.emailChangeOperationHash !== null
      ) {
        throw new IdentityError(
          "invalid_state",
          "Email change finalization did not converge.",
        );
      }
      return publicUser(finalized.value);
    },
  };
}
