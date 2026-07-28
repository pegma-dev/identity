import type { RateLimiter } from "@pegma/rate-limit";
import type { Clock, PrincipalId } from "@pegma/spine";
import type { Store } from "@pegma/storage-core";
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
  passkeysCollection,
  registrationProofsCollection,
  TRANSPORTS,
  type CredentialIndexRecord,
  type PasskeyRecord,
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
  index: CredentialIndexRecord,
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
    current.credentialHash === proposed.credentialHash &&
    current.credentialId === proposed.credentialId &&
    current.registrationId === proposed.registrationId &&
    current.registrationProofHash === proposed.registrationProofHash &&
    current.principalId === proposed.principalId &&
    current.principalHash === proposed.principalHash &&
    current.publicKey === proposed.publicKey &&
    current.counter === proposed.counter &&
    current.label === proposed.label &&
    current.createdAt === proposed.createdAt &&
    current.updatedAt === proposed.updatedAt &&
    current.transports.length === proposed.transports.length &&
    current.transports.every(
      (transport, index) => transport === proposed.transports[index],
    )
  );
}

type RegistrationMaterial = Omit<
  CredentialIndexRecord,
  "partition" | "id" | "registrationProofHash" | "state"
>;

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
    passkey.credentialHash === index.credentialHash &&
    passkey.credentialId === index.credentialId &&
    passkey.registrationId === index.registrationId &&
    passkey.principalId === index.principalId &&
    passkey.principalHash === index.principalHash &&
    passkey.publicKey === index.publicKey &&
    passkey.counter === index.counter &&
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
  ): Promise<string> {
    const proofHash = await registrationProofHash(
      registrationProofMaterial(material),
    );
    const proposed: RegistrationProofRecord = {
      ...registrationProofKey(proofHash),
      ...material,
      registrationProofHash: proofHash,
    };
    const inserted = await registrationProofs.insertIfAbsent(proposed);
    if (
      inserted.value.registrationProofHash !== proofHash ||
      !sameRegistrationProof(inserted.value, {
        ...credentialKey(material.credentialHash),
        ...material,
        registrationProofHash: proofHash,
        state: "reserved",
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
      const existing = await passkeys.get(
        passkeyKey(index.principalHash, index.credentialHash),
      );
      if (existing !== null && existing.state !== "revoked") {
        await passkeys.update(
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
                    updatedAt: index.updatedAt,
                  },
                },
          { maxAttempts: 10 },
        );
      }
      return null;
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
    await activateCredential(index);
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
    const proofHash = await persistRegistrationProof(material);
    const proposed: CredentialIndexRecord = {
      ...key,
      ...material,
      registrationProofHash: proofHash,
      state: "reserved",
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
        await options.challengeService.consumeClaim(claim);
      } catch (cause) {
        throw cause instanceof IdentityError
          ? cause
          : new IdentityError(
              "invalid_state",
              "Credential registration could not be persisted.",
              { cause },
            );
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
      const index = await credentials.get(credentialKey(credentialDigest));
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
            value: { ...current, counter: newCounter, updatedAt: now },
          };
        },
        { maxAttempts: 10 },
      );
      if (!advanced || !updated.written || updated.value === null) {
        return verificationFailed(claim);
      }
      await passkeys.update(
        passkeyKey(index.principalHash, credentialDigest),
        (current) =>
          current === null ||
          current.state !== "active" ||
          current.principalId !== index.principalId ||
          current.principalHash !== index.principalHash ||
          current.registrationId !== index.registrationId ||
          !sameCredentialBinding(current, index) ||
          current.counter > newCounter
            ? { action: "keep" }
            : {
                action: "write",
                value: {
                  ...current,
                  counter: newCounter,
                  updatedAt: now,
                  lastUsedAt: now,
                },
              },
        { maxAttempts: 10 },
      );
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
      const now = timestampFromClock(options.clock).value;
      let revoked = false;
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
            current.state !== "active"
          ) {
            return { action: "keep" };
          }
          revoked = true;
          return {
            action: "write",
            value: { ...current, state: "revoked", updatedAt: now },
          };
        },
        { maxAttempts: 10 },
      );
      if (!revoked || result.value === null) {
        return false;
      }
      await repair(result.value);
      return true;
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
  };
}
