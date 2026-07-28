import { IdentityError } from "./errors.js";

const encoder = new TextEncoder();
const EMAIL_CODE_SPACE = 100_000_000;
const UINT32_RANGE = 0x1_0000_0000;
const EMAIL_CODE_REJECTION_LIMIT =
  Math.floor(UINT32_RANGE / EMAIL_CODE_SPACE) * EMAIL_CODE_SPACE;

export interface EmailCodeProtector {
  deriveCode(handleHash: string): Promise<string>;
  verifier(handleHash: string, code: string): Promise<string>;
  matches(
    expectedVerifier: string,
    handleHash: string,
    candidateCode: string,
  ): Promise<boolean>;
}

function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function assertEmailCodeHash(value: string): void {
  if (!/^[0-9a-f]{64}$/u.test(value)) {
    throw new IdentityError("invalid_input", "Email code handle is invalid.");
  }
}

async function importHmacKey(
  secret: Uint8Array<ArrayBuffer>,
): Promise<CryptoKey> {
  try {
    return await crypto.subtle.importKey(
      "raw",
      secret,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
  } catch (cause) {
    throw new IdentityError(
      "invalid_state",
      "Email code protection is unavailable.",
      { cause },
    );
  }
}

async function hmac(key: CryptoKey, material: string): Promise<Uint8Array> {
  try {
    return new Uint8Array(
      await crypto.subtle.sign("HMAC", key, encoder.encode(material)),
    );
  } catch (cause) {
    throw new IdentityError(
      "invalid_state",
      "Email code protection is unavailable.",
      { cause },
    );
  }
}

function constantTimeHexEqual(left: string, right: string): boolean {
  if (left.length !== right.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

/**
 * Creates a deterministic email-code protector from host-owned key material.
 *
 * Determinism lets an asynchronous Mail worker render a code without storing
 * it. Only the separately domain-separated keyed verifier is persisted.
 */
export function createHmacEmailCodeProtector(
  inputSecret: Uint8Array,
): EmailCodeProtector {
  if (
    !(inputSecret instanceof Uint8Array) ||
    Object.getPrototypeOf(inputSecret) !== Uint8Array.prototype ||
    inputSecret.byteLength < 32
  ) {
    throw new IdentityError(
      "invalid_input",
      "Email code secret must contain at least 32 bytes.",
    );
  }
  let secret: Uint8Array<ArrayBuffer>;
  try {
    secret = new Uint8Array(new ArrayBuffer(inputSecret.byteLength));
    secret.set(inputSecret);
  } catch (cause) {
    throw new IdentityError("invalid_input", "Email code secret is invalid.", {
      cause,
    });
  }
  const key = importHmacKey(secret).finally(() => secret.fill(0));

  async function deriveCode(handleHash: string): Promise<string> {
    assertEmailCodeHash(handleHash);
    for (let block = 0; block < 1_000; block += 1) {
      const bytes = await hmac(
        await key,
        `pegma.identity.email-code.value.v1\u0000${handleHash}\u0000${block}`,
      );
      const view = new DataView(
        bytes.buffer,
        bytes.byteOffset,
        bytes.byteLength,
      );
      for (let offset = 0; offset + 4 <= bytes.byteLength; offset += 4) {
        const sample = view.getUint32(offset, false);
        if (sample < EMAIL_CODE_REJECTION_LIMIT) {
          return String(sample % EMAIL_CODE_SPACE).padStart(8, "0");
        }
      }
    }
    throw new IdentityError(
      "invalid_state",
      "Could not derive an unbiased email code.",
    );
  }

  async function verifier(handleHash: string, code: string): Promise<string> {
    assertEmailCodeHash(handleHash);
    if (!/^\d{8}$/u.test(code)) {
      throw new IdentityError("invalid_input", "Email code is invalid.");
    }
    return bytesToHex(
      await hmac(
        await key,
        `pegma.identity.email-code.verifier.v1\u0000${handleHash}\u0000${code}`,
      ),
    );
  }

  return Object.freeze({
    deriveCode,
    verifier,
    async matches(
      expectedVerifier: string,
      handleHash: string,
      candidateCode: string,
    ) {
      if (
        !/^[0-9a-f]{64}$/u.test(expectedVerifier) ||
        !/^\d{8}$/u.test(candidateCode)
      ) {
        return false;
      }
      return constantTimeHexEqual(
        expectedVerifier,
        await verifier(handleHash, candidateCode),
      );
    },
  });
}

export async function sha256Hex(
  domain: string,
  value: string,
): Promise<string> {
  let digest: ArrayBuffer;
  try {
    digest = await crypto.subtle.digest(
      "SHA-256",
      encoder.encode(`${domain}\u0000${value}`),
    );
  } catch (cause) {
    throw new IdentityError(
      "invalid_state",
      "Cryptographic hashing is unavailable.",
      { cause },
    );
  }
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export async function principalHash(principalId: string): Promise<string> {
  return sha256Hex("pegma.identity.principal.v1", principalId);
}

export async function emailHash(email: string): Promise<string> {
  return sha256Hex("pegma.identity.email.v1", email);
}

export async function credentialHash(credentialId: string): Promise<string> {
  return sha256Hex("pegma.identity.credential.v1", credentialId);
}

export async function registrationProofHash(material: string): Promise<string> {
  return sha256Hex("pegma.identity.registration-proof.v1", material);
}

export async function challengeHandleHash(handle: string): Promise<string> {
  return sha256Hex("pegma.identity.challenge-handle.v1", handle);
}

export async function emailCodeHandleHash(handle: string): Promise<string> {
  return sha256Hex("pegma.identity.email-code-handle.v1", handle);
}

export async function challengeValueHash(challenge: string): Promise<string> {
  return sha256Hex("pegma.identity.challenge-value.v1", challenge);
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

export function base64UrlToBytes(value: string): Uint8Array<ArrayBuffer> {
  const padding = "=".repeat((4 - (value.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(value.replaceAll("-", "+").replaceAll("_", "/") + padding);
  } catch (cause) {
    throw new IdentityError(
      "storage_corrupt",
      "Stored credential material is malformed.",
      { cause },
    );
  }
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export async function constantTimeHashMatch(
  expectedHex: string,
  domain: string,
  candidate: string,
): Promise<boolean> {
  const actual = await sha256Hex(domain, candidate);
  if (actual.length !== expectedHex.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < actual.length; index += 1) {
    difference |= actual.charCodeAt(index) ^ expectedHex.charCodeAt(index);
  }
  return difference === 0;
}
