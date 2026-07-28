import { IdentityError } from "./errors.js";

const encoder = new TextEncoder();

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

export async function challengeHandleHash(handle: string): Promise<string> {
  return sha256Hex("pegma.identity.challenge-handle.v1", handle);
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
