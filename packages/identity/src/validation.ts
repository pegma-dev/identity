import type { IsoTimestamp, PrincipalId } from "@pegma/spine";
import type { StoredRecord } from "@pegma/storage-core";

import { IdentityError, type IdentityErrorCode } from "./errors.js";

const CONTROL = /[\u0000-\u001F\u007F-\u009F]/u;
const HASH = /^[0-9a-f]{64}$/u;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const MAX_STRUCTURED_NODES = 2_000;
const MAX_STRUCTURED_DEPTH = 16;

export function assertBoundedString(
  value: unknown,
  label: string,
  maximum: number,
  options: {
    readonly allowControl?: boolean;
    readonly allowBlank?: boolean;
  } = {},
): string {
  if (
    typeof value !== "string" ||
    value.length > maximum ||
    (!options.allowBlank && value.trim().length === 0) ||
    (!options.allowControl && CONTROL.test(value)) ||
    !isWellFormedUnicode(value)
  ) {
    throw new IdentityError("invalid_input", `${label} is invalid.`);
  }
  return value;
}

export function assertPrincipalId(value: unknown): PrincipalId {
  return assertBoundedString(value, "PrincipalId", 512) as PrincipalId;
}

export function assertCanonicalTimestamp(
  value: unknown,
  label = "Timestamp",
): IsoTimestamp {
  if (typeof value !== "string") {
    throw new IdentityError("storage_corrupt", `${label} is malformed.`);
  }
  const milliseconds = Date.parse(value);
  if (
    !Number.isFinite(milliseconds) ||
    new Date(milliseconds).toISOString() !== value
  ) {
    throw new IdentityError("storage_corrupt", `${label} is malformed.`);
  }
  return value;
}

export function timestampFromClock(clock: { now(): IsoTimestamp }): {
  readonly value: IsoTimestamp;
  readonly milliseconds: number;
} {
  let value: unknown;
  try {
    value = clock.now();
  } catch (cause) {
    throw new IdentityError("invalid_state", "The clock is unavailable.", {
      cause,
    });
  }
  const timestamp = assertCanonicalTimestamp(value, "Clock timestamp");
  return { value: timestamp, milliseconds: Date.parse(timestamp) };
}

export function addMilliseconds(
  timestamp: number,
  duration: number,
): IsoTimestamp {
  return new Date(timestamp + duration).toISOString();
}

export function readDataProperty(record: object, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, name);
  if (descriptor === undefined || !("value" in descriptor)) {
    throw new IdentityError(
      "storage_corrupt",
      `Stored property ${name} is missing or unsafe.`,
    );
  }
  return descriptor.value;
}

export function storedString(
  record: StoredRecord,
  name: string,
  maximum = 4_096,
): string {
  const value = readDataProperty(record, name);
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximum ||
    CONTROL.test(value) ||
    !isWellFormedUnicode(value)
  ) {
    throw new IdentityError(
      "storage_corrupt",
      `Stored property ${name} is malformed.`,
    );
  }
  return value;
}

export function storedNullableString(
  record: StoredRecord,
  name: string,
  maximum = 4_096,
): string | null {
  const descriptor = Object.getOwnPropertyDescriptor(record, name);
  if (descriptor === undefined) {
    // Azure represents null by omitting the property. Whole-record replacement
    // makes absence unambiguous for nullable fields.
    return null;
  }
  if (!("value" in descriptor)) {
    throw new IdentityError(
      "storage_corrupt",
      `Stored property ${name} is missing or unsafe.`,
    );
  }
  const value = descriptor.value;
  if (value === null) {
    return null;
  }
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximum ||
    CONTROL.test(value) ||
    !isWellFormedUnicode(value)
  ) {
    throw new IdentityError(
      "storage_corrupt",
      `Stored property ${name} is malformed.`,
    );
  }
  return value;
}

export function storedBoolean(record: StoredRecord, name: string): boolean {
  const value = readDataProperty(record, name);
  if (typeof value !== "boolean") {
    throw new IdentityError(
      "storage_corrupt",
      `Stored property ${name} is malformed.`,
    );
  }
  return value;
}

export function storedSafeInteger(
  record: StoredRecord,
  name: string,
  minimum = 0,
): number {
  const value = readDataProperty(record, name);
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < minimum
  ) {
    throw new IdentityError(
      "storage_corrupt",
      `Stored property ${name} is malformed.`,
    );
  }
  return value;
}

export function assertHash(value: string, label: string): string {
  if (!HASH.test(value)) {
    throw new IdentityError("storage_corrupt", `${label} is malformed.`);
  }
  return value;
}

export function assertBase64Url(
  value: unknown,
  label: string,
  maximum = 4_096,
  code: IdentityErrorCode = "storage_corrupt",
): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximum ||
    !BASE64URL.test(value)
  ) {
    throw new IdentityError(code, `${label} is malformed.`);
  }
  return value;
}

export function parseStringArray(
  value: string,
  label: string,
  allowed: ReadonlySet<string>,
): string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch (cause) {
    throw new IdentityError("storage_corrupt", `${label} is malformed.`, {
      cause,
    });
  }
  if (
    !Array.isArray(parsed) ||
    parsed.length > 16 ||
    !parsed.every((item) => typeof item === "string" && allowed.has(item))
  ) {
    throw new IdentityError("storage_corrupt", `${label} is malformed.`);
  }
  return [...new Set(parsed)];
}

/**
 * Copies JSON-shaped input without evaluating accessors. Proxies and exotic
 * prototypes are rejected; callers should treat any rejection uniformly.
 */
export function copyDataOnly(value: unknown): unknown {
  let nodes = 0;
  const seen = new Set<object>();

  function copy(current: unknown, depth: number): unknown {
    nodes += 1;
    if (nodes > MAX_STRUCTURED_NODES || depth > MAX_STRUCTURED_DEPTH) {
      throw new IdentityError(
        "invalid_input",
        "Structured input is too large.",
      );
    }
    if (
      current === null ||
      typeof current === "string" ||
      typeof current === "boolean"
    ) {
      return current;
    }
    if (typeof current === "number") {
      if (!Number.isFinite(current)) {
        throw new IdentityError(
          "invalid_input",
          "Structured input is invalid.",
        );
      }
      return current;
    }
    if (typeof current !== "object" || seen.has(current)) {
      throw new IdentityError("invalid_input", "Structured input is invalid.");
    }
    const prototype = Object.getPrototypeOf(current);
    if (
      prototype !== Object.prototype &&
      prototype !== null &&
      prototype !== Array.prototype
    ) {
      throw new IdentityError("invalid_input", "Structured input is invalid.");
    }
    seen.add(current);
    try {
      const descriptors = Object.getOwnPropertyDescriptors(current);
      if (Reflect.ownKeys(descriptors).some((key) => typeof key === "symbol")) {
        throw new IdentityError(
          "invalid_input",
          "Structured input is invalid.",
        );
      }
      if (Array.isArray(current)) {
        const length = current.length;
        if (length > 512) {
          throw new IdentityError(
            "invalid_input",
            "Structured input is too large.",
          );
        }
        const output: unknown[] = [];
        for (let index = 0; index < length; index += 1) {
          const descriptor = descriptors[String(index)];
          if (descriptor === undefined || !("value" in descriptor)) {
            throw new IdentityError(
              "invalid_input",
              "Structured input is invalid.",
            );
          }
          output.push(copy(descriptor.value, depth + 1));
        }
        const keys = Object.keys(descriptors).filter((key) => key !== "length");
        if (keys.length !== length) {
          throw new IdentityError(
            "invalid_input",
            "Structured input is invalid.",
          );
        }
        return output;
      }

      const output: Record<string, unknown> = Object.create(null);
      const keys = Object.keys(descriptors);
      if (keys.length > 128) {
        throw new IdentityError(
          "invalid_input",
          "Structured input is too large.",
        );
      }
      for (const key of keys) {
        const descriptor = descriptors[key];
        if (
          descriptor === undefined ||
          !("value" in descriptor) ||
          !descriptor.enumerable
        ) {
          throw new IdentityError(
            "invalid_input",
            "Structured input is invalid.",
          );
        }
        output[key] = copy(descriptor.value, depth + 1);
      }
      return output;
    } finally {
      seen.delete(current);
    }
  }

  return copy(value, 0);
}

export function dataField(value: unknown, field: string): unknown {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new IdentityError("invalid_input", "Structured input is invalid.");
  }
  const descriptor = Object.getOwnPropertyDescriptor(value, field);
  if (descriptor === undefined || !("value" in descriptor)) {
    throw new IdentityError("invalid_input", "Structured input is invalid.");
  }
  return descriptor.value;
}

function isWellFormedUnicode(value: string): boolean {
  return typeof value.isWellFormed === "function"
    ? value.isWellFormed()
    : !/[\uD800-\uDFFF]/u.test(value);
}
