import { fixedClock } from "@pegma/spine";
import { createMemoryStore } from "@pegma/storage-core";
import { describe, expect, it } from "vitest";

import { createIdentity } from "./index.js";

const allow = {
  async allow() {
    return { allowed: true as const };
  },
};

function identity() {
  return createIdentity({
    store: createMemoryStore(),
    issuer: "https://issuer.example",
    rpName: "Example",
    rpID: "example.test",
    origins: ["https://example.test"],
    registrationLimiter: allow,
    authenticationLimiter: allow,
    clock: fixedClock("2026-07-27T12:00:00.000Z"),
  });
}

describe("the pinned WebAuthn server integration", () => {
  it("generates real discoverable registration options with required UV", async () => {
    const service = identity();
    await service.provisionVerifiedUser({
      principalId: "principal-real-options",
      email: "person@example.test",
    });

    const started = await service.beginPasskeyRegistration(
      "principal-real-options",
      "request",
    );
    expect(started.options.challenge).toMatch(/^[A-Za-z0-9_-]+$/u);
    expect(started.options.authenticatorSelection).toMatchObject({
      residentKey: "required",
      requireResidentKey: true,
      userVerification: "required",
    });
    expect(started.options.rp.id).toBe("example.test");
  });

  it("generates real discoverable authentication options with required UV", async () => {
    const started = await identity().beginPasskeyAuthentication("request");
    expect(started.options.challenge).toMatch(/^[A-Za-z0-9_-]+$/u);
    expect(started.options.allowCredentials).toBeUndefined();
    expect(started.options.userVerification).toBe("required");
    expect(started.options.rpId).toBe("example.test");
  });
});
