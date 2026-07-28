# @pegma/identity

Passkeys-first, passwordless first-party identity for Pegma hosts.

> [!IMPORTANT]
> The audited `0.0.0` package was published only to reserve the npm name.
> Version `0.1.0` is the first advertised stable release of the implemented
> user/email-index, durable email-code, and WebAuthn foundations.

## What it owns

- user records keyed authoritatively by `PrincipalId`;
- a structurally unique canonical email lookup with crash repair;
- discoverable WebAuthn credentials with required user verification;
- hashed, stored, short-lived, attempt-bounded WebAuthn challenges;
- multiple passkeys, revocation, and strict nonzero counter progression; and
- exact frozen `{ issuer, subject, emailVerified: true }` claims.

Email is contact and lookup data, never the identity key. `normalizeEmail` is
the only normalization path. It applies an exact-pinned NFKC/case-fold
pipeline through `unorm@1.6.0` and `unicode-case-folding@1.1.1`, then converts
the domain with exact-pinned `tr46@6.0.0`. Inputs outside the deliberately
fixed Latin, combining-mark, Greek, Cyrillic, Greek Extended, fullwidth-ASCII,
and ASCII repertoire fail closed, preventing runtime Unicode-table drift. The
lookup key is a domain-separated digest, so backend key metacharacters and raw
contact data never become storage keys.

This package does not store sessions, resolve roles or permissions, serve
OIDC/OAuth2, connect social providers, or implement passwords.

## Construction

```ts
import { createHmacEmailCodeProtector, createIdentity } from "@pegma/identity";
import { createDurableLimiter } from "@pegma/rate-limit";
import { createMemoryStore } from "@pegma/storage-core";

const store = createMemoryStore();
const registrationLimiter = createDurableLimiter(
  { name: "identity-passkey-registration", limit: 10, windowMs: 60_000 },
  store,
);
const authenticationLimiter = createDurableLimiter(
  { name: "identity-passkey-authentication", limit: 20, windowMs: 60_000 },
  store,
);
const emailCodeRequestLimiter = createDurableLimiter(
  { name: "identity-email-requests", limit: 5, windowMs: 60_000 },
  store,
);
const emailCodeVerificationLimiter = createDurableLimiter(
  { name: "identity-email-verification", limit: 10, windowMs: 60_000 },
  store,
);
const configuredSecret = process.env.PEGMA_IDENTITY_EMAIL_CODE_SECRET_BASE64;
if (configuredSecret === undefined) {
  throw new Error("Identity email-code secret is not configured.");
}
const emailCodeSecret = Uint8Array.from(atob(configuredSecret), (character) =>
  character.charCodeAt(0),
);

const identity = createIdentity({
  store,
  issuer: "https://accounts.example.com",
  rpName: "Example",
  rpID: "example.com",
  origins: ["https://example.com"],
  registrationLimiter,
  authenticationLimiter,
  emailCodeProtector: createHmacEmailCodeProtector(emailCodeSecret),
  emailCodeRequestLimiter,
  emailCodeVerificationLimiter,
});
```

Use a durable limiter in production. The caller-provided `rateLimitKey`
should identify an abuse scope such as a source address; it is not an email or
credential secret.

## Email codes and durable mail

Account creation, email sign-in fallback, recovery, and authenticated email
change use the same eight-digit-code mechanism:

```ts
const started = await identity.beginAccountCreation(
  "person@example.com",
  requestAbuseKey,
);

const claims = await identity.finishAccountCreation({
  codeHandle: started.codeHandle,
  code: browserCode,
  rateLimitKey: requestAbuseKey,
});
```

`beginEmailSignIn`/`finishEmailSignIn`, `beginRecovery`/`finishRecovery`, and
`beginEmailChange`/`finishEmailChange` have the same two-call shape. Creation,
fallback, and recovery do not disclose whether an address exists. Unknown
fallback/recovery requests commit durable suppression records with the same
request-path transaction shape; they can never become valid later.

`emailCodeSecret` must contain at least 32 random bytes loaded from stable,
host-managed secret storage on every process restart; never generate it during
process startup. Pass a plain `Uint8Array`. Node callers that decode with
`Buffer.from(...)` must copy it first with `Uint8Array.from(decodedBuffer)`.
The protector
deterministically derives the code for asynchronous rendering and a separately
domain-separated keyed verifier. Only the verifier and hashed handle are
stored. Live key rotation is deliberately not represented in v1. To rotate,
stop new begin operations, drain or explicitly invalidate every email
operation, settle and sweep every nonterminal Mail job that may still need to
render a code, and only then replace the secret. An emergency compromise
response invalidates all pending operations before replacing the key. Rotating
sooner can render a different, unusable code for an already committed job.

Code state and delivery intent commit atomically in Identity's own operation
collection. Delivery is asynchronous through `@pegma/mail`:

```ts
const worker = identity.createMailWorker({
  workerId: "identity-mail-1",
  provider, // must honor the supplied idempotency key
  reconciliation, // resolves accepted sends whose callback did not arrive
  renderer: {
    async render(content) {
      return renderIdentityMail(content);
    },
  },
});

await worker.runSendPage({ limit: 100 });
await worker.runReconciliationPage({ limit: 100 });
```

Authenticate and deduplicate provider callbacks before passing them to
`applyAuthenticatedMailCallback`. Schedule `sweepEmailOperations`,
`sweepMail`, both Mail worker cursor cycles, `sweepChallenges`, and the two
durable limiter sweeps independently. Persist every non-null opaque cursor.
Dead-letter and terminal-unknown mail stays operator-visible until explicitly
acknowledged. Provider, renderer, and reconciliation calls must enforce finite
timeouts shorter than the Mail lease.

The mailbox is the recovery security floor. Successful claims belong in
`@pegma/sessions`; Identity itself stores no sessions.

Challenge retention uses storage-core's authoritative bounded scan directly;
there is no host-maintained secondary index. This requires
`@pegma/storage-core@0.4.0` or a conforming adapter at that contract version.

## Verified provisioning

Phase 1 exposes an explicitly privileged provisioning operation for imports,
administrative bootstrap, and tests where the host already possesses trusted
email-verification evidence:

```ts
const user = await identity.provisionVerifiedUser({
  principalId: "01K...",
  email: "Person@example.com",
});

const claims = await identity.claimsFor(user.principalId);
```

Do not expose `provisionVerifiedUser` directly as public signup. Normal
account creation verifies an email code through `beginAccountCreation` and
`finishAccountCreation`.
The reserve/prepare/commit/activate protocol is durable across crashes;
`repairUserByEmail` completes an interrupted operation. Concurrent equivalent
emails converge on the one principal that won the structural reservation.

## Passkeys

Authenticated enrollment is a two-call ceremony:

```ts
const start = await identity.beginPasskeyRegistration(
  user.principalId,
  requestAbuseKey,
);
// Send start.options to the browser and retain start.challengeHandle.

const passkey = await identity.finishPasskeyRegistration({
  principalId: user.principalId,
  challengeHandle: start.challengeHandle,
  label: "Work laptop",
  response: browserRegistrationResponse,
});
```

Authentication is identifier-first through a discoverable credential, not
email-first:

```ts
const start = await identity.beginPasskeyAuthentication(requestAbuseKey);
// Send start.options to the browser.

const claims = await identity.finishPasskeyAuthentication({
  challengeHandle: start.challengeHandle,
  response: browserAuthenticationResponse,
});
// Hand claims to @pegma/sessions; Identity stores no session.
```

The host must authenticate passkey list/add/remove endpoints for the named
principal. Removing the last passkey is allowed because the durable
email-code recovery floor is available.

Run `sweepChallenges(limit, cursor)` periodically. Each call scans and
inspects at most `limit` physical challenge rows, retains malformed rows for
investigation, and deletes expired or terminal rows by their adapter-issued
physical key and version:

```ts
let cursor: string | undefined;
do {
  const result = await identity.sweepChallenges(100, cursor);
  cursor = result.cursor ?? undefined;
  if (!result.hasMore) break;
} while (true);
```

An omitted cursor starts a cycle; `cursor: null` and `hasMore: false` mark its
end. Live rows do not request an immediate retry once that boundary is
reached—start a new cycle on the next scheduled maintenance run. Persisting a
non-null cursor between calls avoids restarting a long cycle. Replaying a
cursor after a crash or from concurrent sweepers is safe: pages may repeat,
but deletion is version-conditional and a changed or already removed row is
left for a later cycle.

## Security posture

See the repository
[threat model](https://github.com/pegma-dev/identity/blob/main/docs/THREAT_MODEL.md).
WebAuthn is
verified by the exact pinned `@simplewebauthn/server` version against the
configured RP ID, origin allowlist, stored challenge digest, user presence,
and required user verification. A stored and newly reported zero counter is
accepted because some authenticators do not implement counters; once a
nonzero counter exists, every report must be strictly greater. Positive
counter mirror updates use a durable repairable transition, so a process crash
between the credential-index and per-user writes cannot strand the passkey.
Structured ceremony inputs are rejected before verification when any string
or property name exceeds 64 KiB of UTF-8 or their aggregate exceeds 256 KiB.

## License

[MIT](LICENSE) © 2026 RetireGolden, LLC
