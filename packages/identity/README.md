# @pegma/identity

Passkeys-first, passwordless first-party identity for Pegma hosts.

> [!IMPORTANT]
> This package is an audited `0.0.0` name-reservation candidate. It is not an
> advertised production release. The user/email-index and WebAuthn passkey
> foundations are implemented; email-code enrollment, fallback, recovery,
> and email change remain unavailable until `@pegma/mail@0.1.0` publishes the
> shared durable-delivery contract.

## What it owns

- user records keyed authoritatively by `PrincipalId`;
- a structurally unique canonical email lookup with crash repair;
- discoverable WebAuthn credentials with required user verification;
- hashed, stored, short-lived, attempt-bounded WebAuthn challenges;
- multiple passkeys, revocation, and strict nonzero counter progression; and
- exact frozen `{ issuer, subject, emailVerified: true }` claims.

Email is contact and lookup data, never the identity key. `normalizeEmail` is
the only normalization path: it compatibility-normalizes Unicode, applies
locale-independent case folding, and converts the domain's IDNA U-label or
A-label to one ASCII A-label. The lookup key is a domain-separated digest, so
backend key metacharacters and raw contact data never become storage keys.

This package does not store sessions, resolve roles or permissions, serve
OIDC/OAuth2, connect social providers, or implement passwords.

## Construction

```ts
import {
  createIdentity,
  createMemoryChallengeRetention,
} from "@pegma/identity";
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

const identity = createIdentity({
  store,
  issuer: "https://accounts.example.com",
  rpName: "Example",
  rpID: "example.com",
  origins: ["https://example.com"],
  registrationLimiter,
  authenticationLimiter,
  // Development only. Production hosts provide a durable lazy index.
  challengeRetention: createMemoryChallengeRetention(),
});
```

Use a durable limiter in production. The caller-provided `rateLimitKey`
should identify an abuse scope such as a source address; it is not an email or
credential secret.

Production hosts must also provide a durable `ChallengeRetention`. Identity
tracks a harmless hash/expiry reference before inserting each authoritative
challenge, so a crash can leave only a stale reference, never an unsweepable
challenge. `track(reference)` must idempotently upsert the reference and return
one stable, unique opaque cursor for its `retentionId`. The host adapter's
`candidates(limit)` must derive that cursor from trusted retention-record
metadata and return it separately from the untrusted stored `reference`
payload. It must be lazy and must not materialize more than `limit` candidates.
`complete(cursor)` removes by trusted cursor even when the payload is
malformed. The included memory implementation is for tests and non-durable
development only.

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
account creation will verify an email code first when the mail phase lands.
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
principal. Removing the last passkey is allowed; the documented email
recovery floor will become available only with the mail phase.

Run `sweepChallenges(limit)` periodically. It pulls and authoritatively
inspects at most `limit` lazy retention candidates, never scans the challenge
collection, key-checks each reference, and deletes only expired or terminal
records with version-conditional deletion. A malformed payload is discarded
by its trusted cursor so it cannot starve later candidates. A valid but
corrupted payload that still locates an authoritative challenge is repaired
from that row before any stale cursor is settled. Stale, duplicate, malformed,
and wrong references cannot supply a delete key for another row or orphan the
only valid pointer. The returned `hasMore` is conservative: `true` means call
again now or after currently live candidates become eligible; `false` means
the source ended during this pass.

## Security posture

See the repository
[threat model](https://github.com/pegma-dev/identity/blob/main/docs/THREAT_MODEL.md).
WebAuthn is
verified by the exact pinned `@simplewebauthn/server` version against the
configured RP ID, origin allowlist, stored challenge digest, user presence,
and required user verification. A stored and newly reported zero counter is
accepted because some authenticators do not implement counters; once a
nonzero counter exists, every report must be strictly greater.

## License

[MIT](LICENSE) © 2026 RetireGolden, LLC
