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
import { createIdentity } from "@pegma/identity";
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
});
```

Use a durable limiter in production. The caller-provided `rateLimitKey`
should identify an abuse scope such as a source address; it is not an email or
credential secret.

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
nonzero counter exists, every report must be strictly greater.

## License

[MIT](LICENSE) © 2026 RetireGolden, LLC
