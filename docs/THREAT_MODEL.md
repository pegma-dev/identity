# Identity threat model

## Overview

`@pegma/identity` is a framework-neutral, first-party identity library. A host
provides storage and HTTP endpoints; the library owns user records, the unique
email lookup, WebAuthn challenges, and passkey credentials. It establishes a
`PrincipalId` and issues verified identity claims. It does not store sessions,
resolve permissions, serve OAuth/OIDC, support social login, or accept
passwords.

The protected assets are:

- the binding between a host-issued `PrincipalId` and its verified contact
  email;
- the structural uniqueness of the canonical email lookup;
- passkey credential public keys and signature counters;
- short-lived WebAuthn challenge state;
- short-lived email-code operation state and its durable Mail intent;
- the integrity of `{ issuer, subject, emailVerified: true }` claims; and
- availability of enrollment, authentication, recovery, and repair.

Mailbox control is the account-recovery security floor. The component cannot
make a compromised mailbox safe; hosts must communicate that limit and should
encourage passkey enrollment. `@pegma/mail@0.1.0` provides durable
at-least-once delivery state while the provider remains host-owned.

## Threat Model, Trust Boundaries, and Assumptions

The primary boundaries are:

1. An untrusted browser supplies email text, WebAuthn JSON, credential labels,
   challenge handles, and authenticator responses to a host endpoint.
2. The host authenticates management operations, chooses a stable issuer,
   relying-party ID, allowed origins, and `PrincipalId` values, and maps its
   HTTP and rate-limit policy onto this library. Host configuration is trusted
   but validated at runtime where practical.
3. `@simplewebauthn/server` parses and cryptographically verifies WebAuthn
   responses. Exact-reviewed `unorm`, `unicode-case-folding`, and `tr46` data
   normalize the fixed email repertoire without relying on runtime Unicode or
   IDNA versions. These exact versions are part of the package's runtime
   security boundary.
4. `@pegma/storage-core` and its adapter persist flat records. Storage content
   is not trusted to be well formed: decoding and state transitions fail
   closed on malformed or stale records. Cross-collection atomicity is not
   assumed; only documented single-partition transactions and optimistic
   conditions are available.
5. The host owns an HMAC key of at least 32 random bytes, a trusted mail
   renderer, provider, authenticated callback boundary, reconciliation port,
   and two durable rate-limit policies. Provider idempotency and finite
   renderer/provider timeouts shorter than the Mail lease are required.
6. A host may mint a session from returned claims. Session lifetime,
   revocation, cookies, CSRF defenses, and authorization are outside this
   repository and belong to `@pegma/sessions` and authorization components.

Attacker-controlled inputs include every public method argument that can
originate in a request, including objects with accessors, Unicode and control
characters, oversized strings, replayed challenge handles, cloned
authenticator counters, and concurrent requests. An attacker may know an
email, credential ID, or `PrincipalId`; none is treated as a secret.

Operator-controlled inputs include issuer, RP ID, origin allowlists, clock and
ID ports, storage configuration, endpoint authentication, rate-limit keys,
HMAC key rotation, and mail delivery. Developer-controlled inputs include dependency
updates, collection codecs, release tooling, and CI.

Security invariants:

- `PrincipalId`, not email, is the authoritative identity subject.
- Exactly one normalization function produces every email lookup value.
  NFKC-compatible, full Unicode default-case-fold equivalent, and IDNA
  U-label/A-label domain inputs inside a fixed repertoire collide
  structurally. Inputs outside that repertoire fail closed.
- User creation cannot expose two active principals for one normalized email,
  including during crashes and races. Recovery uses an explicit
  reserve/prepare/commit/activate/repair protocol.
- Claims contain exactly `issuer`, `subject`, and literal
  `emailVerified: true`; they are fresh, own-data-only frozen objects and are
  issued only from active verified state.
- WebAuthn credentials are discoverable, require user verification, are
  scoped to configured RP IDs and origins, and support multiple credentials
  per principal. Every credential-index trust boundary recomputes
  `principalHash` from `principalId` before verification, mutation, repair, or
  claims issuance. A reserved generation can create its passkey mirror only
  from an exact, content-addressed immutable registration proof stored before
  the reservation; an active generation must cross-check the independently
  stored passkey mirror's owner, credential identity, generation, public key,
  transports, label, creation time, and counter.
- Authenticator attestation is deliberately not verified. Registration uses
  `attestationType: "none"`, so no authenticator-model or AAGUID policy is
  expressed and software passkeys are accepted. This is the correct default
  for consumer passkeys; a host that must assume hardware-bound keys cannot
  obtain that assurance from this component.
- Challenges are unpredictable, hashed at rest, short-lived, single-use,
  attempt-bounded, and version-conditionally swept through storage-core's
  authoritative bounded collection scan. The adapter returns at most the
  requested limit, the physical key and version of every row, and an opaque
  continuation that survives process restart. A null continuation closes the
  cycle, so live rows do not cause a hot retry loop; repeated complete cycles
  cannot permanently starve committed work.
- A positive nonzero signature counter must strictly increase. A counter may
  remain zero only when both stored and newly reported values are zero.
  Positive advances pass through a durable `counter-pending` state: the
  credential index retains the verifier's old counter and target counter until
  the independently stored passkey mirror reaches exactly that target, after
  which repair finalizes the index. A crash on either side of the mirror write
  is replayable without weakening owner, generation, or counter-regression
  checks.
- Raw token-shaped values, one-time codes, and challenge verification
  material never enter storage, logs, or error messages.
- Eight-digit codes are deterministically derived with unbiased rejection
  sampling from a domain-separated HMAC. Storage contains only a separately
  domain-separated keyed verifier and hashed handle, so a database-only
  attacker cannot validate offline guesses.
- V1 does not support live HMAC-key rotation. Rotation pauses new operations,
  invalidates or drains all code operations, and settles/sweeps every
  nonterminal Mail job before replacing the key. Emergency replacement first
  invalidates pending operations.
- Code state and initial delivery intent commit in one Identity-owned
  operation/Mail transaction. Unknown fallback/recovery commits a suppression
  row in the same request shape and can never become valid after later signup.
- A pending code is single-use through optimistic update. Known authentication
  rechecks that the active principal still owns the email observed at begin.
- Email change is a repairable cross-collection saga. Old-address notification
  is atomically enqueued with completed operation state only after User and
  new-index agreement.
- Email change carries no freshness requirement inside the component: it
  verifies only that the named principal is active and email-verified, and
  mailbox control of the new address completes it. Authenticating the
  change endpoint for that principal and requiring a fresh passkey assertion
  before `beginEmailChange` are host obligations, recorded in the package
  README. The old-address notification is a detective control that arrives
  only after the change commits, so a host that skips step-up leaves a
  hijacked session able to redirect email sign-in and recovery, bounded by
  the victim's retained passkeys.
- Mail delivery is at least once. Provider idempotency keys fence ambiguous
  sends; authenticated callbacks are generation-fenced; dead-letter and
  terminal-unknown outcomes remain operator-visible until acknowledged.
- Malformed storage and malformed/accessor-bearing request objects fail
  closed. Validation must not execute attacker-provided getters.
- Email-code creation, fallback, and recovery return indistinguishable public
  shapes for known and unknown emails. Both limiter dimensions and the same
  operation transaction are performed without short-circuiting. Hosts with a
  remote timing threat should additionally enforce a response timing floor.

The model assumes HTTPS outside explicit localhost development, correct
browser WebAuthn implementations, secure host endpoint authentication for
enrollment and credential management, a cryptographically sound Web Crypto
implementation, and a storage adapter conforming to `@pegma/storage-core`.

## Attack Surface, Mitigations, and Attacker Stories

Email lookup is exposed to normalization confusion and concurrency. NFKC
normalization, exact-pinned full Unicode default case folding, exact-pinned
TR46 conversion to an ASCII A-label domain, a deliberately fixed supported
repertoire, control rejection, bounded input, a digest-derived backend-safe
key, and `insertIfAbsent` prevent runtime Unicode/IDNA table drift,
case/Unicode/IDNA aliases, and storage-key metacharacters from creating
duplicate accounts.
Cross-collection crashes are expected, so intermediate states are durable and
repairable rather than treated as exceptional.

WebAuthn option generation can be abused for storage exhaustion. Challenge
TTLs, maximum attempts, bounded identifiers and labels, authoritative
adapter-bounded scan pages, and host endpoint rate limiting constrain the
budget. Sweep decodes each physical row independently, so a malformed row is
retained for investigation without preventing the continuation from reaching
later rows. It deletes only by the adapter-issued physical key and version.
Opaque continuations may be replayed after a crash or by concurrent sweepers;
conditional deletion makes duplicate pages harmless. A null continuation
ends the current cycle even when rows remain live, preventing immediate
retry loops while the next scheduled cycle restores eventual visibility.
Authentication uses discoverable credentials and does not accept an email
identity hint.
Verification pins the expected RP ID, allowed origin, challenge digest, and
required user verification. Credential IDs are structurally unique and
signature-counter transitions use optimistic concurrency. A re-registration
of a revoked credential succeeds only when the reserved row has the exact
registration generation and immutable credential material proposed by that
ceremony; a concurrent loser cannot consume its challenge or report another
ceremony's key as its own.

Challenge handles and authenticator responses can be replayed or raced. The
handle is random and only its domain-separated hash is stored. A verification
attempt atomically claims a pending record; success consumes it, while failure
increments a bounded attempt count. Concurrent submissions cannot both claim
the same challenge. Expired and terminal records are retained until a
version-conditional sweep, so a stale listing cannot delete replacement
state.

Storage poisoning can target codecs, sweep key reconstruction, or state
machines. Codecs validate types, exact enum values, timestamp shape, hashes,
and identity relationships. Email-index repair recomputes `principalHash` from
`principalId` before any write. Reserved credential repair requires the exact
immutable registration proof; active credential reads require an exact
independently stored passkey binding before any challenge claim, signature
verification, repair, mutation, or claims lookup. These checks prevent
substituting both owner fields from attaching an attacker's credential
material to a victim. Sweeps delete only adapter-issued physical keys paired
with the version returned for that row. Malformed and unknown authoritative
states are retained for investigation and never promoted.

Object-shape attacks can hide work in getters or prototypes. Public structured
inputs are copied from property descriptors only after rejecting accessors,
symbol keys, non-plain prototypes, cycles, and excessive depth/size. Every
string value and object key is limited to 64 KiB in UTF-8, with a 256 KiB
aggregate string budget for one structured input. The WebAuthn dependency
receives the inert bounded copy. Public outputs are newly allocated,
own-data-only, and frozen.

Dependency and release compromise matter because this library executes in an
authentication path. Runtime versions are exact, the lockfile is reviewed,
and every direct runtime lock entry requires public-registry provenance and
SHA-512 integrity. Release operations isolate npm config and explicitly
override hostile inherited registries. `pnpm audit` gates preparation, CI
actions are SHA-pinned, Node 22 and 24 run the complete gate, package contents
are allowlisted, tests are excluded from the tarball, and publishing uses a
prepared artifact with trusted-publisher OIDC. A bootstrap `0.0.0` exists only
to reserve the npm name and is not an advertised production release; normal
release automation rejects every version below `0.1.0` before dependency
installation.

Realistic attacker stories include racing account creation with canonically
equivalent emails, replaying an assertion, submitting a cloned authenticator
whose nonzero counter regresses, exhausting challenges, corrupting storage
records, or exploiting a parser in the WebAuthn dependency. An attacker who
already controls the host process, production storage credentials, the
configured origin/RP ID, HMAC key, mail provider, or recovery mailbox is beyond what this
library can contain. Session theft, CSRF, and permission mistakes are material
to the composed application but are outside this repository's code surface.

## Severity Calibration (Critical, High, Medium, Low)

**Critical:** remotely obtaining verified claims for another principal
without controlling an enrolled authenticator or approved recovery channel;
WebAuthn verification bypass; arbitrary code execution through request
parsing or a runtime dependency; or a release-chain compromise that publishes
attacker code as this package.

**High:** creating two active principals for one canonical email; replaying
one challenge to authenticate more than once; accepting the wrong RP ID or
origin; accepting absent user verification; silently accepting a nonzero
counter regression; or exposing raw code/challenge secrets from
storage.

**Medium:** a bounded denial of service against enrollment or sign-in;
permanent orphaned reservations without repair; cross-account passkey removal
that cannot itself issue claims; email enumeration through a fallback
flow; or malformed records causing a fail-closed outage in one partition.

**Low:** unbounded diagnostic detail that contains no secret or account
existence signal; inaccurate sweep counts while deletion remains conditional;
developer-only tooling defects that cannot alter a release artifact; or
documentation that weakens operator guidance without changing a secure
default.

Repository: sha256:d0658a8b602d4afefbbe71a4d7d0a33500bf48657015923311007629bfe6e193
Version: 2a761f170d8c8f2382d1ba0013f100b7bc533b35
