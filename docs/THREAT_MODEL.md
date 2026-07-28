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
- the integrity of `{ issuer, subject, emailVerified: true }` claims; and
- availability of enrollment, authentication, recovery, and repair.

Email-code delivery and its durable outbox are intentionally not implemented
until `@pegma/mail@0.1.0` provides the shared contract. When that phase lands,
mailbox control will be the account-recovery security floor. The component
cannot make a compromised mailbox safe; hosts must communicate that limit and
should encourage passkey enrollment.

## Threat Model, Trust Boundaries, and Assumptions

The primary boundaries are:

1. An untrusted browser supplies email text, WebAuthn JSON, credential labels,
   challenge handles, and authenticator responses to a host endpoint.
2. The host authenticates management operations, chooses a stable issuer,
   relying-party ID, allowed origins, and `PrincipalId` values, and maps its
   HTTP and rate-limit policy onto this library. Host configuration is trusted
   but validated at runtime where practical.
3. `@simplewebauthn/server` parses and cryptographically verifies WebAuthn
   responses. Its exact reviewed version is part of this package's runtime
   security boundary.
4. `@pegma/storage-core` and its adapter persist flat records. Storage content
   is not trusted to be well formed: decoding and state transitions fail
   closed on malformed or stale records. Cross-collection atomicity is not
   assumed; only documented single-partition transactions and optimistic
   conditions are available.
5. A host may mint a session from returned claims. Session lifetime,
   revocation, cookies, CSRF defenses, and authorization are outside this
   repository and belong to `@pegma/sessions` and authorization components.

Attacker-controlled inputs include every public method argument that can
originate in a request, including objects with accessors, Unicode and control
characters, oversized strings, replayed challenge handles, cloned
authenticator counters, and concurrent requests. An attacker may know an
email, credential ID, or `PrincipalId`; none is treated as a secret.

Operator-controlled inputs include issuer, RP ID, origin allowlists, clock and
ID ports, storage configuration, endpoint authentication, rate-limit keys,
and future mail delivery. Developer-controlled inputs include dependency
updates, collection codecs, release tooling, and CI.

Security invariants:

- `PrincipalId`, not email, is the authoritative identity subject.
- Exactly one normalization function produces every email lookup value.
  Canonically equivalent, case-equivalent, and IDNA U-label/A-label domain
  inputs collide structurally.
- User creation cannot expose two active principals for one normalized email,
  including during crashes and races. Recovery uses an explicit
  reserve/prepare/commit/activate/repair protocol.
- Claims contain exactly `issuer`, `subject`, and literal
  `emailVerified: true`; they are fresh, own-data-only frozen objects and are
  issued only from active verified state.
- WebAuthn credentials are discoverable, require user verification, are
  scoped to configured RP IDs and origins, and support multiple credentials
  per principal.
- Challenges are unpredictable, hashed at rest, short-lived, single-use,
  attempt-bounded, and version-conditionally swept through a caller-supplied
  durable lazy retention index. A sweep pulls and inspects at most its limit;
  it never enumerates the authoritative challenge collection.
- A positive nonzero signature counter must strictly increase. A counter may
  remain zero only when both stored and newly reported values are zero.
- Raw token-shaped values, future one-time codes, and challenge verification
  material never enter storage, logs, or error messages.
- Malformed storage and malformed/accessor-bearing request objects fail
  closed. Validation must not execute attacker-provided getters.
- Email-code creation, fallback, and recovery will return indistinguishable
  responses for known and unknown emails. Those flows remain unavailable
  until the shared mail contract exists rather than shipping a partial,
  enumerable substitute.

The model assumes HTTPS outside explicit localhost development, correct
browser WebAuthn implementations, secure host endpoint authentication for
enrollment and credential management, a cryptographically sound Web Crypto
implementation, and a storage adapter conforming to `@pegma/storage-core`.

## Attack Surface, Mitigations, and Attacker Stories

Email lookup is exposed to normalization confusion and concurrency. NFKC
normalization, locale-independent case folding, web-standard IDNA conversion
to an ASCII A-label domain, control rejection, bounded input, a digest-derived
backend-safe key, and `insertIfAbsent` prevent case/Unicode/IDNA aliases and
storage-key metacharacters from creating duplicate accounts.
Cross-collection crashes are expected, so intermediate states are durable and
repairable rather than treated as exceptional.

WebAuthn option generation can be abused for storage exhaustion. Challenge
TTLs, maximum attempts, bounded identifiers and labels, a required durable
retention index, truly bounded lazy candidate pulls, and host endpoint rate
limiting constrain the budget. The harmless retention reference is written
before its authoritative challenge, so crashes can create stale references
but not unsweepable rows. Authentication uses
discoverable credentials and does not accept an email identity hint.
Verification pins the expected RP ID, allowed origin, challenge digest, and
required user verification. Credential IDs are structurally unique and
signature-counter transitions use optimistic concurrency.

Challenge handles and authenticator responses can be replayed or raced. The
handle is random and only its domain-separated hash is stored. A verification
attempt atomically claims a pending record; success consumes it, while failure
increments a bounded attempt count. Concurrent submissions cannot both claim
the same challenge. Expired and terminal records are retained until a
version-conditional sweep, so a stale listing cannot delete replacement
state.

Storage poisoning can target codecs, sweep key reconstruction, or state
machines. Codecs validate types, exact enum values, timestamp shape, hashes,
and identity relationships. Sweeps delete only keys reconstructed from valid
records and pair each with the version returned for that record. Unknown
states are retained for investigation and never promoted.

Object-shape attacks can hide work in getters or prototypes. Public structured
inputs are copied from property descriptors only after rejecting accessors,
symbol keys, non-plain prototypes, cycles, and excessive depth/size. The
WebAuthn dependency receives the inert copy. Public outputs are newly
allocated, own-data-only, and frozen.

Dependency and release compromise matter because this library executes in an
authentication path. Runtime versions are exact, the lockfile is reviewed,
`npm audit` gates preparation, CI actions are SHA-pinned, Node 22 and 24 run
the complete gate, package contents are allowlisted, tests are excluded from
the tarball, and publishing uses a prepared artifact with trusted-publisher
OIDC. A bootstrap `0.0.0` exists only to reserve the npm name and is not an
advertised production release.

Realistic attacker stories include racing account creation with canonically
equivalent emails, replaying an assertion, submitting a cloned authenticator
whose nonzero counter regresses, exhausting challenges, corrupting storage
records, or exploiting a parser in the WebAuthn dependency. An attacker who
already controls the host process, production storage credentials, the
configured origin/RP ID, or the future recovery mailbox is beyond what this
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
counter regression; or exposing raw future code/challenge secrets from
storage.

**Medium:** a bounded denial of service against enrollment or sign-in;
permanent orphaned reservations without repair; cross-account passkey removal
that cannot itself issue claims; email enumeration through a future fallback
flow; or malformed records causing a fail-closed outage in one partition.

**Low:** unbounded diagnostic detail that contains no secret or account
existence signal; inaccurate sweep counts while deletion remains conditional;
developer-only tooling defects that cannot alter a release artifact; or
documentation that weakens operator guidance without changing a secure
default.

Repository: sha256:d0658a8b602d4afefbbe71a4d7d0a33500bf48657015923311007629bfe6e193
Version: 2a761f170d8c8f2382d1ba0013f100b7bc533b35
