# Identity Project Plan

## Status

**Stage:** Phases 1–4 are complete. `@pegma/identity@0.1.0` is published and
live in pegma.dev with `@pegma/authorization-identity@0.1.2`. The public API
remains unstable.

The audited `0.0.0` name-reservation bootstrap is published and deliberately
unadvertised. Version `0.1.0` contains the reviewed full passwordless
lifecycle and was published from the protected, signed annotated `v0.1.0` tag
through the hardened GitHub Actions workflow using npm trusted publishing.
The user/email-index model, durable email-code creation/fallback/recovery and
email-change lifecycle, and passkey/challenge foundation are built and tested
over memory plus real Azurite races. Mail delivery uses exact
`@pegma/mail@0.1.0`; Identity owns the operation/Mail union required to commit
code state and delivery intent atomically. The threat model and hardened
release scaffold gate every identity change.

**License:** MIT

**Naming and origin:** "Identity" is the first-party identity provider of
the Pegma ecosystem: user records in the host's own storage, no external
provider. It is NOT an authorization component (roles and permissions are
`@pegma/authorization-core`'s) and NOT a session store (`@pegma/sessions`
remembers what this component establishes). It answers exactly one
question: **who is this, and how do they prove it?** The git history begins
here; nothing was ever published under another name.

**Storage:** collections over an injected `@pegma/storage-core` `Store`;
time, logging, and `PrincipalId` from `@pegma/spine`. Pinned exactly. No
dependency on authorization-core — the link into it is a separate,
deliberately tiny published adapter
(`@pegma/authorization-identity@0.1.2`).

## Vision

The ecosystem's "site assembled by an agent" story currently ends at an
external signup: every host needs an Auth0 (or similar) account before its
first user exists. This component closes that last third-party dependency —
a host that wants first-party accounts declares collections, wires ports,
and owns its users outright.

And it is **passkeys-first, passwordless entirely**. Passwords are not the
familiar default with known risks; they are a liability class — storage,
stuffing, reuse, phishing, reset flows — that a component born in 2026 can
simply decline to have. Passkeys are phishing-resistant, breach-inert, and
supported everywhere that matters; an emailed one-time code covers
enrollment, fallback, and recovery. No passwords means no password table,
no password reset, and no password breach — ever.

## Fundamental model

**User** — a record keyed by `PrincipalId`, holding contact email (verified
flag), created/updated instants, and status. The email is a CONTACT and a
LOOKUP, never an identity key (the ecosystem invariant): a separate index
collection maps canonically-normalized email → principal, with uniqueness
made structural by `insertIfAbsent` on the normalized email as the record
id — the same trick authorization-core uses for tuple guards. Email
normalization (case-folding, Unicode) is ONE function, used everywhere.

**Passkey** — a WebAuthn credential record per user: credential id, public
key, signature counter, transports. Users may hold several; adding and
removing them are first-class flows.

**One-time code** — the email channel: an eight-digit HMAC-derived code,
stored only as a separately domain-separated keyed verifier, single-use via a
conditional update, short TTL.
Codes serve enrollment verification, sign-in fallback, and recovery — three
uses, one mechanism, one set of invariants.

**Challenge** — the short-lived server-side WebAuthn challenge record,
stored (not stateless) for simplicity, swept like any expiring record.

**Verified identity claims** — the output: `{ issuer, subject,
emailVerified }`, where `issuer` is a host-configured stable string and
`subject` is the `PrincipalId`. The host mints a session from this
(`@pegma/sessions`); authorization-core links it through its adapter. This
component ISSUES claims; it never stores sessions or resolves permissions.

## Flows (v1, complete list)

- **Account creation** — email in, uniform response out (see enumeration
  resistance), code emailed, code verifies, user exists with a verified
  email, passkey enrollment offered immediately.
- **Sign-in** — passkey ceremony first; email-code fallback for devices
  without one.
- **Passkey management** — add, list (by user-visible label), remove; the
  last passkey may be removed (email-code remains — the honest floor; see
  design decisions).
- **Email change** — verify the NEW address by code before the switch;
  notify the old address; index updated transactionally with the user
  record where the port allows.
- **Recovery** — the email code IS recovery. No security questions, no
  backup codes in v1.
- **Sign out everywhere** — delegated: the host calls sessions'
  `destroyAllForPrincipal`. Identity exposes nothing session-shaped.

## Design decisions

### Passwordless is a refusal, not a phase

No password support, at all, in any version until a real consumer proves
passkeys-plus-email cannot serve it — and the burden of proof is high,
because every password feature (hashing parameters, rehash-on-login,
stuffing defense, reset flows) is permanent liability bought for
compatibility with the past. This is the component's loudest contract term.

### The email channel is the security floor — say so

An account recoverable by emailed code is exactly as secure as the mailbox
behind it. That is true of nearly every consumer service and nearly always
left unsaid. This component says it: hosts inherit mailbox-grade account
security, documented, and the mitigation is passkey enrollment plus
prompt notification mails on sensitive events — not pretending otherwise.

### Enumeration resistance is a hard rule shaping every flow

Creation, sign-in fallback, and recovery answer IDENTICALLY whether or not
the email exists (same response, same timing envelope, the send just
doesn't happen for unknown addresses). One helpful error message —
"no account with that email" — undoes the property everywhere; tests pin
the uniform responses.

### Codes and challenges follow the sessions discipline

Hashed at rest (a leaked table verifies nothing), single-use consumed
through a conditional update (two concurrent submissions cannot both
succeed), short TTLs, versioned sweeps, attempts bounded and rate-limited
(`@pegma/rate-limit`'s durable tier — sign-in and code-request throttling
are its named use case).

### Signature counters are checked, honestly

A passkey whose reported counter regresses is flagged and refused (possible
clone), with the caveat the WebAuthn spec itself carries: many
authenticators always report zero, so the check catches what it catches.
Documented as such — no theater.

### Delivery is a port; the outbox is the implementation

Verification and recovery mail are canonical must-not-be-lost sends. The
component defines a narrow send port; the host implements it — over the
durable outbox pattern when `@pegma/mail` exists (this component is,
deliberately, the second consumer that justifies extracting it from the
support desk per the audit rule).

### The threat model is a deliverable, not documentation

`docs/THREAT_MODEL.md` ships before any 0.x publish: assets, attackers,
the email-floor admission, enumeration analysis, WebAuthn ceremony
assumptions, and the abuse budget per endpoint. A security-focused review
pass gates the first release. This is the one component where a bug is a
breach; it gets the ceremony that deserves.

## Scope

### Non-goals (the loud ones)

- **Being an OIDC/OAuth2 server for third parties.** Issuing tokens other
  applications consume is a product with a standards surface, not a
  component. Hosts that need federation should buy it.
- **Social login.** Connecting Google/Apple/GitHub is what external
  providers are for; a host wanting both wires both, and
  authorization-core's issuer-namespaced links already keep the principals
  straight.
- **Passwords.** See above — the refusal is the feature.
- **MFA beyond passkey + email.** A passkey is already
  possession-plus-biometric; TOTP apps and SMS add complexity and (for
  SMS) known weakness.
- **Profiles, avatars, display names** beyond the identity fields — host
  data, host's problem.
- **Admin UI, org/tenant management, user search** — hosts compose these
  from the ports if they need them.

## Package architecture

One package: `packages/identity` publishing `@pegma/identity`.
Dependencies: exact `@pegma/spine@0.1.1`,
`@pegma/storage-core@0.4.0`, `@pegma/rate-limit@0.1.0`,
`@pegma/mail@0.1.0`, and
`@simplewebauthn/server@13.3.2`, `unicode-case-folding@1.1.1`,
`unorm@1.6.0`, and `tr46@6.0.0`. Framework-free flows are functions the host's
HTTP layer calls, same posture as every Pegma component.

## Delivery phases

### Phase 1 — the user store (implemented)

User + email-index collections, canonical normalization, structural
uniqueness, the claims shape. Race tests: concurrent same-email creation
converges on one user.

### Phase 2 — the email-code flows (implemented)

Creation, verification, fallback sign-in, recovery, and a repairable email
change saga are implemented over an Identity-owned operation/Mail union.
Eight-digit codes are HMAC-derived without modulo bias; storage contains only
the hashed handle and a separately domain-separated keyed verifier. Known and
unknown flows have uniform public shapes and durable suppression for unknown
fallback/recovery. Durable rate limiting, authoritative sweeps, Mail
worker/callback/acknowledgement wrappers, and old-address notification are
part of this phase.

### Phase 3 — passkeys (foundation implemented)

Registration and authentication ceremonies, credential management,
counter handling. Exit: a host can run passkey-only sign-in with email
strictly as enrollment/recovery.

### Phase 4 — threat model, review, first consumer (released)

THREAT_MODEL.md and repeated adversarial review passes gate the release. The
audited `0.0.0` package-name bootstrap followed the ecosystem bootstrap rule
(npm/cli#8544). The first advertised `0.1.0` release was published from its
protected, signed annotated tag through the GitHub Actions workflow using npm
trusted publishing, without runtime or API changes. pegma.dev now composes the
package and the published Authorization adapter; consumer deployment remains
independent of the package boundary.

## Timing

The storage, rate-limit, WebAuthn, and Mail prerequisites exist. Phases 1, 2,
and 3 are implemented, the threat model and adversarial release review are
complete, and both the audited `0.0.0` bootstrap and advertised `0.1.0`
release are published. The protected `v0.1.0` release ceremony is complete,
and pegma.dev composes Identity with
`@pegma/authorization-identity@0.1.2`.

## Open questions

**Magic links vs. codes (resolved).** V1 is codes-only. Links leak into
mailbox previews, can be consumed by security scanners, and break
cross-device sign-in; eight-digit codes type anywhere.

**PrincipalId as subject.** Using the storage principal directly as the
claim subject is simple and stable; an argument exists for an opaque
separate subject (rotatable). Lean direct; revisit only with a rotation
requirement.

**Email index transactionality.** Email change wants the index swap and
user update atomic; storage-core transactions are single-collection,
single-partition, so the swap likely follows the reserve-then-commit
pattern instead. Settle against the real port in Phase 1.
