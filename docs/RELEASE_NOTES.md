# Release notes

## 0.1.2

`0.1.2` is a dependency-only alignment release. `@pegma/rate-limit` advances
from `0.1.0` to `0.2.0` and `@pegma/mail` from `0.1.0` to `0.1.1`, so the
dependency tree resolves a single `@pegma/storage-core@0.4.0` — previously
rate-limit's transitive `storage-core@0.3.0` split hosts' trees into two
incompatible `Store` types. Identity itself already required a storage-core
`0.4.0` `Store`, so its composition contract, runtime behavior, and public
API are unchanged.

## 0.1.1

`0.1.1` closes the operator-guidance findings from the 2026-07-28 repository
security scan. It changes no runtime behavior and no public API; the packed
`dist/` output is identical to `0.1.0`. The release exists so consumers
receive the corrected package README.

### Security documentation

- `claimsFor` and `repairUserByEmail` are now named as privileged operations
  alongside `provisionVerifiedUser`. None of the three may be reachable from
  unauthenticated traffic or from a user-supplied `principalId` or email.
- The account-creation flow is documented as also authenticating existing
  accounts: `finishAccountCreation` returns an existing principal's claims,
  so the creation endpoint needs sign-in-grade rate limiting, session policy,
  and anomaly detection.
- Email change now carries explicit host obligations: authenticate the
  endpoint for the named principal, and require a fresh passkey assertion
  before `beginEmailChange`. The old-address notification is a detective
  control that arrives only after the change commits.
- `docs/THREAT_MODEL.md` records two acceptances explicitly: authenticator
  attestation is not verified (`attestationType: "none"`), and email-change
  freshness is a host obligation rather than a component invariant.

Three scan findings were reviewed and disputed as non-findings, with the
reasoning kept in `docs/securityscan.md`: plaintext deliverable addresses at
rest, deterministic HMAC-derived codes, and the credential-ID timing
distinction in `finishPasskeyAuthentication`.

## 0.1.0

`0.1.0` is the first advertised stable release of `@pegma/identity`. It
promotes the exact runtime and API audited in the `0.0.0` name-reservation
bootstrap; this release preparation changes no runtime behavior or public API.

### Included

- structurally unique, canonically normalized verified-email ownership keyed
  to stable `PrincipalId` users;
- durable eight-digit email-code account creation, fallback sign-in, recovery,
  and repairable email-change flows;
- enumeration-resistant suppression, dual durable rate limits, single-use
  conditional consumption, bounded attempts, retention, and authoritative
  sweeps;
- atomic Identity-owned Mail intent with worker, authenticated callback,
  acknowledgement, reconciliation, and old-address notification support;
- discoverable WebAuthn registration and authentication, multiple passkeys,
  revocation, user verification, and strict nonzero signature-counter
  progression; and
- exact frozen verified claims for composition with host-owned sessions and
  authorization.

### Security and operations

The mailbox is the recovery security floor. Hosts must keep the email-code
HMAC secret stable in managed secret storage, use durable rate limiters,
authenticate Mail callbacks, persist maintenance cursors, and schedule
challenge, email-operation, Mail, and limiter sweeps. Identity stores neither
sessions nor permissions and deliberately provides no passwords, social login,
or third-party OIDC/OAuth2 server.

Direct runtime dependencies remain exact:
`@pegma/mail@0.1.0`, `@pegma/rate-limit@0.1.0`,
`@pegma/spine@0.1.1`, `@pegma/storage-core@0.4.0`,
`@simplewebauthn/server@13.3.2`, `punycode@2.3.1`, `tr46@6.0.0`,
`unicode-case-folding@1.1.1`, and `unorm@1.6.0`.

## 0.0.0

Audited, unadvertised package-name bootstrap published on 2026-07-28 under
the `bootstrap` tag. It exists only to reserve `@pegma/identity`; consumers
should use `0.1.0` once the signed stable release is published.
