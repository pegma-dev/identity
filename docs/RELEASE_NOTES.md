# Release notes

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
