# Identity

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

First-party identity for [Pegma](https://pegma.dev) hosts: passkeys-first,
email-code fallback, **no passwords** — user records in your own storage, no
external provider.

> [!IMPORTANT]
> `@pegma/identity@0.1.0` is the first advertised supported release, published
> from the protected signed `v0.1.0` tag through trusted-publisher OIDC. Its
> public API remains unstable. pegma.dev composes it in production with
> Sessions, Mail, durable Rate Limit policies, and
> `@pegma/authorization-identity@0.1.2`.

## What it is — and refuses to be

It answers one question: **who is this, and how do they prove it?** Account
creation, passkey sign-in, email one-time codes for enrollment/fallback/
recovery, email change — issuing verified identity claims the host turns
into a session ([`@pegma/sessions`](https://github.com/pegma-dev/sessions))
and links into
[`@pegma/authorization-core`](https://github.com/pegma-dev/authorization-core)
through a deliberately tiny adapter.

Refused, loudly:

- **Passwords.** Not a phase — a refusal. No password table, no reset flow,
  no breach class. Passkeys are phishing-resistant and breach-inert; an
  emailed code covers everything else.
- **Being an OIDC/OAuth2 server for third parties.** That is a product
  with a standards surface, not a component.
- **Social login.** External providers exist for that; issuer-namespaced
  identity links already let a host run both side by side.
- **MFA beyond passkey + email**, profiles, admin UIs, org management.

One honest admission, stated rather than buried: an account recoverable by
emailed code is exactly as secure as the mailbox behind it. Every consumer
service works this way; almost none say it. We say it.

## License

MIT © RetireGolden, LLC
