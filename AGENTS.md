# Working in this repository

Read this before changing anything. It is short on purpose.

## What this is part of

Identity is the first-party identity provider of **Pegma**, a family of
MIT-licensed packages a host application composes. Shared contracts live in
`@pegma/spine`; persistence in `@pegma/storage-core`; sessions, roles, and
permissions in their own components. One repository per component,
publishing under the `@pegma` scope.

The governing principle, which every rule below follows from:

> **Optimize for a fresh agent context window.** How much must be read to make
> a correct change, and how does the change prove itself correct? Minimize the
> first, mechanize the second.

This is the one component where a bug is a breach. Weigh changes
accordingly, and give every change the adversarial read.

## Hard rules

**No passwords. Ever. In any form.** No hash column "for later", no
compatibility shim, no optional provider. The refusal is the component's
central feature; a consumer that cannot live with passkeys + email codes
uses a different product.

**No OIDC/OAuth2 serving and no social login.** Issuing tokens for third
parties is a product, not a component; connecting Google/Apple is what
external providers are for. Refuse both regardless of how small the request
looks.

**Email is a contact and a lookup, never an identity key.** Users are keyed
by PrincipalId; the email→principal index owns uniqueness structurally.
Exactly one normalization function exists; every path uses it.

**Secrets are hashed at rest, always.** One-time codes and any
token-shaped value are stored hashed, single-use via conditional update,
short-TTL, swept. A raw code or token never reaches storage, logs, or
error messages.

**Enumeration resistance is a test-pinned property.** Creation, fallback
sign-in, and recovery answer identically for known and unknown emails. Any
change that makes the two distinguishable — message, status, timing shape —
is wrong even if it is friendlier.

**Sessions are not stored here and permissions are not resolved here.**
This component issues verified claims; `@pegma/sessions` remembers,
authorization-core decides. Anything session- or role-shaped in a diff is
scope creep.

**The threat model gates release.** `docs/THREAT_MODEL.md` ships before any
publish, and security-relevant changes update it in the same PR.

**Test against real storage, races included.** The suite runs over
`createMemoryStore()` and real Azurite; concurrent same-email creation,
double code consumption, and counter-regression cases are the
specification.

## Reference points

The plan is `docs/PROJECT_PLAN.md`. The sessions repository's discipline
(hashed at rest, opposite delete rules, fail-closed) is the nearest
precedent for the storage posture here.

## Where things stand

The audited `0.0.0` package remains under the `bootstrap` tag solely to reserve
`@pegma/identity`. Version `0.1.0` is the first advertised supported release,
published from its protected signed tag through trusted-publisher OIDC. Its
runtime and API contain the reviewed user/email-index, durable email-code,
Mail, and passkey implementation. pegma.dev composes it in production with
Sessions, Rate Limit, and `@pegma/authorization-identity@0.1.2`.
The public API remains unstable while it is in the `0.x` line.

Normal releases use the protected signed annotated `vX.Y.Z` tag and GitHub
release workflow described in `docs/RELEASING.md`. Never publish a locally
repacked artifact or add an npm token.
