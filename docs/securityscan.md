# Security Scan Log

**Scan date:** 2026-07-28
**Scope:** Repository-wide security review of `@pegma/identity`
**Method:** Incremental static review; findings appended as discovered.

## Findings

Findings are appended below in the order they were discovered during the scan.

---

*(Scan complete — 7 findings, none Critical/High/Medium. Summary at bottom.)*

### F-01 — Privileged claim-issuing primitives on the public API surface

- **Severity:** Low (hardening / trust-boundary documentation)
- **Status:** Mitigated by documentation — `packages/identity/README.md:153-170` explicitly labels `provisionVerifiedUser` "an explicitly privileged provisioning operation" and warns "Do not expose `provisionVerifiedUser` directly as public signup"; `claimsFor` is shown inside the same privileged block. Residual: the warning covers provisioning but does not separately call out `claimsFor`/`repairUserByEmail`; a one-line addition would close the gap.
- **Evidence:** `createIdentity()` exposes `provisionVerifiedUser`, `repairUserByEmail`, and `claimsFor` directly on the frozen public object (`packages/identity/src/index.ts:389-393`). `claimsFor` (`packages/identity/src/users.ts:456-463`) returns `VerifiedIdentityClaims` for **any** principalId that resolves to an active verified user, with no proof of possession. `provisionVerifiedUser` (`packages/identity/src/users.ts:334-382`) creates an already-verified user without any email-code ceremony.
- **Exploitability:** Not exploitable inside the component — these exist so the verified email-code repair path and host bootstrap can run. Risk is realized only if a host wires them to an unauthenticated route; then arbitrary verified-account creation / claim minting for any known principalId.
- **Recommendation:** Document in the package README that these three methods must never be reachable from unauthenticated traffic; consider a naming or options-level gate in a future API revision.

### F-02 — Email change requires no fresh authentication; old address notified only after the fact

- **Severity:** Low
- **Status:** Open — design tradeoff, partially mitigated
- **Evidence:** `begin("email_change", ...)` (`packages/identity/src/email-codes.ts:302-322`) requires only that the principal is active + email-verified. Proof of control of the **new** inbox (`finishEmailChange`) completes the change; the old address receives `old-address-notification` only after `effectState: "complete"` (`packages/identity/src/email-codes.ts:604-619`, `803-870`).
- **Exploitability:** An attacker holding a hijacked session (sessions are out of component scope) can redirect email-code sign-in and recovery to an inbox they control. Bounded by: passkeys remain bound to the principal (victim retains passkey sign-in and can revert), and the old-address notification is a detective control.
- **Recommendation:** Host guidance to require a fresh passkey assertion before `beginEmailChange`; confirm coverage in `docs/THREAT_MODEL.md`.

### F-03 — WebAuthn attestation is not verified

- **Severity:** Informational
- **Status:** Accepted design (confirm in threat model)
- **Evidence:** `attestationType: "none"` in `beginRegistration` (`packages/identity/src/passkeys.ts:785`). No authenticator-model/AAGUID policy is possible; software passkeys are permitted.
- **Exploitability:** N/A for typical consumer passkey deployments; relevant only if a host assumes hardware-bound keys.

### F-04 — Plaintext PII (email addresses) at rest

- **Severity:** Informational
- **Status:** Accepted design
- **Evidence:** Email addresses are stored unhashed in `UserRecord.email`, `EmailIndexRecord.email`, `EmailCodeOperationRecord.targetEmail`/`oldEmail` (`packages/identity/src/records.ts:18-54`, `packages/identity/src/email-operation-records.ts:26-56`). Required so the Mail worker can deliver; hashes own lookup/uniqueness. At-rest protection is delegated to the storage layer.

### F-05 — Email codes are deterministic HMAC outputs, not random values

- **Severity:** Informational
- **Status:** Accepted design — key-management dependency
- **Evidence:** `createHmacEmailCodeProtector` (`packages/identity/src/crypto.ts:80-162`) derives the code as `HMAC(secret, handleHash ‖ block) mod 10^8`. The stored verifier is separately domain-separated (`email-codes.ts:331-343`). Code secrecy rests entirely on the host-owned HMAC secret; compromise of the secret exposes all in-TTL codes. Minimum 32-byte secret enforced (`crypto.ts:83-92`); secret zeroed after key import (`crypto.ts:102`).
- **Positive observations (no action):** unbiased rejection sampling (`crypto.ts:104-127`), constant-time verifier compare (`crypto.ts:63-72`, `156-159`), 8-digit space bounded by `maxAttempts ≤ 10` + TTL ≤ 15 min (decoder invariants `email-operation-records.ts:245-247`) + dual rate limiters (`email-codes.ts:480-484`).

### F-06 — `finishAccountCreation` silently doubles as email sign-in for existing accounts

- **Severity:** Informational
- **Status:** Accepted design — host-policy dependency
- **Evidence:** When a code is verified for an email that already belongs to an active principal, `repair()` returns the existing user (`packages/identity/src/email-codes.ts:689-710`) and `finishAccountCreation` issues `VerifiedIdentityClaims` for that principal (`email-codes.ts:758-774`). The account-creation endpoint is therefore also a full sign-in endpoint.
- **Exploitability:** None beyond the intended mailbox-control-equals-sign-in model, but a host that treats "signup" as lower-risk than "login" (weaker rate limiting, no session policy, no anomaly detection on the creation route) would under-protect a sign-in path.
- **Recommendation:** State explicitly in the package README that the creation flow authenticates existing accounts and must carry the same endpoint policy as sign-in.

### F-07 — Timing side-channel distinguishes registered credential IDs

- **Severity:** Low
- **Status:** Accepted per threat model (credential IDs are not secrets)
- **Evidence:** `finishAuthentication` returns via `verificationFailed(claim)` before `verifyAuthenticationResponse` when the credential ID is unknown (`packages/identity/src/passkeys.ts:936-962`); a registered ID proceeds through signature verification, a measurably more expensive path.
- **Exploitability:** An attacker who already possesses a candidate credential ID can confirm its registration remotely. Credential IDs are random, non-enumerable authenticator outputs; the threat model (`docs/THREAT_MODEL.md:60`) explicitly treats them as non-secret. Residual value is negligible.

---

## Scan summary

**Scan completed:** 2026-07-28

### Scope covered

- All runtime source: `packages/identity/src/` (crypto, challenges, email-codes, email-operation-records, identity-mail, passkeys, users, records, email, validation, errors, index).
- Release toolchain: `scripts/release-package.mjs`, `.github/workflows/{ci,publish,codeql}.yml`.
- Documentation: `docs/THREAT_MODEL.md`, `docs/RELEASING.md`, `SECURITY.md`, both READMEs, `AGENTS.md`.
- Test suite (static review of pinned properties, not execution): `users.test.ts`, `email-codes.test.ts`, `passkeys.test.ts`, `webauthn-options.test.ts`, `azurite-harness.test.ts`, `test/azurite.ts`.
- Secret/pattern sweeps: no committed credentials, tokens, or private keys; no `eval`/`new Function`/`Math.random`/unsafe HTML sinks; `dist/` and `.env`-style files are git-untracked.

### Result

**No Critical, High, or Medium vulnerabilities found.** Seven findings logged: two Low (F-02 email-change freshness, F-07 credential-ID timing), one Low mitigated by documentation (F-01 privileged primitives), four Informational (F-03 attestation, F-04 PII at rest, F-05 deterministic codes, F-06 creation-as-sign-in).

### Verified strengths (spot-checked against code)

- Secrets at rest: codes/challenges stored only as keyed verifiers or domain-separated SHA-256 digests; raw values transient (`crypto.ts`, `challenges.ts:292-296`, `email-codes.ts:331-343`).
- Enumeration resistance: identical response shapes, durable suppression rows in the same transaction shape, decoy reads for unknown emails (`email-codes.ts:357-417`, `users.ts:404-410`, `469-473`); test-pinned (`email-codes.test.ts:641`, `:676`).
- Single-use semantics: optimistic conditional updates with post-write verification; exactly-one-winner race tests for code consumption, challenge claims, counter transitions, re-registration, and same-email creation (`email-codes.test.ts:513`, `passkeys.test.ts:705`, `:756`, `:1072`, `users.test.ts:178`).
- Counter regression: strict positive progression, durable `counter-pending` mirror transition (`passkeys.ts:322-333`, `989-1051`).
- Fail-closed decoding: every stored record passes strict codec invariants before use (`records.ts`, `email-operation-records.ts:237-290`).
- Input hardening: accessor/prototype/cycle/depth/size rejection before any use (`validation.ts:228-369`).
- Release chain: trusted-publisher OIDC with no token fallback, signed-tag verification against an allowed-signers file, receipt hash re-verification in the publish job, SHA-pinned actions, isolated npm config, exact dependency pins with SHA-512 provenance, packed-file allowlist (`publish.yml`, `scripts/release-package.mjs`).

### Suggested follow-ups (non-blocking)

1. README: one line stating `claimsFor`/`repairUserByEmail` are privileged alongside `provisionVerifiedUser` (F-01).
2. README: one line stating the account-creation flow authenticates existing accounts (F-06).
3. Threat model: one line recording that attestation is not verified (`attestationType: "none"`, F-03) so the acceptance is explicit.
