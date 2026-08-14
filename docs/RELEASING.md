# Release operations

No package is published merely by merging a pull request. Normal releases use
the hardened GitHub release workflow, npm trusted publishing, provenance, and
a protected signed annotated tag already on `origin/main`.

## Release invariants

The release tool verifies the single public workspace, stable package version,
exact runtime pins, matching pnpm lockfile, package metadata, package-local
README and LICENSE, prepack build, test exclusion, dist-only allowlist,
exports, and a production dependency audit. Every direct runtime lock entry
must carry SHA-512 integrity and public-registry provenance. Release commands
discard
inherited npm configuration, use isolated temporary config files, and pass the
public registry explicitly. Packing builds once, checks the complete file
inventory and hashes, and imports the package from a clean consumer
installation.

The prepared `package-manifest.json` records the source commit, optional
release tag, tarball filename, SHA-1, SHA-512 integrity, and packed files.
`release:registry:check` revalidates those local bytes before comparing their
exact integrity with npm. Only npm `E404` means `absent`; an existing different
artifact or another registry failure stops the ceremony.

## One-time `0.0.0` package-name bootstrap

This ceremony completed on 2026-07-28. The signed annotated `v0.0.0` tag
points to reviewed commit `9aa61e7ee87b93e7e34c49807ee2e448f368c78d`.
The exact artifact is published under `bootstrap` with integrity
`sha512-99rC2I3qlDUhdb/qYxwgVRoSIELKl5yyqhij7yy/FmrEe+hJuOMIaylAyR7D7rzliNVyoR+5f6PhworvZAx9QA==`.
It reserves the npm name and is not an advertised production release. The
commands below are retained as the historical, non-repeatable receipt; never
reuse or republish `0.0.0`.

From a clean checkout of the exact reviewed `origin/main` commit, use Node 24
and the reviewed npm version:

```sh
git fetch origin
git switch --detach origin/main
npm install --global npm@11.18.0
npm ci --registry https://registry.npmjs.org/
npm run format:check
npm run check
npm test
npm audit --omit=dev --audit-level=high
npm run release:pack -- -- --require-clean --require-main-ancestor --output .release
npm run release:registry:check -- -- --manifest .release/package-manifest.json
```

Before that one-time publication, the registry check reported
`@pegma/identity@0.0.0: absent`. The preserved release receipt subsequently
reported `exact`. Do not repack between review, tagging, and publication.

After confirming the repository `v*` ruleset blocks tag updates and deletion
and restricts creation to the release maintainer, create the signed annotated
source tag:

```sh
git config gpg.format ssh
git config user.signingkey ~/.ssh/pegma-release-signing-key
git config gpg.ssh.allowedSignersFile ~/.config/pegma/release-allowed-signers
git tag --sign v0.0.0 --message "Identity bootstrap v0.0.0" HEAD
git verify-tag v0.0.0
git rev-parse HEAD
git rev-parse "v0.0.0^{commit}"
git push origin refs/tags/v0.0.0
git fetch origin tag v0.0.0 --force
git verify-tag v0.0.0
```

Both commit IDs must equal the receipt's `gitCommit`. Authenticate the human
npm operator with current interactive requirements and publish only the
reviewed tarball under `bootstrap`:

```sh
npm publish .release/pegma-identity-0.0.0.tgz --access public --tag bootstrap --registry https://registry.npmjs.org/
npm run release:registry:check -- -- --manifest .release/package-manifest.json
npm dist-tag ls @pegma/identity
```

The second registry check reported `exact`. Never unpublish and reuse a
version. Do not add an npm token.

Trusted publishing for normal releases is configured for:

- organization or user: `pegma-dev`
- repository: `identity`
- workflow: `publish.yml`
- environment: `npm-publish`
- allowed action: `npm publish` only

The matching GitHub environment supplies the reviewed
`RELEASE_ALLOWED_SIGNERS` SSH allowed-signers entry. The normal workflow
deliberately refuses `0.0.0`.

## Normal release

A release pull request updates the root, package, and `pnpm-lock.yaml`
versions, status documentation, and release notes, then passes the complete
gate on Node 22 and 24. After merge, create and verify a protected signed
annotated tag on the exact `origin/main` commit:

```sh
git fetch origin
git switch --detach origin/main
git tag --sign v0.1.0 --message "Identity v0.1.0" HEAD
git verify-tag v0.1.0
git push origin refs/tags/v0.1.0
git fetch origin tag v0.1.0 --force
git verify-tag v0.1.0
gh release create v0.1.0 --verify-tag --title "v0.1.0"
```

The workflow rejects prerelease events, tag/version mismatches, and every
normal package version below `0.1.0` immediately after checkout, before
fetching the protected branch or installing anything. CI and preparation use
Corepack to activate the reviewed `packageManager`, an isolated npm user
config, and an explicit public-registry override; the release tool repeats
that isolation for audit, clean-consumer install, registry comparison, and
publish. Registry publish remains `npm publish` so trusted-publisher OIDC
keeps its configured allowed action.

The unprivileged preparation job verifies the signed tag, release-event
commit, main ancestry, full gate, production audit, package inventory,
consumer import, and hashes. It activates the reviewed pnpm via Corepack and
installs the reviewed `npm@11.18.0` for pack, registry view, and the trusted
publishing version gate. Only the environment-scoped publish job receives
OIDC authority; it installs no workspace dependencies, does not download
Corepack pnpm, and publishes the downloaded prepared artifact with
`node scripts/release-package.mjs publish`.
