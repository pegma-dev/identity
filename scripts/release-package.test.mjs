import assert from "node:assert/strict";
import test from "node:test";

import {
  assertNormalReleaseVersion,
  isolatedPublicNpmEnvironment,
  parsePnpmLockfile,
  parsePnpmWorkspace,
} from "./release-package.mjs";

test("normal releases reject every stable version below 0.1.0", () => {
  for (const version of ["0.0.0", "0.0.1", "0.0.999"]) {
    assert.throws(
      () => assertNormalReleaseVersion(version),
      /at least 0\.1\.0/u,
    );
  }
  assert.doesNotThrow(() => assertNormalReleaseVersion("0.1.0"));
  assert.doesNotThrow(() => assertNormalReleaseVersion("1.0.0"));
});

test("pnpm workspace and lockfile parsers accept the reviewed format", () => {
  assert.deepEqual(parsePnpmWorkspace('packages:\n  - "packages/*"\n'), [
    "packages/*",
  ]);
  assert.throws(
    () => parsePnpmWorkspace("packages:\n  - ../escape\n"),
    /invalid/u,
  );

  const lock = parsePnpmLockfile(`lockfileVersion: '9.0'

importers:

  packages/identity:
    dependencies:
      '@pegma/mail':
        specifier: 0.1.1
        version: 0.1.1
      punycode:
        specifier: 2.3.1
        version: 2.3.1

packages:

  '@pegma/mail@0.1.1':
    resolution: {integrity: sha512-mailIntegrity==}

  punycode@2.3.1:
    resolution: {integrity: sha512-punyIntegrity==, tarball: https://registry.npmjs.org/punycode/-/punycode-2.3.1.tgz}

snapshots:
`);

  assert.equal(lock.lockfileVersion, "9.0");
  assert.deepEqual(lock.identitySpecifiers, {
    "@pegma/mail": "0.1.1",
    punycode: "2.3.1",
  });
  assert.match(lock.packagesBlock, /punycode@2\.3\.1/u);
});

test("release npm commands isolate and override hostile registry config", () => {
  const environment = isolatedPublicNpmEnvironment(
    {
      PATH: "kept",
      NPM_CONFIG_REGISTRY: "https://registry.attacker.invalid/",
      npm_config_userconfig: "/attacker/user.npmrc",
      npm_config_globalconfig: "/attacker/global.npmrc",
      npm_config_proxy: "https://proxy.attacker.invalid/",
    },
    "/isolated/user.npmrc",
    "/isolated/global.npmrc",
  );

  assert.deepEqual(environment, {
    PATH: "kept",
    NPM_CONFIG_REGISTRY: "https://registry.npmjs.org/",
    NPM_CONFIG_USERCONFIG: "/isolated/user.npmrc",
    NPM_CONFIG_GLOBALCONFIG: "/isolated/global.npmrc",
  });
});
