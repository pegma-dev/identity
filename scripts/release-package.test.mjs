import assert from "node:assert/strict";
import test from "node:test";

import {
  assertNormalReleaseVersion,
  isolatedPublicNpmEnvironment,
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
