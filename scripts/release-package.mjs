import { spawnSync } from "node:child_process";
import { createHash, timingSafeEqual } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const PACKAGE_NAME = "@pegma/identity";
const PACKAGE_DIRECTORY = "packages/identity";
const REPOSITORY_URL = "git+https://github.com/pegma-dev/identity.git";
const PACKAGE_MANAGER = "pnpm@10.34.5";
const PNPM_LOCKFILE_VERSION = "9.0";
const WORKSPACE_GLOBS = ["packages/*"];
const NODE_RANGE = ">=22";
const PUBLIC_REGISTRY = "https://registry.npmjs.org/";
const REQUIRED_DEPENDENCIES = {
  "@pegma/mail": "0.1.1",
  "@pegma/rate-limit": "0.2.0",
  "@pegma/spine": "0.1.1",
  "@pegma/storage-core": "0.4.0",
  "@simplewebauthn/server": "13.3.2",
  punycode: "2.3.1",
  tr46: "6.0.0",
  "unicode-case-folding": "1.1.1",
  unorm: "1.6.0",
};
const ALLOWED_STATIC_FILES = new Set(["LICENSE", "README.md", "package.json"]);

function fail(message) {
  throw new Error(message);
}

function run(command, arguments_, options = {}) {
  const result = spawnSync(command, arguments_, {
    cwd: options.cwd,
    encoding: "utf8",
    env: options.env ?? process.env,
    shell: options.shell ?? false,
    stdio: options.capture ? "pipe" : "inherit",
  });
  if (result.error !== undefined) {
    throw result.error;
  }
  if (result.status !== 0 && !options.allowFailure) {
    fail(
      `${command} ${arguments_.join(" ")} failed${
        options.capture ? `:\n${result.stderr}` : ""
      }`,
    );
  }
  return result;
}

function runNpm(arguments_, options = {}) {
  return run(process.platform === "win32" ? "npm.cmd" : "npm", arguments_, {
    ...options,
    shell: process.platform === "win32",
  });
}

function runPnpm(arguments_, options = {}) {
  return run(process.platform === "win32" ? "pnpm.cmd" : "pnpm", arguments_, {
    ...options,
    shell: process.platform === "win32",
  });
}

function defaultRoot() {
  return resolve(fileURLToPath(new URL("..", import.meta.url)));
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function parsePnpmWorkspace(text) {
  const packages = [];
  const lines = text.split(/\r?\n/u);
  if (lines[0] !== "packages:") {
    fail("pnpm-workspace.yaml is invalid");
  }
  for (const line of lines.slice(1)) {
    if (line === "") {
      continue;
    }
    const match = /^  - ["']([^"']+)["']$/u.exec(line);
    if (match === null) {
      fail("pnpm-workspace.yaml is invalid");
    }
    packages.push(match[1]);
  }
  if (packages.length === 0) {
    fail("pnpm-workspace.yaml is invalid");
  }
  return packages;
}

function parseResolutionMapping(body) {
  const fields = {};
  for (const part of body.split(",")) {
    const match = /^\s*([A-Za-z][A-Za-z0-9]*)\s*:\s*(.+?)\s*$/u.exec(part);
    if (match === null) {
      fail("pnpm-lock.yaml resolution mapping is invalid");
    }
    let value = match[2];
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    fields[match[1]] = value;
  }
  return fields;
}

export function parsePnpmLockfile(text) {
  const version = /^lockfileVersion:\s*['"]([^'"]+)['"]\s*$/mu.exec(text);
  if (version === null) {
    fail("pnpm-lock.yaml is missing lockfileVersion");
  }

  const importerMatch =
    /^  packages\/identity:\n    dependencies:\n((?:      .+\n)+)/mu.exec(text);
  if (importerMatch === null) {
    fail("pnpm-lock.yaml is missing packages/identity dependencies");
  }

  const specifiers = {};
  const entryPattern =
    /^      ('[^']+'|[A-Za-z0-9@/._-]+):\n        specifier: (\S+)\n        version: (\S+)$/gmu;
  let entry;
  while ((entry = entryPattern.exec(importerMatch[1])) !== null) {
    let name = entry[1];
    if (name.startsWith("'") && name.endsWith("'")) {
      name = name.slice(1, -1);
    }
    specifiers[name] = entry[2];
  }
  if (Object.keys(specifiers).length === 0) {
    fail("pnpm-lock.yaml packages/identity dependencies are empty");
  }

  const packagesMatch = /^packages:\n\n([\s\S]*?)\n(?=snapshots:\n)/mu.exec(
    text,
  );
  if (packagesMatch === null) {
    fail("pnpm-lock.yaml is missing the packages catalog");
  }

  return {
    lockfileVersion: version[1],
    identitySpecifiers: specifiers,
    packagesBlock: packagesMatch[1],
  };
}

function directDependencyLockEntry(lock, name, version) {
  const key = `${name}@${version}`;
  const pattern = new RegExp(
    `^  (?:'${escapeRegExp(key)}'|${escapeRegExp(key)}):\n    resolution: \\{([^}\\n]+)\\}`,
    "mu",
  );
  const match = pattern.exec(lock.packagesBlock);
  if (match === null) {
    return undefined;
  }
  return parseResolutionMapping(match[1]);
}

function assertPublicRegistryLockEntry(name, version, dependency) {
  const fields = dependency === undefined ? [] : Object.keys(dependency);
  if (
    dependency === undefined ||
    typeof dependency.integrity !== "string" ||
    !dependency.integrity.startsWith("sha512-") ||
    fields.some((field) => field !== "integrity" && field !== "tarball") ||
    (dependency.tarball !== undefined &&
      !dependency.tarball.startsWith(PUBLIC_REGISTRY))
  ) {
    fail(
      `direct runtime dependency ${name}@${version} lacks public-registry provenance`,
    );
  }
}

async function assertAbsentLockfile(root, filename) {
  try {
    await stat(join(root, filename));
  } catch (error) {
    if (error?.code === "ENOENT") {
      return;
    }
    throw error;
  }
  fail(`${filename} must not be present`);
}

export function isolatedPublicNpmEnvironment(
  environment,
  userConfig,
  globalConfig,
) {
  const isolated = {};
  for (const [name, value] of Object.entries(environment)) {
    if (!name.toLowerCase().startsWith("npm_config_")) {
      isolated[name] = value;
    }
  }
  isolated.NPM_CONFIG_REGISTRY = PUBLIC_REGISTRY;
  isolated.NPM_CONFIG_USERCONFIG = userConfig;
  isolated.NPM_CONFIG_GLOBALCONFIG = globalConfig;
  return isolated;
}

async function publicNpmConfiguration() {
  const directory = await mkdtemp(join(tmpdir(), "pegma-identity-npm-"));
  const userConfig = join(directory, "user.npmrc");
  const globalConfig = join(directory, "global.npmrc");
  await writeFile(userConfig, `registry=${PUBLIC_REGISTRY}\n`);
  await writeFile(globalConfig, "");
  return {
    environment: isolatedPublicNpmEnvironment(
      process.env,
      userConfig,
      globalConfig,
    ),
    async dispose() {
      await rm(directory, { force: true, recursive: true });
    },
  };
}

function publicRegistryArguments(arguments_) {
  return [...arguments_, "--registry", PUBLIC_REGISTRY];
}

export function assertNormalReleaseVersion(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)$/u.exec(version);
  if (match === null || (Number(match[1]) === 0 && Number(match[2]) === 0)) {
    fail("normal releases require a stable package version of at least 0.1.0");
  }
}

function safeEqual(left, right) {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return (
    leftBytes.length === rightBytes.length &&
    timingSafeEqual(leftBytes, rightBytes)
  );
}

function hashes(bytes) {
  return {
    integrity: `sha512-${createHash("sha512").update(bytes).digest("base64")}`,
    shasum: createHash("sha1").update(bytes).digest("hex"),
  };
}

function valueAfter(arguments_, name) {
  const index = arguments_.indexOf(name);
  if (index === -1) {
    return undefined;
  }
  const value = arguments_[index + 1];
  if (value === undefined || value.startsWith("--")) {
    fail(`${name} requires a value`);
  }
  return value;
}

function has(arguments_, name) {
  return arguments_.includes(name);
}

function git(root, arguments_, options = {}) {
  return run("git", arguments_, { cwd: root, ...options });
}

function currentCommit(root) {
  return git(root, ["rev-parse", "HEAD"], { capture: true }).stdout.trim();
}

function assertGitRequirements(root, arguments_) {
  const commit = currentCommit(root);
  const expected = valueAfter(arguments_, "--expected-release-commit");
  if (expected !== undefined && !safeEqual(commit, expected)) {
    fail(`HEAD ${commit} is not expected release commit ${expected}`);
  }
  if (has(arguments_, "--require-clean")) {
    const status = git(root, ["status", "--porcelain"], {
      capture: true,
    }).stdout;
    if (status.trim() !== "") {
      fail("the release worktree is not clean");
    }
  }
  if (has(arguments_, "--require-main-ancestor")) {
    git(root, ["merge-base", "--is-ancestor", commit, "origin/main"], {
      capture: true,
    });
  }
  if (has(arguments_, "--require-release-tag")) {
    const tag = git(root, ["describe", "--tags", "--exact-match", commit], {
      capture: true,
    }).stdout.trim();
    git(root, ["verify-tag", tag], { capture: true });
    if (!/^v\d+\.\d+\.\d+$/u.test(tag)) {
      fail(`release tag ${tag} is not a stable version tag`);
    }
    if (
      process.env.RELEASE_TAG !== undefined &&
      !safeEqual(tag, process.env.RELEASE_TAG)
    ) {
      fail(
        `checked-out tag ${tag} is not release event tag ${process.env.RELEASE_TAG}`,
      );
    }
    return { commit, tag };
  }
  return { commit, tag: null };
}

export async function validateRepository(root = defaultRoot()) {
  const rootManifest = await readJson(join(root, "package.json"));
  const manifest = await readJson(
    join(root, PACKAGE_DIRECTORY, "package.json"),
  );
  const workspace = parsePnpmWorkspace(
    await readFile(join(root, "pnpm-workspace.yaml"), "utf8"),
  );
  const lock = parsePnpmLockfile(
    await readFile(join(root, "pnpm-lock.yaml"), "utf8"),
  );
  await assertAbsentLockfile(root, "package-lock.json");
  await assertAbsentLockfile(root, "yarn.lock");
  const packageDirectories = (
    await readdir(join(root, "packages"), { withFileTypes: true })
  )
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();

  if (
    rootManifest.name !== "identity" ||
    rootManifest.private !== true ||
    rootManifest.packageManager !== PACKAGE_MANAGER ||
    !sameJson(workspace, WORKSPACE_GLOBS)
  ) {
    fail("the private root workspace metadata is invalid");
  }
  if (lock.lockfileVersion !== PNPM_LOCKFILE_VERSION) {
    fail("pnpm-lock.yaml lockfileVersion is not the reviewed format");
  }
  if (!sameJson(packageDirectories, ["identity"])) {
    fail("the public workspace inventory must contain only packages/identity");
  }
  if (
    manifest.name !== PACKAGE_NAME ||
    !/^\d+\.\d+\.\d+$/u.test(manifest.version) ||
    manifest.private === true ||
    manifest.license !== "MIT" ||
    manifest.type !== "module" ||
    manifest.sideEffects !== false ||
    manifest.publishConfig?.access !== "public" ||
    manifest.engines?.node !== NODE_RANGE ||
    manifest.repository?.type !== "git" ||
    manifest.repository?.url !== REPOSITORY_URL ||
    manifest.repository?.directory !== PACKAGE_DIRECTORY
  ) {
    fail(`${PACKAGE_DIRECTORY}/package.json has invalid public metadata`);
  }
  if (
    !sameJson(manifest.dependencies, REQUIRED_DEPENDENCIES) ||
    !sameJson(lock.identitySpecifiers, REQUIRED_DEPENDENCIES)
  ) {
    fail("runtime dependencies must match the reviewed exact pins");
  }
  for (const [name, version] of Object.entries(REQUIRED_DEPENDENCIES)) {
    assertPublicRegistryLockEntry(
      name,
      version,
      directDependencyLockEntry(lock, name, version),
    );
  }
  if (
    manifest.scripts?.prepack !== "pnpm run build" ||
    !sameJson(manifest.files, [
      "dist/**/*.d.ts",
      "dist/**/*.d.ts.map",
      "dist/**/*.js",
      "dist/**/*.js.map",
    ]) ||
    !sameJson(Object.keys(manifest.exports), ["."])
  ) {
    fail("package build, file allowlist, or exports are invalid");
  }
  const tsconfig = await readJson(
    join(root, PACKAGE_DIRECTORY, "tsconfig.json"),
  );
  if (!tsconfig.exclude?.includes("src/**/*.test.ts")) {
    fail("the package tsconfig must exclude source tests");
  }
  for (const required of ["README.md", "LICENSE"]) {
    const metadata = await stat(join(root, PACKAGE_DIRECTORY, required));
    if (!metadata.isFile()) {
      fail(`${PACKAGE_DIRECTORY}/${required} is required`);
    }
  }
  return { manifest, lock };
}

function validatePackedFiles(files) {
  if (files.length === 0) {
    fail("npm pack returned an empty package");
  }
  for (const path of files) {
    if (
      !ALLOWED_STATIC_FILES.has(path) &&
      !/^dist\/.+\.(?:d\.ts|d\.ts\.map|js|js\.map)$/u.test(path)
    ) {
      fail(`unexpected packed file ${path}`);
    }
    if (path.includes(".test.") || path.startsWith("src/")) {
      fail(`test or source file escaped into the package: ${path}`);
    }
  }
  for (const required of ALLOWED_STATIC_FILES) {
    if (!files.includes(required)) {
      fail(`packed package is missing ${required}`);
    }
  }
  if (!files.includes("dist/index.js") || !files.includes("dist/index.d.ts")) {
    fail("packed package is missing its public export");
  }
}

async function smokeImport(tarball, npmEnvironment) {
  const workspace = await mkdtemp(join(tmpdir(), "pegma-identity-consumer-"));
  try {
    await writeFile(
      join(workspace, "package.json"),
      JSON.stringify({ private: true, type: "module" }),
    );
    runNpm(
      publicRegistryArguments([
        "install",
        "--ignore-scripts",
        "--no-audit",
        tarball,
      ]),
      {
        cwd: workspace,
        env: npmEnvironment,
      },
    );
    run(
      process.execPath,
      [
        "--input-type=module",
        "--eval",
        `const module = await import(${JSON.stringify(PACKAGE_NAME)});
         if (typeof module.createIdentity !== "function") process.exit(1);
         if (module.normalizeEmail("xs@example.test") !== "xs@example.test") process.exit(1);
         let rejected = false;
         try { module.normalizeEmail("x\\uA7F1@example.test"); } catch { rejected = true; }
         if (!rejected) process.exit(1);`,
      ],
      { cwd: workspace },
    );
  } finally {
    await rm(workspace, { force: true, recursive: true });
  }
}

async function pack(root, arguments_) {
  const { manifest } = await validateRepository(root);
  const source = assertGitRequirements(root, arguments_);
  if (source.tag !== null && source.tag !== `v${manifest.version}`) {
    fail(
      `release tag ${source.tag} does not match package version ${manifest.version}`,
    );
  }
  const npmConfiguration = await publicNpmConfiguration();
  try {
    runPnpm(
      publicRegistryArguments(["audit", "--prod", "--audit-level=high"]),
      {
        cwd: root,
        env: npmConfiguration.environment,
      },
    );
    const output = resolve(
      root,
      valueAfter(arguments_, "--output") ?? ".release",
    );
    if (
      output !== root &&
      !output.startsWith(`${root}\\`) &&
      !output.startsWith(`${root}/`)
    ) {
      fail("release output must remain inside the repository");
    }
    await mkdir(output, { recursive: true });
    if ((await readdir(output)).length !== 0) {
      fail(`release output ${output} must be empty`);
    }
    const packed = runNpm(
      publicRegistryArguments([
        "pack",
        `./${PACKAGE_DIRECTORY}`,
        "--json",
        "--pack-destination",
        output,
      ]),
      {
        cwd: root,
        capture: true,
        env: npmConfiguration.environment,
      },
    );
    const entries = JSON.parse(packed.stdout);
    if (!Array.isArray(entries) || entries.length !== 1) {
      fail("npm pack did not report exactly one package");
    }
    const entry = entries[0];
    const files = entry.files.map(({ path }) => path).sort();
    validatePackedFiles(files);
    const tarball = join(output, basename(entry.filename));
    const bytes = await readFile(tarball);
    const digest = hashes(bytes);
    if (
      !safeEqual(digest.integrity, entry.integrity) ||
      !safeEqual(digest.shasum, entry.shasum)
    ) {
      fail("local tarball hashes disagree with npm pack");
    }
    await smokeImport(tarball, npmConfiguration.environment);
    const receipt = {
      package: PACKAGE_NAME,
      version: manifest.version,
      gitCommit: source.commit,
      releaseTag: source.tag,
      tarball: basename(tarball),
      ...digest,
      files,
    };
    await writeFile(
      join(output, "package-manifest.json"),
      `${JSON.stringify(receipt, null, 2)}\n`,
    );
    console.log(`Prepared ${PACKAGE_NAME}@${manifest.version} at ${tarball}`);
  } finally {
    await npmConfiguration.dispose();
  }
}

async function readAndVerifyReceipt(root, arguments_) {
  const manifestPath = resolve(
    root,
    valueAfter(arguments_, "--manifest") ?? ".release/package-manifest.json",
  );
  const receipt = await readJson(manifestPath);
  if (
    receipt.package !== PACKAGE_NAME ||
    !/^\d+\.\d+\.\d+$/u.test(receipt.version) ||
    typeof receipt.gitCommit !== "string" ||
    typeof receipt.tarball !== "string" ||
    basename(receipt.tarball) !== receipt.tarball
  ) {
    fail("release receipt is malformed");
  }
  const expected = valueAfter(arguments_, "--expected-release-commit");
  if (expected !== undefined && !safeEqual(receipt.gitCommit, expected)) {
    fail("release receipt commit does not match the release event");
  }
  const tarball = join(resolve(manifestPath, ".."), receipt.tarball);
  const digest = hashes(await readFile(tarball));
  if (
    !safeEqual(digest.integrity, receipt.integrity) ||
    !safeEqual(digest.shasum, receipt.shasum)
  ) {
    fail("prepared tarball no longer matches its receipt");
  }
  return { receipt, tarball };
}

async function registryCheck(root, arguments_) {
  const { receipt } = await readAndVerifyReceipt(root, arguments_);
  const npmConfiguration = await publicNpmConfiguration();
  let result;
  try {
    result = runNpm(
      publicRegistryArguments([
        "view",
        `${receipt.package}@${receipt.version}`,
        "dist.integrity",
        "--json",
      ]),
      {
        cwd: root,
        capture: true,
        allowFailure: true,
        env: npmConfiguration.environment,
      },
    );
  } finally {
    await npmConfiguration.dispose();
  }
  if (result.status !== 0) {
    if (/\bE404\b/u.test(`${result.stdout}\n${result.stderr}`)) {
      console.log(`${receipt.package}@${receipt.version}: absent`);
      return;
    }
    fail(`npm registry lookup failed:\n${result.stderr}`);
  }
  const registryIntegrity = JSON.parse(result.stdout);
  if (!safeEqual(registryIntegrity, receipt.integrity)) {
    fail(`${receipt.package}@${receipt.version}: different`);
  }
  console.log(`${receipt.package}@${receipt.version}: exact`);
}

async function publish(root, arguments_) {
  const { receipt, tarball } = await readAndVerifyReceipt(root, arguments_);
  assertNormalReleaseVersion(receipt.version);
  const npmConfiguration = await publicNpmConfiguration();
  try {
    runNpm(
      publicRegistryArguments([
        "publish",
        tarball,
        "--access",
        "public",
        "--provenance",
      ]),
      {
        cwd: root,
        env: npmConfiguration.environment,
      },
    );
  } finally {
    await npmConfiguration.dispose();
  }
}

async function normalReleaseCheck(root, arguments_) {
  const { manifest } = await validateRepository(root);
  assertNormalReleaseVersion(manifest.version);
  const source = assertGitRequirements(root, arguments_);
  if (
    process.env.RELEASE_PRERELEASE !== "false" ||
    process.env.RELEASE_TAG !== `v${manifest.version}`
  ) {
    fail("the release event does not match the stable package version");
  }
  return source;
}

async function main() {
  const root = defaultRoot();
  const command = process.argv[2];
  const arguments_ = process.argv.slice(3).filter((value) => value !== "--");
  switch (command) {
    case "check":
      await validateRepository(root);
      console.log("Release metadata is valid.");
      break;
    case "pack":
      await pack(root, arguments_);
      break;
    case "publish":
      await publish(root, arguments_);
      break;
    case "registry-check":
      await registryCheck(root, arguments_);
      break;
    case "normal-release-check":
      await normalReleaseCheck(root, arguments_);
      console.log("Normal release metadata is valid.");
      break;
    default:
      fail(
        "expected check, pack, publish, registry-check, or normal-release-check",
      );
  }
}

if (
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  await main();
}
