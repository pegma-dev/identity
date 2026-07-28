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
const PACKAGE_MANAGER = "npm@11.18.0";
const NODE_RANGE = ">=22";
const REQUIRED_DEPENDENCIES = {
  "@pegma/rate-limit": "0.1.0",
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
    env: process.env,
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
  const npmExecPath = process.env.npm_execpath;
  if (npmExecPath !== undefined) {
    return run(process.execPath, [npmExecPath, ...arguments_], options);
  }
  return run(process.platform === "win32" ? "npm.cmd" : "npm", arguments_, {
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
  const lock = await readJson(join(root, "package-lock.json"));
  const lockEntry = lock.packages?.[PACKAGE_DIRECTORY];
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
    !sameJson(rootManifest.workspaces, ["packages/*"])
  ) {
    fail("the private root workspace metadata is invalid");
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
    !sameJson(lockEntry?.dependencies, REQUIRED_DEPENDENCIES)
  ) {
    fail("runtime dependencies must match the reviewed exact pins");
  }
  if (
    lockEntry?.name !== PACKAGE_NAME ||
    lockEntry.version !== manifest.version ||
    manifest.scripts?.prepack !== "npm run build" ||
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
  return { manifest, lockEntry };
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

async function smokeImport(tarball) {
  const workspace = await mkdtemp(join(tmpdir(), "pegma-identity-consumer-"));
  try {
    await writeFile(
      join(workspace, "package.json"),
      JSON.stringify({ private: true, type: "module" }),
    );
    runNpm(["install", "--ignore-scripts", "--no-audit", tarball], {
      cwd: workspace,
    });
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
  runNpm(["audit", "--omit=dev", "--audit-level=high"], { cwd: root });
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
    ["pack", `./${PACKAGE_DIRECTORY}`, "--json", "--pack-destination", output],
    { cwd: root, capture: true },
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
  await smokeImport(tarball);
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
  const result = runNpm(
    [
      "view",
      `${receipt.package}@${receipt.version}`,
      "dist.integrity",
      "--json",
    ],
    { cwd: root, capture: true, allowFailure: true },
  );
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
  if (receipt.version === "0.0.0") {
    fail("the trusted-publisher workflow refuses the manual bootstrap version");
  }
  runNpm(["publish", tarball, "--access", "public", "--provenance"], {
    cwd: root,
  });
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
    default:
      fail("expected check, pack, publish, or registry-check");
  }
}

await main();
