import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const TABLE_PORT = 10115;

let child: ChildProcess | undefined;
let workspace: string | undefined;

function terminated(process: ChildProcess): boolean {
  return process.exitCode !== null || process.signalCode !== null;
}

function waitForTermination(
  process: ChildProcess,
  timeoutMilliseconds: number,
): Promise<boolean> {
  if (terminated(process)) {
    return Promise.resolve(true);
  }
  return new Promise((resolve) => {
    let settled = false;
    const finish = (didTerminate: boolean) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      process.off("exit", onTermination);
      process.off("close", onTermination);
      resolve(didTerminate);
    };
    const onTermination = () => finish(true);
    const timer = setTimeout(
      () => finish(terminated(process)),
      timeoutMilliseconds,
    );
    process.once("exit", onTermination);
    process.once("close", onTermination);
    if (terminated(process)) {
      finish(true);
    }
  });
}

function portAccepting(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = connect({ host: "127.0.0.1", port });
    const settle = (accepting: boolean) => {
      socket.destroy();
      resolve(accepting);
    };
    socket.once("connect", () => settle(true));
    socket.once("error", () => settle(false));
    socket.setTimeout(1_000, () => settle(false));
  });
}

async function waitForStartup(
  process: ChildProcess,
  port: number,
): Promise<void> {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (process.exitCode !== null) {
      throw new Error(`Azurite exited with code ${process.exitCode}.`);
    }
    if (await portAccepting(port)) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Azurite did not start listening on port ${port}.`);
}

export async function stopProcess(
  instance: ChildProcess,
  gracefulTimeoutMilliseconds = 5_000,
  forcedTimeoutMilliseconds = 1_000,
): Promise<void> {
  if (terminated(instance)) {
    return;
  }
  instance.kill();
  if (!(await waitForTermination(instance, gracefulTimeoutMilliseconds))) {
    instance.kill("SIGKILL");
    await waitForTermination(instance, forcedTimeoutMilliseconds);
  }
}

export async function setup(): Promise<void> {
  const entry = join(
    process.cwd(),
    "node_modules",
    "azurite",
    "dist",
    "src",
    "table",
    "main.js",
  );
  if (!existsSync(entry)) {
    throw new Error(`Azurite is missing at ${entry}. Run 'npm ci' first.`);
  }
  workspace = await mkdtemp(join(tmpdir(), "pegma-identity-azurite-"));
  child = spawn(
    process.execPath,
    [
      entry,
      "--location",
      workspace,
      "--silent",
      "--tableHost",
      "127.0.0.1",
      "--tablePort",
      String(TABLE_PORT),
    ],
    { stdio: "ignore" },
  );
  await waitForStartup(child, TABLE_PORT);
}

export async function teardown(): Promise<void> {
  const running = child;
  child = undefined;
  if (running !== undefined) {
    await stopProcess(running);
  }
  const directory = workspace;
  workspace = undefined;
  if (directory !== undefined) {
    await rm(directory, {
      force: true,
      recursive: true,
      maxRetries: 5,
      retryDelay: 100,
    });
  }
}
