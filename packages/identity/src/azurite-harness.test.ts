import { EventEmitter } from "node:events";
import type { ChildProcess } from "node:child_process";

import { describe, expect, it } from "vitest";

import { stopProcess } from "../../../test/azurite.js";
import { isLocalDevelopmentHostname } from "./validation.js";

describe("Azurite harness teardown", () => {
  it("force-kills after a bounded graceful wait and bounds the final wait", async () => {
    const signals: Array<NodeJS.Signals | number | undefined> = [];
    const process = Object.assign(new EventEmitter(), {
      exitCode: null,
      signalCode: null,
      kill(signal?: NodeJS.Signals | number) {
        signals.push(signal);
        return true;
      },
    }) as unknown as ChildProcess;

    await expect(stopProcess(process, 5, 5)).resolves.toBeUndefined();
    expect(signals).toEqual([undefined, "SIGKILL"]);
  });
});

describe("local development origins", () => {
  it("recognizes WHATWG's bracketed IPv6 loopback hostname", () => {
    const hostname = new URL("http://[::1]").hostname;

    expect(hostname).toBe("[::1]");
    expect(isLocalDevelopmentHostname(hostname)).toBe(true);
  });
});
