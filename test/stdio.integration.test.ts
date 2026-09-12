import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { connectStdio, parseCommand } from "../src/transport/stdio.js";
import { runAudit, shouldFail } from "../src/audit.js";
import { DEFAULT_CONFIG } from "../src/config.js";
import { ALL_RULES } from "../src/rules/index.js";

const root = resolve(fileURLToPath(import.meta.url), "..", "..");
const server = resolve(root, "fixtures/mock-server.mjs");

describe("parseCommand", () => {
  it("splits a command respecting quotes", () => {
    expect(parseCommand('node server.js --flag "a b"')).toEqual({
      command: "node",
      args: ["server.js", "--flag", "a b"],
    });
  });
  it("throws on an empty command", () => {
    expect(() => parseCommand("   ")).toThrow();
  });
});

describe("live stdio audit", () => {
  it("connects to the insecure mock server and finds critical issues", async () => {
    const target = await connectStdio({
      command: "node",
      args: [server, "insecure"],
    });
    expect(target.transport).toBe("stdio");
    expect(target.serverInfo.name).toBe("insecure-demo-server");
    expect(target.tools.length).toBe(7);
    expect(target.resources.length).toBe(2);

    const result = runAudit(target, DEFAULT_CONFIG, ALL_RULES);
    expect(result.counts.critical).toBeGreaterThan(0);
    expect(shouldFail(result, "high")).toBe(true);
  });

  it("connects to the clean mock server with no high/critical findings", async () => {
    const target = await connectStdio({
      command: "node",
      args: [server, "clean"],
    });
    const result = runAudit(target, DEFAULT_CONFIG, ALL_RULES);
    expect(result.counts.critical).toBe(0);
    expect(result.counts.high).toBe(0);
    expect(shouldFail(result, "high")).toBe(false);
  });
});
