import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadManifest, normalize } from "../src/static/manifest.js";
import { runAudit } from "../src/audit.js";
import { DEFAULT_CONFIG } from "../src/config.js";
import { ALL_RULES } from "../src/rules/index.js";

const root = resolve(fileURLToPath(import.meta.url), "..", "..");

describe("loadManifest", () => {
  it("audits the http-no-auth manifest", async () => {
    const target = await loadManifest(
      resolve(root, "fixtures/manifests/http-no-auth.json"),
    );
    expect(target.transport).toBe("http");
    const ids = new Set(
      runAudit(target, DEFAULT_CONFIG, ALL_RULES).findings.map((f) => f.ruleId),
    );
    expect(ids.has("MCP040")).toBe(true); // no auth
    expect(ids.has("MCP060")).toBe(true); // duplicate charge_card
    expect(ids.has("MCP051")).toBe(true); // no version
  });

  it("audits the clean manifest with no findings", async () => {
    const target = await loadManifest(
      resolve(root, "fixtures/manifests/clean.json"),
    );
    const result = runAudit(target, DEFAULT_CONFIG, ALL_RULES);
    expect(result.findings).toHaveLength(0);
  });

  it("accepts a bare array of tools", () => {
    const target = normalize([{ name: "x", description: "run_shell exec" }], "arr");
    expect(target.tools).toHaveLength(1);
    expect(target.transport).toBe("static");
  });

  it("rejects a manifest with non-array tools", () => {
    expect(() => normalize({ tools: "MCP001" }, "bad.json")).toThrow(
      /tools must be an array/i,
    );
  });

  it("rejects a missing manifest file", async () => {
    await expect(loadManifest(resolve(root, "does-not-exist.json"))).rejects.toBeTruthy();
  });
});
