import { describe, it, expect } from "vitest";
import { applyIgnores, runAudit } from "../src/audit.js";
import { normalizeConfig } from "../src/config.js";
import { ALL_RULES } from "../src/rules/index.js";
import { normalize } from "../src/static/manifest.js";
import { insecureSurface } from "../fixtures/surfaces.mjs";
import type { Finding } from "../src/types.js";

describe("applyIgnores", () => {
  const sample: Finding[] = [
    {
      ruleId: "MCP001",
      severity: "high",
      title: "Destructive tool",
      message: "no confirm",
      remediation: "add confirm",
      location: "delete_file",
    },
    {
      ruleId: "MCP002",
      severity: "critical",
      title: "Exec",
      message: "shell",
      remediation: "scope",
      location: "run_shell",
    },
  ];

  it("suppresses findings when ignore matches location", () => {
    const filtered = applyIgnores(sample, ["delete_file"]);
    expect(filtered.map((f) => f.ruleId)).toEqual(["MCP002"]);
  });

  it("suppresses findings when ignore matches rule id", () => {
    const filtered = applyIgnores(sample, ["MCP001"]);
    expect(filtered.map((f) => f.ruleId)).toEqual(["MCP002"]);
  });
});

describe("runAudit ignore by rule id", () => {
  it("suppresses MCP001 findings when ignore lists the rule id", () => {
    const target = normalize(insecureSurface, "insecure");
    const config = normalizeConfig({ ignore: ["MCP001"] });
    const result = runAudit(target, config, ALL_RULES);
    expect(result.findings.some((f) => f.ruleId === "MCP001")).toBe(false);
    expect(result.findings.some((f) => f.ruleId === "MCP002")).toBe(true);
  });
});
