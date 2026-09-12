import { describe, it, expect } from "vitest";
import { runAudit } from "../src/audit.js";
import { DEFAULT_CONFIG } from "../src/config.js";
import { ALL_RULES } from "../src/rules/index.js";
import { normalize } from "../src/static/manifest.js";
import { renderJson } from "../src/reporters/json.js";
import { renderSarif } from "../src/reporters/sarif.js";
import { renderTerminal } from "../src/reporters/terminal.js";
import { insecureSurface } from "../fixtures/surfaces.mjs";

const result = runAudit(
  normalize(insecureSurface, "insecure"),
  DEFAULT_CONFIG,
  ALL_RULES,
);

describe("json reporter", () => {
  it("emits parseable JSON with findings and summary", () => {
    const doc = JSON.parse(renderJson(result));
    expect(doc.tool).toBe("mcp-audit");
    expect(doc.findings.length).toBe(result.findings.length);
    expect(doc.summary.critical).toBeGreaterThan(0);
    expect(doc.target.counts.tools).toBe(7);
  });
});

describe("sarif reporter", () => {
  const sarif = JSON.parse(renderSarif(result, ALL_RULES));

  it("is a valid SARIF 2.1.0 skeleton", () => {
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe("mcp-audit");
  });

  it("declares every referenced rule exactly once", () => {
    const declared = sarif.runs[0].tool.driver.rules.map(
      (r: { id: string }) => r.id,
    );
    const referenced = new Set(
      sarif.runs[0].results.map((r: { ruleId: string }) => r.ruleId),
    );
    expect(new Set(declared).size).toBe(declared.length);
    for (const id of referenced) expect(declared).toContain(id);
  });

  it("carries a security-severity score for code scanning", () => {
    for (const rule of sarif.runs[0].tool.driver.rules) {
      expect(rule.properties["security-severity"]).toBeDefined();
    }
  });
});

describe("terminal reporter", () => {
  it("groups findings and prints a summary", () => {
    const text = renderTerminal(result, { color: false });
    expect(text).toContain("CRITICAL");
    expect(text).toContain("MCP002");
    expect(text).toMatch(/\d+ findings/);
  });
  it("disables ANSI colors without mutating the environment", () => {
    const previous = process.env.NO_COLOR;
    try {
      delete process.env.NO_COLOR;
      const text = renderTerminal(result, { color: false });
      expect(text).not.toMatch(/\u001b\[/);
      expect(process.env.NO_COLOR).toBeUndefined();
    } finally {
      if (previous === undefined) delete process.env.NO_COLOR;
      else process.env.NO_COLOR = previous;
    }
  });

  it("reports a clean audit", () => {
    const clean = runAudit(
      normalize({ tools: [], server: { name: "empty", version: "1.0.0" } }, "empty"),
      DEFAULT_CONFIG,
      ALL_RULES,
    );
    expect(renderTerminal(clean, { color: false })).toContain("No findings");
  });
});
