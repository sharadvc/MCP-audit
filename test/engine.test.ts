import { describe, it, expect } from "vitest";
import { Engine, exceedsThreshold } from "../src/engine/engine.js";
import type { Finding, Rule } from "../src/types.js";
import { makeTarget } from "./helpers.js";

function rule(id: string, sev: Finding["severity"], emit = true): Rule {
  return {
    id,
    title: `rule ${id}`,
    description: "test rule",
    severity: sev,
    category: "hygiene",
    evaluate: (_t, ctx) =>
      emit
        ? [ctx.report({ title: id, message: "m", remediation: "r", location: id })]
        : [],
  };
}

describe("Engine", () => {
  it("runs all rules and aggregates findings sorted by severity", () => {
    const engine = new Engine([rule("A", "low"), rule("B", "critical")]);
    const result = engine.run(makeTarget());
    expect(result.findings.map((f) => f.ruleId)).toEqual(["B", "A"]);
    expect(result.counts.critical).toBe(1);
    expect(result.counts.low).toBe(1);
    expect(result.rulesRun).toEqual(["A", "B"]);
  });

  it("respects disabledRules", () => {
    const engine = new Engine([rule("A", "low"), rule("B", "high")]);
    const result = engine.run(makeTarget(), { disabledRules: ["A"] });
    expect(result.findings.map((f) => f.ruleId)).toEqual(["B"]);
  });

  it("respects enabledRules allowlist", () => {
    const engine = new Engine([rule("A", "low"), rule("B", "high")]);
    const result = engine.run(makeTarget(), { enabledRules: ["A"] });
    expect(result.rulesRun).toEqual(["A"]);
    expect(result.findings.map((f) => f.ruleId)).toEqual(["A"]);
  });

  it("runs no rules when enabledRules is an empty allowlist", () => {
    const engine = new Engine([rule("A", "low"), rule("B", "high")]);
    const result = engine.run(makeTarget(), { enabledRules: [] });
    expect(result.rulesRun).toEqual([]);
    expect(result.findings).toEqual([]);
  });

  it("applies severity overrides", () => {
    const engine = new Engine([rule("A", "low")]);
    const result = engine.run(makeTarget(), {
      severityOverrides: { A: "critical" },
    });
    expect(result.findings[0].severity).toBe("critical");
    expect(result.counts.critical).toBe(1);
  });

  it("isolates a throwing rule instead of crashing", () => {
    const boom: Rule = {
      id: "BOOM",
      title: "boom",
      description: "throws",
      severity: "high",
      category: "hygiene",
      evaluate: () => {
        throw new Error("kaboom");
      },
    };
    const engine = new Engine([boom, rule("A", "low")]);
    const result = engine.run(makeTarget());
    const boomFinding = result.findings.find((f) => f.ruleId === "BOOM");
    expect(boomFinding?.message).toContain("kaboom");
    expect(result.findings.some((f) => f.ruleId === "A")).toBe(true);
  });
});

describe("exceedsThreshold", () => {
  const counts = { info: 3, low: 2, medium: 0, high: 1, critical: 0 };
  it("fails when a finding is at or above the threshold", () => {
    expect(exceedsThreshold(counts, "high")).toBe(true);
    expect(exceedsThreshold(counts, "low")).toBe(true);
  });
  it("passes when nothing reaches the threshold", () => {
    expect(exceedsThreshold(counts, "critical")).toBe(false);
    expect(
      exceedsThreshold({ info: 0, low: 0, medium: 0, high: 0, critical: 0 }, "info"),
    ).toBe(false);
  });
});
