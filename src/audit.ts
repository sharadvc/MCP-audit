import { Engine, exceedsThreshold } from "./engine/engine.js";
import type { AuditResult } from "./engine/engine.js";
import { ALL_RULES } from "./rules/index.js";
import type { AuditTarget, Finding, Rule, Severity } from "./types.js";
import type { McpAuditConfig } from "./config.js";

/** Remove findings whose location or rule id matches any ignore substring. */
export function applyIgnores(
  findings: Finding[],
  ignore: string[],
): Finding[] {
  if (ignore.length === 0) return findings;
  return findings.filter((f) => {
    const loc = f.location ?? "";
    const id = f.ruleId;
    return !ignore.some(
      (pattern) => loc.includes(pattern) || id.includes(pattern),
    );
  });
}

function recount(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    info: 0,
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

/**
 * Run the full audit pipeline against a target: execute the (configured) rules,
 * apply ignore filters, and recompute counts.
 */
export function runAudit(
  target: AuditTarget,
  config: McpAuditConfig,
  rules: Rule[] = ALL_RULES,
): AuditResult {
  const engine = new Engine(rules);
  const raw = engine.run(target, {
    disabledRules: config.disabledRules,
    enabledRules: config.enabledRules,
    severityOverrides: config.severityOverrides,
  });
  const findings = applyIgnores(raw.findings, config.ignore);
  return { ...raw, findings, counts: recount(findings) };
}

/** Whether a result should cause a non-zero (CI-failing) exit. */
export function shouldFail(
  result: AuditResult,
  failOn: Severity,
): boolean {
  return exceedsThreshold(result.counts, failOn);
}
