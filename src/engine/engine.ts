import type {
  AuditTarget,
  Finding,
  Rule,
  Severity,
} from "../types.js";
import { SEVERITY_RANK } from "../types.js";
import { createRuleContext } from "./context.js";

export interface EngineOptions {
  /** Rule ids to skip entirely. */
  disabledRules?: string[];
  /** If set, only these rule ids run. */
  enabledRules?: string[];
  /** Per-rule severity overrides. */
  severityOverrides?: Record<string, Severity>;
}

export interface AuditResult {
  target: AuditTarget;
  findings: Finding[];
  /** Count of findings per severity. */
  counts: Record<Severity, number>;
  /** Rule ids that were executed. */
  rulesRun: string[];
}

/**
 * The rule engine. It runs a set of rules against a target and aggregates the
 * findings. Rules are pure functions of the target, so the engine is
 * deterministic and easy to test.
 */
export class Engine {
  private readonly rules: Rule[];

  constructor(rules: Rule[]) {
    this.rules = rules;
  }

  /** Rules that will run given the supplied options. */
  activeRules(options: EngineOptions = {}): Rule[] {
    const { disabledRules = [], enabledRules } = options;
    return this.rules.filter((rule) => {
      if (enabledRules !== undefined) {
        return enabledRules.includes(rule.id);
      }
      return !disabledRules.includes(rule.id);
    });
  }

  run(target: AuditTarget, options: EngineOptions = {}): AuditResult {
    const active = this.activeRules(options);
    const overrides = options.severityOverrides ?? {};
    const findings: Finding[] = [];

    for (const rule of active) {
      const ctx = createRuleContext(rule);
      let produced: Finding[];
      try {
        produced = rule.evaluate(target, ctx);
      } catch (err) {
        // A misbehaving rule must never crash the whole audit.
        produced = [
          {
            ruleId: rule.id,
            severity: "info",
            title: `Rule ${rule.id} failed to evaluate`,
            message: err instanceof Error ? err.message : String(err),
            remediation:
              "This is likely a bug in mcp-audit; please report it with the target details.",
          },
        ];
      }
      for (const finding of produced) {
        const override = overrides[finding.ruleId];
        findings.push(override ? { ...finding, severity: override } : finding);
      }
    }

    findings.sort(
      (a, b) =>
        SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
        a.ruleId.localeCompare(b.ruleId) ||
        (a.location ?? "").localeCompare(b.location ?? ""),
    );

    const counts: Record<Severity, number> = {
      info: 0,
      low: 0,
      medium: 0,
      high: 0,
      critical: 0,
    };
    for (const f of findings) counts[f.severity]++;

    return {
      target,
      findings,
      counts,
      rulesRun: active.map((r) => r.id),
    };
  }
}

/**
 * Given severity counts and a threshold, decide whether the audit "fails".
 * Any finding at or above the threshold severity fails.
 */
export function exceedsThreshold(
  counts: Record<Severity, number>,
  threshold: Severity,
): boolean {
  const min = SEVERITY_RANK[threshold];
  return (Object.keys(counts) as Severity[]).some(
    (sev) => SEVERITY_RANK[sev] >= min && counts[sev] > 0,
  );
}
