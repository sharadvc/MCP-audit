import type { Finding, Rule } from "../types.js";
import {
  containsAny,
  DESTRUCTIVE_VERBS,
  EXEC_VERBS,
  schemaProperties,
  WRITE_VERBS,
} from "./helpers.js";

const CONFIRM_HINTS = [
  "confirm",
  "confirmation",
  "acknowledge",
  "force",
  "dry_run",
  "dryrun",
  "yes",
  "approve",
];

/**
 * MCP001 - Destructive tool without an explicit confirmation/scoping argument.
 * A tool whose name or description implies deletion but which exposes no
 * confirmation-style parameter can be invoked by the model with no guardrail.
 */
export const destructiveNoScoping: Rule = {
  id: "MCP001",
  title: "Destructive tool lacks scoping or confirmation",
  description:
    "A tool that performs destructive actions should require an explicit confirmation or scope argument.",
  severity: "high",
  category: "permissions",
  evaluate(target, ctx): Finding[] {
    const findings: Finding[] = [];
    for (const tool of target.tools) {
      const haystack = `${tool.name} ${tool.description ?? ""}`;
      const hit = containsAny(haystack, DESTRUCTIVE_VERBS);
      if (!hit) continue;
      const props = schemaProperties(tool).map((p) => p.toLowerCase());
      const hasConfirm = props.some((p) =>
        CONFIRM_HINTS.some((c) => p.includes(c)),
      );
      if (!hasConfirm) {
        findings.push(
          ctx.report({
            title: "Destructive tool has no confirmation argument",
            message: `Tool "${tool.name}" implies a destructive action ("${hit}") but exposes no confirmation/scope parameter.`,
            remediation:
              "Add a required boolean like `confirm` (or a narrow scope/id argument) so the action cannot be triggered implicitly.",
            location: tool.name,
          }),
        );
      }
    }
    return findings;
  },
};

/**
 * MCP002 - Tool exposes arbitrary command / shell execution.
 * These are the highest-risk MCP tools: they turn the model into an RCE vector.
 */
export const execTool: Rule = {
  id: "MCP002",
  title: "Tool exposes arbitrary command execution",
  description:
    "Tools that run shell commands or arbitrary code give the model remote code execution capability.",
  severity: "critical",
  category: "permissions",
  evaluate(target, ctx): Finding[] {
    const findings: Finding[] = [];
    for (const tool of target.tools) {
      const hit =
        containsAny(tool.name, EXEC_VERBS) ??
        containsAny(tool.description, EXEC_VERBS);
      if (hit) {
        findings.push(
          ctx.report({
            title: "Arbitrary execution tool detected",
            message: `Tool "${tool.name}" appears to execute commands or code (matched "${hit.trim()}").`,
            remediation:
              "Avoid exposing raw exec. If unavoidable, allowlist commands, drop privileges, sandbox execution, and require human approval.",
            location: tool.name,
          }),
        );
      }
    }
    return findings;
  },
};

/**
 * MCP003 - Write/mutating tool with a completely open input surface.
 * A mutating tool that accepts a free-form object with no properties can write
 * anything anywhere.
 */
/**
 * MCP004 - Mutating/destructive tool advertises readOnlyHint.
 * Clients use readOnlyHint for auto-approval; marking a write tool read-only
 * is a confused-deputy / approval-bypass primitive.
 */
export const readOnlyHintMismatch: Rule = {
  id: "MCP004",
  title: "Mutating tool advertises readOnlyHint",
  description:
    "A tool that mutates or deletes state must not advertise readOnlyHint, which clients use to auto-approve safe reads.",
  severity: "high",
  category: "permissions",
  evaluate(target, ctx): Finding[] {
    const mutatingVerbs = [...WRITE_VERBS, ...DESTRUCTIVE_VERBS];
    const findings: Finding[] = [];
    for (const tool of target.tools) {
      if (tool.annotations?.readOnlyHint !== true) continue;
      const haystack = `${tool.name} ${tool.description ?? ""}`;
      const hit = containsAny(haystack, mutatingVerbs);
      if (!hit) continue;
      findings.push(
        ctx.report({
          title: "Write tool incorrectly marked read-only",
          message: `Tool "${tool.name}" advertises readOnlyHint but implies a mutating action ("${hit}").`,
          remediation:
            "Set readOnlyHint to false (or omit it) for tools that delete, update, or otherwise change state.",
          location: tool.name,
        }),
      );
    }
    return findings;
  },
};

export const unscopedWriteTool: Rule = {
  id: "MCP003",
  title: "Mutating tool has an unscoped input surface",
  description:
    "A write/update tool that accepts arbitrary input without declared properties cannot be reasoned about or constrained.",
  severity: "medium",
  category: "permissions",
  evaluate(target, ctx): Finding[] {
    const findings: Finding[] = [];
    for (const tool of target.tools) {
      const hit =
        containsAny(tool.name, WRITE_VERBS) ??
        containsAny(tool.description, WRITE_VERBS);
      if (!hit) continue;
      const props = schemaProperties(tool);
      if (props.length === 0) {
        findings.push(
          ctx.report({
            title: "Mutating tool declares no input properties",
            message: `Tool "${tool.name}" mutates state ("${hit}") but declares no input properties, so its effect is unbounded.`,
            remediation:
              "Declare explicit, typed properties for every input the tool acts on and mark the mandatory ones as required.",
            location: tool.name,
          }),
        );
      }
    }
    return findings;
  },
};

export const permissionRules: Rule[] = [
  destructiveNoScoping,
  execTool,
  readOnlyHintMismatch,
  unscopedWriteTool,
];
