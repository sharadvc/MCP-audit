import { describe, it, expect } from "vitest";
import { ALL_RULES } from "../src/rules/index.js";
import { runAudit } from "../src/audit.js";
import { DEFAULT_CONFIG } from "../src/config.js";
import { normalize } from "../src/static/manifest.js";
import { makeTarget } from "./helpers.js";
import type { AuditTarget } from "../src/types.js";
// The mock server surfaces are the single source of truth for fixtures.
import { insecureSurface } from "../fixtures/surfaces.mjs";

function audit(target: AuditTarget) {
  return runAudit(target, DEFAULT_CONFIG, ALL_RULES);
}

function idsFor(target: AuditTarget): Set<string> {
  return new Set(audit(target).findings.map((f) => f.ruleId));
}

describe("rule catalog", () => {
  it("has unique ids and at least 15 rules", () => {
    const ids = ALL_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ALL_RULES.length).toBeGreaterThanOrEqual(15);
  });

  it("every rule declares required metadata", () => {
    for (const r of ALL_RULES) {
      expect(r.id).toMatch(/^MCP\d{3}$/);
      expect(r.title.length).toBeGreaterThan(0);
      expect(r.remediation ?? "ok").toBeTruthy();
    }
  });
});

describe("rules against the insecure surface", () => {
  const target = normalize(insecureSurface, "insecure");
  const ids = idsFor(target);

  for (const expected of [
    "MCP001", // destructive delete_file
    "MCP002", // exec run_shell
    "MCP003", // unscoped write_record
    "MCP010", // no schema
    "MCP011", // additionalProperties
    "MCP012", // unconstrained string
    "MCP014", // unbounded numeric
    "MCP020", // injection phrase
    "MCP021", // overly broad
    "MCP030", // .env resource
    "MCP031", // path traversal
    "MCP032", // secret in schema defaults
    "MCP041", // SSRF url
    "MCP062", // undocumented tool
  ]) {
    it(`fires ${expected}`, () => {
      expect(ids.has(expected)).toBe(true);
    });
  }
});

describe("MCP004 readOnlyHint mismatch", () => {
  function findingsFor(tools: AuditTarget["tools"]) {
    return audit(makeTarget({ tools })).findings.filter((f) => f.ruleId === "MCP004");
  }

  it("fires when a write-verb tool advertises readOnlyHint", () => {
    const findings = findingsFor([
      {
        name: "cleanup_records",
        description: "deletes stale records",
        annotations: { readOnlyHint: true },
      },
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].location).toBe("cleanup_records");
  });

  it("does not fire when readOnlyHint is false", () => {
    const findings = findingsFor([
      {
        name: "cleanup_records",
        description: "deletes stale records",
        annotations: { readOnlyHint: false },
      },
    ]);
    expect(findings).toHaveLength(0);
  });

  it("does not fire for a read-only tool with readOnlyHint", () => {
    const findings = findingsFor([
      {
        name: "get_weather",
        description: "returns weather for a city",
        annotations: { readOnlyHint: true },
      },
    ]);
    expect(findings).toHaveLength(0);
  });
});

describe("MCP002 exec detection", () => {
  it("flags a shell tool as critical", () => {
    const target = makeTarget({
      tools: [{ name: "run_command", description: "runs a command" }],
    });
    const findings = audit(target).findings.filter((f) => f.ruleId === "MCP002");
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("critical");
  });

  it("does not flag a benign read tool", () => {
    const target = makeTarget({
      tools: [
        {
          name: "get_weather",
          description: "returns weather",
          inputSchema: {
            type: "object",
            properties: { city: { type: "string", enum: ["london"] } },
            required: ["city"],
            additionalProperties: false,
          },
        },
      ],
    });
    expect(idsFor(target).has("MCP002")).toBe(false);
  });
});

describe("MCP030 resource secret detection", () => {
  function findingsFor(resources: AuditTarget["resources"]) {
    return audit(makeTarget({ resources })).findings.filter((f) => f.ruleId === "MCP030");
  }

  it("does not treat generic credentials or secrets wording as critical evidence", () => {
    const findings = findingsFor([
      {
        uri: "docs://project-notes",
        name: "Credential safety notes",
        description: "Project notes. Contains no credentials or secrets.",
      },
    ]);

    expect(findings).toEqual([]);
  });

  it("reports an unambiguous metadata filename reference below critical severity", () => {
    const findings = findingsFor([
      {
        uri: "docs://deployment-guide",
        description: "Includes a copy of the production .env file.",
      },
    ]);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: "medium",
      location: "docs://deployment-guide",
    });
  });

  it("keeps sensitive resource URIs critical", () => {
    const findings = findingsFor([
      {
        uri: "file:///home/app/.env",
        description: "Configuration reference",
      },
    ]);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: "critical",
      location: "file:///home/app/.env",
    });
  });
});

describe("MCP032 secret in schema defaults", () => {
  function findingsFor(tools: AuditTarget["tools"]) {
    return audit(makeTarget({ tools })).findings.filter((f) => f.ruleId === "MCP032");
  }

  it("fires when a property has a hardcoded secret default", () => {
    const findings = findingsFor([
      {
        name: "test_tool",
        description: "A test tool",
        inputSchema: {
          type: "object",
          properties: {
            api_key: { type: "string", default: "sk-live-1234567890abcdefghijkl" },
          },
        },
      },
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].location).toBe("test_tool.api_key");
    expect(findings[0].severity).toBe("critical");
  });

  it("fires when a property uses const with secret material", () => {
    const findings = findingsFor([
      {
        name: "test_tool",
        description: "A test tool",
        inputSchema: {
          type: "object",
          properties: {
            auth_token: {
              type: "string",
              const: "ghp_123456789012345678901234567890123456",
            },
          },
        },
      },
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].location).toBe("test_tool.auth_token");
  });

  it("does not fire for benign const values", () => {
    const findings = findingsFor([
      {
        name: "test_tool",
        description: "A test tool",
        inputSchema: {
          type: "object",
          properties: {
            mode: { type: "string", const: "read_only" },
          },
        },
      },
    ]);
    expect(findings).toHaveLength(0);
  });

  it("fires when examples array contains secret material", () => {
    const findings = findingsFor([
      {
        name: "test_tool",
        description: "A test tool",
        inputSchema: {
          type: "object",
          properties: {
            secret_key: {
              type: "string",
              examples: ["placeholder", "AKIAIOSFODNN7EXAMPLE"],
            },
          },
        },
      },
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].location).toBe("test_tool.secret_key");
  });

  it("does not fire for benign examples or non-secret defaults", () => {
    const findings = findingsFor([
      {
        name: "test_tool",
        description: "A test tool",
        inputSchema: {
          type: "object",
          properties: {
            api_key: { type: "string", default: "" },
            hostname: {
              type: "string",
              default: "localhost",
              examples: ["example.com", "test.local"],
            },
            other: { type: "string" },
          },
        },
      },
    ]);
    expect(findings).toHaveLength(0);
  });
});

describe("MCP040 http auth", () => {
  it("flags http transport without auth", () => {
    const target = makeTarget({
      transport: "http",
      connection: { url: "http://x", authProvided: false },
    });
    expect(idsFor(target).has("MCP040")).toBe(true);
  });
  it("passes when auth is provided", () => {
    const target = makeTarget({
      transport: "http",
      connection: { url: "http://x", authProvided: true },
    });
    expect(idsFor(target).has("MCP040")).toBe(false);
  });
});

describe("MCP060 tool name collision", () => {
  it("detects duplicate tool names", () => {
    const target = makeTarget({
      tools: [
        { name: "dup", description: "a" },
        { name: "dup", description: "b" },
      ],
    });
    expect(idsFor(target).has("MCP060")).toBe(true);
  });
});

describe("MCP061 capability sprawl", () => {
  it("fires when tool count exceeds the threshold", () => {
    const tools = Array.from({ length: 45 }, (_, i) => ({
      name: `t${i}`,
      description: "documented tool",
      inputSchema: {
        type: "object",
        properties: { a: { type: "string", enum: ["x"] } },
        required: ["a"],
        additionalProperties: false as const,
      },
    }));
    expect(idsFor(makeTarget({ tools })).has("MCP061")).toBe(true);
  });
});

describe("MCP014 unbounded numeric arg", () => {
  function findingsFor(tools: AuditTarget["tools"]) {
    return audit(makeTarget({ tools })).findings.filter((f) => f.ruleId === "MCP014");
  }

  it("flags an integer arg with no minimum or maximum", () => {
    const findings = findingsFor([
      {
        name: "list_items",
        description: "list",
        inputSchema: {
          type: "object",
          properties: { limit: { type: "integer" } },
          required: ["limit"],
          additionalProperties: false,
        },
      },
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("low");
    expect(findings[0].location).toBe("list_items.limit");
  });

  it("flags a number arg with no range", () => {
    const findings = findingsFor([
      {
        name: "set_temp",
        description: "set",
        inputSchema: {
          type: "object",
          properties: { temperature: { type: "number" } },
          additionalProperties: false,
        },
      },
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].location).toBe("set_temp.temperature");
  });

  it("does not flag an integer with minimum and maximum", () => {
    const findings = findingsFor([
      {
        name: "list_items",
        description: "list",
        inputSchema: {
          type: "object",
          properties: { limit: { type: "integer", minimum: 1, maximum: 100 } },
          required: ["limit"],
          additionalProperties: false,
        },
      },
    ]);
    expect(findings).toHaveLength(0);
  });

  it("does not flag an integer with an enum", () => {
    const findings = findingsFor([
      {
        name: "set_page",
        description: "page",
        inputSchema: {
          type: "object",
          properties: { page: { type: "integer", enum: [1, 2, 3] } },
          additionalProperties: false,
        },
      },
    ]);
    expect(findings).toHaveLength(0);
  });
});

describe("clean target", () => {
  it("produces no high or critical findings", () => {
    const target = makeTarget({
      serverInfo: { name: "clean", version: "1.0.0" },
      tools: [
        {
          name: "get_weather",
          description: "Returns the weather for a supported city.",
          inputSchema: {
            type: "object",
            properties: { city: { type: "string", enum: ["london"] } },
            required: ["city"],
            additionalProperties: false,
          },
        },
      ],
    });
    const { counts } = audit(target);
    expect(counts.critical).toBe(0);
    expect(counts.high).toBe(0);
  });
});
