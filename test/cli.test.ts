import { afterEach, describe, expect, it, vi } from "vitest";
import { collectHeaders, main, overlayFlags, parseArgs } from "../src/cli.js";
import { DEFAULT_CONFIG } from "../src/config.js";
import { runAudit } from "../src/audit.js";
import { makeTarget } from "./helpers.js";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("top-level information flags", () => {
  it("prints only the version and succeeds without a command", async () => {
    const write = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

    await expect(main(["--version"])).resolves.toBe(0);

    expect(write).toHaveBeenCalledOnce();
    expect(write).toHaveBeenCalledWith(expect.stringMatching(/^\d+\.\d+\.\d+\n$/));
  });

  it("keeps a bare invocation as a usage error", async () => {
    const write = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

    await expect(main([])).resolves.toBe(2);
    expect(write).toHaveBeenCalledWith(expect.stringContaining("USAGE"));
  });

  it("keeps explicit help successful", async () => {
    const write = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

    await expect(main(["--help"])).resolves.toBe(0);
    expect(write).toHaveBeenCalledWith(expect.stringContaining("USAGE"));
  });
});

describe("HTTP headers", () => {
  it("collects every repeated --header flag", () => {
    const { flags } = parseArgs([
      "http",
      "https://example.com/mcp",
      "--header",
      "X-Tenant: acme",
      "--header",
      "X-Env: prod",
    ]);

    expect(collectHeaders(flags)).toEqual({
      "X-Tenant": "acme",
      "X-Env": "prod",
    });
  });

  it("preserves colons in header values", () => {
    const { flags } = parseArgs([
      "http",
      "https://example.com/mcp",
      "--header",
      "Authorization: Bearer a:b",
    ]);

    expect(collectHeaders(flags)).toEqual({ Authorization: "Bearer a:b" });
  });

  it("treats --only \"\" as an empty allowlist (zero rules run)", () => {
    const { flags } = parseArgs(["static", "manifest.json", "--only", ""]);
    const config = overlayFlags(DEFAULT_CONFIG, flags);
    const result = runAudit(makeTarget(), config);
    expect(result.rulesRun).toEqual([]);
  });

  it("keeps last-wins behavior for repeated non-header flags", () => {
    const { flags } = parseArgs([
      "http",
      "https://example.com/mcp",
      "--config",
      "one.json",
      "--config",
      "two.json",
    ]);

    expect(flags.config).toBe("two.json");
  });
});
