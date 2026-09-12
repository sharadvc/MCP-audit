import { afterEach, describe, expect, it, vi } from "vitest";
import { collectHeaders, main, parseArgs } from "../src/cli.js";

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

describe("parseArgs", () => {
  it("parses --flag=value as a string flag value", () => {
    const { flags } = parseArgs(["audit", "--fail-on=high"]);
    expect(flags["fail-on"]).toBe("high");
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
