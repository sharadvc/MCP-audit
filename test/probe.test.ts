import { describe, it, expect, vi } from "vitest";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";

const { listToolsMock } = vi.hoisted(() => ({
  listToolsMock: vi.fn(),
}));

vi.mock("@modelcontextprotocol/sdk/client/index.js", () => {
  class Client {
    async connect(_transport: Transport) {}
    getServerVersion() {
      return { name: "paginated-server", version: "1.0.0" };
    }
    getInstructions() {
      return undefined;
    }
    async listTools(params?: { cursor?: string }) {
      return listToolsMock(params);
    }
    async listResources() {
      return { resources: [] };
    }
    async listPrompts() {
      return { prompts: [] };
    }
    async close() {}
  }
  return { Client };
});

import { probe } from "../src/transport/probe.js";

describe("probe", () => {
  it("aggregates all pages from paginated listTools", async () => {
    listToolsMock.mockImplementation((params?: { cursor?: string }) => {
      if (!params?.cursor) {
        return {
          tools: [
            {
              name: "page-one-tool",
              description: "first page",
              inputSchema: { type: "object" },
            },
          ],
          nextCursor: "page-2",
        };
      }
      if (params.cursor === "page-2") {
        return {
          tools: [
            {
              name: "page-two-tool",
              description: "second page",
              inputSchema: { type: "object" },
            },
          ],
        };
      }
      throw new Error(`unexpected cursor: ${params.cursor}`);
    });

    const target = await probe({} as Transport, {
      kind: "stdio",
      source: "test://paginated",
    });

    expect(target.tools.map((t) => t.name)).toEqual([
      "page-one-tool",
      "page-two-tool",
    ]);
    expect(listToolsMock).toHaveBeenCalledTimes(2);
    expect(listToolsMock.mock.calls[0]?.[0]).toBeUndefined();
    expect(listToolsMock.mock.calls[1]?.[0]).toEqual({ cursor: "page-2" });
  });
});
