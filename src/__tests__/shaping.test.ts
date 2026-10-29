/**
 * `fields` and `count_only` (src/shaping.ts) on the real tool handlers, with
 * IT Glue stubbed at `fetch`, plus unit tests of the text parsing and the
 * field projection. Fixture values are made up.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpServer } from "../mcp-server.js";
import { resetSharedStore } from "../pii/index.js";
import { COUNT_TOOLS, FIELDS_TOOLS, parseFields, parseToolText, projectFields } from "../shaping.js";

let itgUrls: string[];
let itgBody: unknown;

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
}

beforeEach(() => {
  itgUrls = [];
  itgBody = { data: [] };
  resetSharedStore();
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL) => {
      itgUrls.push(decodeURIComponent(String(input)));
      return jsonResponse(itgBody);
    }),
  );
  vi.stubEnv("PII_MODE", "off");
  vi.stubEnv("MCP_AUDIT", "off");
  vi.stubEnv("MCP_POLICY", "");
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

async function connect(): Promise<Client> {
  const server = createMcpServer({ apiKey: "itg-test-key", baseUrl: "https://itglue.example.invalid" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "t", version: "0" });
  await Promise.all([server.connect(a), client.connect(b)]);
  return client;
}

function text(result: unknown): string {
  return (result as { content?: { text?: string }[] }).content?.[0]?.text ?? "";
}

function isError(result: unknown): boolean {
  return (result as { isError?: boolean }).isError === true;
}

/** The JSON inside a tool's text, with the <itglue-data> frame and any notes removed. */
function body(result: unknown): Record<string, unknown> {
  const parsed = parseToolText(text(result));
  if (!parsed) throw new Error("no JSON in tool text");
  return parsed.json as Record<string, unknown>;
}

const configs = {
  data: [
    {
      id: "1",
      type: "configurations",
      attributes: { name: "SRV-01", hostname: "srv-01", "serial-number": "ABC", notes: "long text", "configuration-type-name": "Server" },
    },
    {
      id: "2",
      type: "configurations",
      attributes: { name: "PC-02", hostname: "pc-02", "serial-number": "DEF", notes: "more text", "configuration-type-name": "Workstation" },
    },
  ],
  meta: { "current-page": 1, "next-page": 2, "total-pages": 21, "total-count": 42 },
};

describe("tool list", () => {
  it("adds fields and count_only only to the tools that take them", async () => {
    const client = await connect();
    const { tools } = await client.listTools();
    for (const tool of tools) {
      const props = Object.keys(tool.inputSchema.properties ?? {});
      expect(props.includes("fields")).toBe(FIELDS_TOOLS.has(tool.name));
      expect(props.includes("count_only")).toBe(COUNT_TOOLS.has(tool.name));
    }
    // Every listed shaping tool really exists, so a rename upstream is caught here.
    const names = new Set(tools.map((t) => t.name));
    for (const n of [...FIELDS_TOOLS, ...COUNT_TOOLS]) expect(names.has(n)).toBe(true);
  });
});

describe("fields", () => {
  it("returns only the named fields plus id and type, and keeps meta", async () => {
    itgBody = configs;
    const client = await connect();
    const result = await client.callTool({
      name: "search_configurations",
      arguments: { organization_id: 1, fields: "name, hostname" },
    });
    const out = body(result);
    expect(out.data).toEqual([
      { id: "1", type: "configurations", name: "SRV-01", hostname: "srv-01" },
      { id: "2", type: "configurations", name: "PC-02", hostname: "pc-02" },
    ]);
    expect((out.meta as Record<string, unknown>).totalCount).toBe(42);
    // The frame stays: data is still marked untrusted.
    expect(text(result).startsWith("<itglue-data>\n")).toBe(true);
    // fields is not sent to IT Glue.
    expect(itgUrls[0]).not.toContain("fields");
  });

  it("lists names that matched nothing", async () => {
    itgBody = configs;
    const client = await connect();
    const out = body(
      await client.callTool({ name: "search_configurations", arguments: { organization_id: 1, fields: "name,serialNumbr" } }),
    );
    expect(out.fieldsNotFound).toEqual(["serialNumbr"]);
  });

  it("keeps the account-wide search note", async () => {
    itgBody = configs;
    const client = await connect();
    const result = await client.callTool({ name: "search_configurations", arguments: { fields: "name" } });
    expect(text(result)).toContain("ALL organizations");
    expect(body(result).data).toHaveLength(2);
  });

  it("works on a single record", async () => {
    itgBody = { data: configs.data[0] };
    const client = await connect();
    const out = body(await client.callTool({ name: "get_configuration", arguments: { id: "1", fields: "hostname" } }));
    expect(out).toEqual({ id: "1", type: "configurations", hostname: "srv-01" });
  });

  it("selects one flexible asset trait", async () => {
    itgBody = {
      data: [{ id: "5", type: "flexible-assets", attributes: { name: "Wifi", traits: { ssid: "Guest", notes: "x" } } }],
      meta: { "total-count": 1 },
    };
    const client = await connect();
    const out = body(
      await client.callTool({
        name: "search_flexible_assets",
        arguments: { flexible_asset_type_id: 9, fields: "name,traits.ssid" },
      }),
    );
    expect(out.data).toEqual([{ id: "5", type: "flexible-assets", name: "Wifi", traits: { ssid: "Guest" } }]);
  });

  it.each([
    ["", false],
    ["name;drop", true],
    [42, true],
  ])("fields=%j error=%s", async (value, error) => {
    itgBody = configs;
    const client = await connect();
    const result = await client.callTool({ name: "search_configurations", arguments: { organization_id: 1, fields: value } });
    expect(isError(result)).toBe(error);
    if (error) expect(itgUrls).toHaveLength(0);
  });

  it("is refused on a tool that does not take it", async () => {
    const client = await connect();
    const result = await client.callTool({ name: "get_document", arguments: { organization_id: 1, id: "7", fields: "name" } });
    expect(text(result)).toContain("does not take fields");
    expect(itgUrls).toHaveLength(0);
  });
});

describe("count_only", () => {
  it("asks IT Glue for one record and returns only the total", async () => {
    itgBody = configs;
    const client = await connect();
    const result = await client.callTool({
      name: "search_configurations",
      arguments: { organization_id: 1, configuration_type_id: 3, page_size: 500, count_only: true },
    });
    expect(body(result)).toEqual({ count: 42 });
    expect(text(result)).not.toContain("SRV-01");
    expect(itgUrls[0]).toContain("page[size]=1");
    expect(itgUrls[0]).toContain("filter[configuration-type-id]=3");
  });

  it("keeps the account-wide note with the count", async () => {
    itgBody = configs;
    const client = await connect();
    const result = await client.callTool({ name: "search_configurations", arguments: { count_only: true } });
    expect(text(result)).toContain("ALL organizations");
    expect(body(result)).toEqual({ count: 42 });
  });

  it("is refused on search_documents and on get tools", async () => {
    const client = await connect();
    for (const [name, args] of [
      ["search_documents", { organization_id: 1 }],
      ["get_configuration", { id: "1" }],
    ] as const) {
      const result = await client.callTool({ name, arguments: { ...args, count_only: true } });
      expect(text(result)).toContain("does not take count_only");
    }
    expect(itgUrls).toHaveLength(0);
  });

  it.each(["true", " TRUE "])("accepts count_only as the string %j (stale client tool list)", async (value) => {
    itgBody = configs;
    const client = await connect();
    const result = await client.callTool({ name: "search_configurations", arguments: { organization_id: 1, count_only: value } });
    expect(body(result)).toEqual({ count: 42 });
    expect(itgUrls[0]).toContain("page[size]=1");
  });

  it("refuses a count_only value that is not true or false", async () => {
    const client = await connect();
    const result = await client.callTool({ name: "search_configurations", arguments: { organization_id: 1, count_only: "yes" } });
    expect(text(result)).toContain("count_only must be true or false");
    expect(itgUrls).toHaveLength(0);
  });

  it("count_only=false is a normal search", async () => {
    itgBody = configs;
    const client = await connect();
    const out = body(
      await client.callTool({ name: "search_configurations", arguments: { organization_id: 1, count_only: false } }),
    );
    expect(out.data).toHaveLength(2);
  });
});

describe("with PII masking on", () => {
  it("masks what fields leaves in", async () => {
    vi.stubEnv("PII_MODE", "on");
    vi.stubEnv("PII_KEY", "test-pii-key-0123456789abcdef");
    itgBody = {
      data: [{ id: "1", type: "configurations", attributes: { name: "SRV-01", "contact-name": "Jane Doe", hostname: "srv-01" } }],
      meta: { "total-count": 1 },
    };
    const client = await connect();
    const out = text(
      await client.callTool({ name: "search_configurations", arguments: { organization_id: 1, fields: "contactName" } }),
    );
    expect(out).not.toContain("Jane Doe");
    expect(out).not.toContain("srv-01");
    expect(out).toMatch(/"contactName": "<PERSON_[0-9a-f]{10}>"/);
  });
});

describe("units", () => {
  it("parseFields", () => {
    expect(parseFields("a, b,a")).toEqual({ names: ["a", "b"] });
    expect(parseFields("traits.site-contact")).toEqual({ names: ["traits.site-contact"] });
    expect(parseFields(" , ")).toHaveProperty("error");
    expect(parseFields(Array.from({ length: 51 }, (_, i) => `f${i}`).join(","))).toHaveProperty("error");
  });

  it("parseToolText handles bare JSON, notes, and the frame", () => {
    expect(parseToolText('{"a":1}')?.json).toEqual({ a: 1 });
    const noted = parseToolText('Note one\n\nNote two\n\n{"a":1}');
    expect(noted?.note).toBe("Note one\n\nNote two");
    expect(noted?.rebuild({ b: 2 })).toBe('Note one\n\nNote two\n\n{\n  "b": 2\n}');
    const framed = parseToolText('<itglue-data>\n{"a":1}\n</itglue-data>\n\nNOTICE');
    expect(framed?.rebuild({ b: 2 })).toBe('<itglue-data>\n{\n  "b": 2\n}\n</itglue-data>\n\nNOTICE');
    expect(parseToolText("Multiple organizations match")).toBeNull();
  });

  it("projectFields on a bare array", () => {
    expect(projectFields([{ id: "1", type: "t", name: "x", other: 1 }], ["name"])).toEqual([
      { id: "1", type: "t", name: "x" },
    ]);
  });
});
