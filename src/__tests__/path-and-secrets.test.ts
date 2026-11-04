/**
 * Data leak review 2026-11-03, items IG-1 and IG-2.
 *  - IG-1: path-bound IDs must be plain numbers; the client refuses unsafe paths.
 *  - IG-2: secrets (passwords, BitLocker keys, tokens, private keys) are redacted
 *    by key name and by value shape, without Presidio.
 * Fixture values are made up.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpServer, ITGlueClient } from "../mcp-server.js";
import { resetSharedStore } from "../pii/index.js";
import { createTokenizer } from "../pii/tokenizer.js";
import { MemoryTokenStore } from "../pii/store.js";
import { maskJson, type PiiContext } from "../pii/mask-json.js";
import { REDACTED_SECRET, isSecretKey } from "../pii/secret-rules.js";
import { assertSafeApiPath, invalidPathArgument } from "../path-safety.js";

function makeCtx(): PiiContext {
  return {
    tokenizer: createTokenizer("test-key-not-a-secret"),
    store: new MemoryTokenStore(),
    tenant: "t:1",
    ttlSeconds: 60,
    scoreThreshold: 0.4,
  };
}

const BITLOCKER = "123456-234567-345678-456789-567890-678901-789012-890123";

describe("path safety (IG-1)", () => {
  it("accepts numeric ids as numbers or digit strings", () => {
    expect(invalidPathArgument({ id: 5, organization_id: "123", document_id: 9 })).toBeUndefined();
    expect(invalidPathArgument({ name: "../x" })).toBeUndefined();
    expect(invalidPathArgument(undefined)).toBeUndefined();
  });

  it("leaves absent and falsy ids to the handler; the client still refuses an empty segment", () => {
    expect(invalidPathArgument({ organization_id: 0, id: "", document_id: null })).toBeUndefined();
    expect(() => assertSafeApiPath("/organizations/")).toThrow(/unsafe/);
  });

  it.each([
    ["../passwords/5?show_password=true"],
    ["5/../../passwords/5"],
    ["5?x=1"],
    ["5#frag"],
    ["%2e%2e/passwords"],
    ["abc"],
    ["-1"],
    ["1.5"],
    [-1],
    [false],
    [1.5],
    [Number.MAX_SAFE_INTEGER + 2],
    [{ a: 1 }],
    [["5"]],
  ])("refuses id %j and names the argument, not the value", (value) => {
    expect(invalidPathArgument({ id: value })).toBe("id");
    expect(invalidPathArgument({ resource_id: value })).toBe("resource_id");
  });

  it("assertSafeApiPath allows the paths the tools build", () => {
    for (const p of [
      "/organizations",
      "/organizations/12",
      "/organizations/12/relationships/documents",
      "/documents/9/relationships/sections/4",
      "/documents/9/publish",
      "/flexible_asset_types",
      "/flexible_assets",
      "/organizations/12/relationships/document_folders",
      "/configurations/3/relationships/attachments",
    ]) {
      expect(() => assertSafeApiPath(p)).not.toThrow();
    }
  });

  it.each([
    ["/configurations/../passwords/5"],
    ["/configurations/%2e%2e/passwords/5"],
    ["/configurations/5?show_password=true"],
    ["/configurations/5#x"],
    ["/configurations/a\\b"],
    ["/passwords/5"],
    ["/passwords"],
    ["/organizations/5/relationships/passwords"],
    ["/password_folders"],
    ["/organizations//5"],
    ["/organizations/5/"],
    ["organizations/5"],
    ["//evil.example/x"],
  ])("assertSafeApiPath refuses %s", (p) => {
    expect(() => assertSafeApiPath(p)).toThrow(/unsafe IT Glue request path/);
  });

  describe("through the server", () => {
    let calls: string[];

    beforeEach(() => {
      calls = [];
      resetSharedStore();
      vi.spyOn(console, "error").mockImplementation(() => {});
      vi.stubGlobal(
        "fetch",
        vi.fn(async (input: string | URL) => {
          calls.push(String(input));
          return new Response(JSON.stringify({ data: [{ id: "42", type: "configurations", attributes: { name: "pc" } }] }), { status: 200 });
        }),
      );
      vi.stubEnv("PII_MODE", "off");
      vi.stubEnv("MCP_AUDIT", "off");
      vi.stubEnv("MCP_POLICY", "admin");
    });

    afterEach(() => {
      vi.restoreAllMocks();
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

    const text = (r: unknown) => (r as { content?: { text?: string }[] }).content?.[0]?.text ?? "";

    it.each([
      ["get_configuration", { id: "../passwords/5?show_password=true" }],
      ["get_organization", { id: "../passwords/5" }],
      ["get_location", { id: "5/../x", organization_id: 1 }],
      ["list_attachments", { resource_type: "documents", resource_id: "../passwords/5" }],
      ["create_attachment", { resource_type: "documents", resource_id: "../passwords/5", file_name: "a.txt", content: "QQ==" }],
      ["update_document", { organization_id: 1, document_id: "../passwords/5", name: "x" }],
      ["delete_document_section", { document_id: 1, section_id: "../../passwords/5" }],
    ])("%s with a traversing id is refused before IT Glue", async (name, args) => {
      const client = await connect();
      const result = await client.callTool({ name, arguments: args });
      expect((result as { isError?: boolean }).isError).toBe(true);
      expect(text(result)).toMatch(/Invalid .*IT Glue IDs are plain numbers/);
      expect(text(result)).not.toContain("passwords");
      expect(calls).toEqual([]);
    });

    it("a numeric id still reaches IT Glue", async () => {
      const client = await connect();
      await client.callTool({ name: "get_configuration", arguments: { id: 42 } });
      expect(calls.length).toBe(1);
      expect(calls[0]).toBe("https://itglue.example.invalid/configurations/42");
    });
  });

  it("the client refuses a traversing path even when called directly", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    try {
      const client = new ITGlueClient({ apiKey: "itg-test-key", baseUrl: "https://itglue.example.invalid" });
      await expect(client.get("/configurations/../passwords/5")).rejects.toThrow(/unsafe IT Glue request path/);
      await expect(client.post("/passwords/5", {})).rejects.toThrow(/unsafe IT Glue request path/);
      await expect(client.patch("/configurations/5?x=1", {})).rejects.toThrow(/unsafe IT Glue request path/);
      await expect(client.delete("/documents/../passwords")).rejects.toThrow(/unsafe IT Glue request path/);
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe("secret key names (IG-2)", () => {
  it.each([
    "password",
    "Password",
    "bitlockerRecoveryKey",
    "bitlocker-recovery-key",
    "recovery_key",
    "Recovery Key",
    "apiKey",
    "api-key",
    "privateKey",
    "secret",
    "clientSecret",
    "accessToken",
    "otpSeed",
    "totp",
    "admin-password",
    "localAdminPassword",
    "Passphrase",
    "credentials",
    "preSharedKey",
    "backup-codes",
    "bitlocker",
  ])("%s is a secret key", (key) => {
    expect(isSecretKey(key)).toBe(true);
  });

  it.each([
    "name",
    "hostname",
    "notes",
    "passwordUpdatedAt",
    "password-folder-id",
    "passwordCount",
    "bitlockerRecoveryId",
    "bitlockerEnabled",
    "tokenId",
    "keyboard",
    "shipping",
    "footprint",
    "organizationName",
    "recoveryPolicy",
    "primaryKeyword",
  ])("%s is not a secret key", (key) => {
    expect(isSecretKey(key)).toBe(false);
  });
});

describe("secret redaction in maskJson (IG-2)", () => {
  it("redacts flexible asset trait values by key name and keeps the others readable", async () => {
    const out = (await maskJson(
      {
        id: "7",
        type: "flexible-assets",
        name: "Laptop-01 BitLocker",
        traits: {
          "recovery-key": BITLOCKER,
          "recovery-key-id": "AB12CD34",
          "local-admin-password": "Hunter2!x",
          "operating-system": "Windows 11",
        },
      },
      makeCtx(),
    )) as { name: string; traits: Record<string, string> };
    expect(out.name).toBe("Laptop-01 BitLocker");
    expect(out.traits["recovery-key"]).toBe(REDACTED_SECRET);
    expect(out.traits["local-admin-password"]).toBe(REDACTED_SECRET);
    expect(out.traits["recovery-key-id"]).toBe("AB12CD34");
    expect(out.traits["operating-system"]).toBe("Windows 11");
  });

  it("redacts a whole object or array under a secret key, numbers too, not booleans or empties", async () => {
    const out = (await maskJson(
      {
        password: { value: "abc", hint: "pet" },
        pin: 1234,
        secret: ["a", "b"],
        token: 98765,
        passwordProtected: true,
        otp: "",
        apiKey: null,
      },
      makeCtx(),
    )) as Record<string, unknown>;
    expect(out.password).toBe(REDACTED_SECRET);
    expect(out.secret).toBe(REDACTED_SECRET);
    expect(out.token).toBe(REDACTED_SECRET);
    expect(out.passwordProtected).toBe(true);
    expect(out.otp).toBe("");
    expect(out.apiKey).toBeNull();
    expect(JSON.stringify(out)).not.toContain("abc");
  });

  it("finds a BitLocker key in a field with an ordinary name", async () => {
    const out = (await maskJson({ notes: `Recovery ${BITLOCKER} for LT-01`, details: BITLOCKER }, makeCtx())) as {
      notes: string;
      details: string;
    };
    expect(out.notes).toBe(`Recovery ${REDACTED_SECRET} for LT-01`);
    expect(out.details).toBe(REDACTED_SECRET);
  });

  it("does not match digit runs that are not a recovery key", async () => {
    const out = (await maskJson({ notes: "ticket 123456-234567 and serial 1234567890123456789" }, makeCtx())) as {
      notes: string;
    };
    expect(out.notes).toBe("ticket 123456-234567 and serial 1234567890123456789");
  });

  it.each([
    ["Password: Hunter2!x for the switch", "Password: [REDACTED: secret] for the switch"],
    ["password = 'two words' ok", "password = [REDACTED: secret] ok"],
    ["<p>Password: Hunter2!x</p>", "<p>Password: [REDACTED: secret]</p>"],
    ["the admin password is Hunter2!x today", "the admin password is [REDACTED: secret] today"],
    ["**Recovery Key**: abc123def", "**Recovery Key**: [REDACTED: secret]"],
    ["API key: sk_live_ABCDEF123456", "API key: [REDACTED: secret]"],
    ["PSK=Wifi-Pass-1", "PSK=[REDACTED: secret]"],
  ])("redacts the value after a label in text: %s", async (input, expected) => {
    const out = (await maskJson({ content: input }, makeCtx())) as { content: string };
    expect(out.content).toBe(expected);
  });

  it("redacts PEM private keys, JWTs and well-known token shapes", async () => {
    const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\ndef\n-----END RSA PRIVATE KEY-----";
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123_-";
    const out = (await maskJson(
      {
        content: `before ${pem} after`,
        notes: `bearer ${jwt}`,
        description: "AKIAABCDEFGHIJKLMNOP and ghp_abcdefghijklmnopqrstuvwxyz0123456789",
      },
      makeCtx(),
    )) as { content: string; notes: string; description: string };
    expect(out.content).toBe(`before ${REDACTED_SECRET} after`);
    expect(out.notes).toBe(`bearer ${REDACTED_SECRET}`);
    expect(out.description).toBe(`${REDACTED_SECRET} and ${REDACTED_SECRET}`);
  });

  it("an unterminated PEM block is redacted to the end of the text", async () => {
    const out = (await maskJson({ content: "key: -----BEGIN PRIVATE KEY-----\nMIIEabc" }, makeCtx())) as {
      content: string;
    };
    expect(out.content).toBe(`key: ${REDACTED_SECRET}`);
  });

  it("uses a fixed marker, never a token that could be turned back into the secret", async () => {
    const ctx = makeCtx();
    const out = JSON.stringify(
      await maskJson({ traits: { password: "Hunter2!x" }, content: `Password: Hunter2!x` }, ctx),
    );
    expect(out).not.toMatch(/<[A-Z]+_[0-9a-f]{10}>/);
    expect(out).not.toContain("Hunter2");
  });

  it("still redacts when the analyzer is down (free text goes to the unavailable marker, traits by key)", async () => {
    const ctx = makeCtx();
    ctx.analyzer = async () => {
      throw new Error("down");
    };
    const out = (await maskJson({ traits: { "recovery-key": BITLOCKER } }, ctx)) as {
      traits: Record<string, string>;
    };
    expect(out.traits["recovery-key"]).toBe(REDACTED_SECRET);
  });

  it("keeps person PII masking working next to secrets", async () => {
    const out = (await maskJson({ contactName: "Jane Doe", notes: "mail jane@contoso.com Password: x1y2z3" }, makeCtx())) as {
      contactName: string;
      notes: string;
    };
    expect(out.contactName).toMatch(/^<PERSON_[0-9a-f]{10}>$/);
    expect(out.notes).toMatch(/^mail <EMAIL_[0-9a-f]{10}> Password: \[REDACTED: secret\]$/);
  });
});
