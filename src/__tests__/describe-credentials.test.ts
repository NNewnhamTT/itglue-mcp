import { afterEach, describe, expect, it, vi } from "vitest";
import { describeEnvCredentials } from "../mcp-server.js";

// The startup summary must help diagnose a 401 without ever exposing the key.
const FAKE_KEY = "ITG.0123456789abcdef0123456789abcdef"; // test value, not a real key

describe("describeEnvCredentials", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("never contains the key or any long part of it", () => {
    vi.stubEnv("ITGLUE_API_KEY", FAKE_KEY);
    vi.stubEnv("ITGLUE_REGION", "us");
    const out = describeEnvCredentials();
    expect(out).not.toContain(FAKE_KEY);
    expect(out).not.toContain(FAKE_KEY.slice(4, 16));
    expect(out).toContain("length 36");
    expect(out).toContain("ITG-prefix yes");
    expect(out).toContain("api.itglue.com");
  });

  it("reports the region API host and raw versus trimmed length (stray space)", () => {
    vi.stubEnv("ITGLUE_API_KEY", `${FAKE_KEY} `);
    vi.stubEnv("ITGLUE_REGION", "eu");
    const out = describeEnvCredentials();
    expect(out).toContain("api.eu.itglue.com");
    expect(out).toContain("length 36 (raw length 37)");
  });

  it("flags an unresolved Key Vault reference without echoing it", () => {
    const ref = "@Microsoft.KeyVault(SecretUri=https://vault.example/secrets/x/)";
    vi.stubEnv("ITGLUE_API_KEY", ref);
    const out = describeEnvCredentials();
    expect(out).toContain("unresolved-vault-reference YES");
    expect(out).not.toContain("vault.example");
  });

  it("says MISSING when there is no key, and flags an invalid region", () => {
    vi.stubEnv("ITGLUE_API_KEY", "");
    vi.stubEnv("X_API_KEY", "");
    vi.stubEnv("ITGLUE_REGION", "USA");
    const out = describeEnvCredentials();
    expect(out).toContain("API key MISSING");
    expect(out).toContain('no API URL for region "USA"');
  });
});
