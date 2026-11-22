import { describe, expect, it, vi } from "vitest";
import { claudeAccessTokenOf, claudeConnectionRunScope, claudeRefreshDue, claudeRunScopesOf, claudeScopesAllowRun, claudeSignInEndsAt, parseStoredClaudeOauth, refreshClaudeOauth, serializeClaudeOauth } from "../services/claude-oauth-credential.js";

const now = 1_800_000_000_000;
const stored = { accessToken: "old-access", refreshToken: "old-refresh", expiresAt: now + 28800_000, scopes: ["user:inference"], subscriptionType: "max" };
describe("Claude OAuth credential", () => {
  it("keeps refresh fields and uses only the access token for execution", () => {
    const raw = serializeClaudeOauth({ ...stored, unrelated: "discard" })!;
    expect(JSON.parse(raw)).toEqual({ claudeAiOauth: stored });
    expect(claudeAccessTokenOf(raw)).toBe(stored.accessToken);
    expect(claudeAccessTokenOf("legacy-token")).toBe("legacy-token");
    expect(serializeClaudeOauth({ accessToken: "setup-token" })).toBeNull();
    expect(parseStoredClaudeOauth("{invalid")).toBeNull();
    expect(claudeRefreshDue(stored, now)).toBe(false);
    expect(claudeRefreshDue(stored, now + 7 * 3600_000)).toBe(true);
  });
  it("keeps the rotated pair, expiry, scopes and subscription metadata", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(new Response(JSON.stringify({ access_token: "new-access", refresh_token: "new-refresh", expires_in: 28800 })));
    const next = await refreshClaudeOauth(stored, { fetchImpl, now: () => now });
    expect(parseStoredClaudeOauth(next)).toEqual({ ...stored, accessToken: "new-access", refreshToken: "new-refresh" });
    const [url, request] = fetchImpl.mock.calls[0];
    expect(url).toBe("https://platform.claude.com/v1/oauth/token");
    expect(request.redirect).toBe("error");
    expect(JSON.parse(request.body)).toMatchObject({ grant_type: "refresh_token", refresh_token: stored.refreshToken, scope: "user:inference" });
  });
  it.each([0, -1, 400 * 86400 + 1, "28800"])("rejects an invalid expires_in (%s)", async expires_in => {
    const fetchImpl = vi.fn().mockResolvedValue(new Response(JSON.stringify({ access_token: "private-token", expires_in })));
    await expect(refreshClaudeOauth(stored, { fetchImpl })).rejects.toThrow("unexpected response");
  });
  it("treats only an explicit full run scope as full", () => {
    expect(claudeConnectionRunScope({ aiClaudeRunScope: "full" })).toBe("full");
    for (const config of [undefined, null, {}, { aiClaudeRunScope: "inference" }, { aiClaudeRunScope: true }, { ai: { aiClaudeRunScope: "full" } }]) {
      expect(claudeConnectionRunScope(config)).toBe("inference");
    }
  });
  it("delivers a broad login only to a full-scope connection and declares its scopes", () => {
    const broad = { ...stored, scopes: ["user:profile", "user:inference", "user:mcp_servers"] };
    const raw = serializeClaudeOauth(broad)!;
    expect(claudeScopesAllowRun(broad)).toBe(false);
    expect(claudeScopesAllowRun(broad, "full")).toBe(true);
    expect(claudeRefreshDue(broad, now)).toBe(true);
    expect(claudeRefreshDue(broad, now, undefined, "full")).toBe(false);
    expect(claudeRunScopesOf(raw, "full")).toEqual(broad.scopes);
    expect(claudeRunScopesOf(raw, "inference")).toBeNull();
    // A narrowed document, a login without inference, and a plain token keep the CLI default.
    expect(claudeRunScopesOf(serializeClaudeOauth(stored)!, "full")).toBeNull();
    expect(claudeScopesAllowRun({ ...stored, scopes: ["user:profile"] }, "full")).toBe(false);
    expect(claudeRunScopesOf("legacy-token", "full")).toBeNull();
    expect(claudeRunScopesOf(serializeClaudeOauth({ ...broad, scopes: [...broad.scopes, "bad scope\n"] })!, "full")).toEqual(broad.scopes);
  });
  it("renews a full-scope login with its granted scopes and never moves the sign-in end later", async () => {
    const ends = now + 20 * 86400_000;
    const broad = { ...stored, scopes: ["user:profile", "user:inference"], refreshTokenExpiresAt: ends };
    const fetchImpl = vi.fn().mockImplementation(async () => new Response(JSON.stringify({ access_token: "new-access", refresh_token: "new-refresh", expires_in: 28800, refresh_token_expires_in: 30 * 86400 })));
    const next = await refreshClaudeOauth(broad, { fetchImpl, now: () => now, runScope: "full" });
    expect(JSON.parse(fetchImpl.mock.calls[0][1].body).scope).toBe("user:profile user:inference");
    expect(parseStoredClaudeOauth(next)).toEqual({ ...broad, accessToken: "new-access", refreshToken: "new-refresh" });
    expect(claudeSignInEndsAt(next)).toBe(ends);
    // The default still narrows, and a first statement of the end is kept.
    const narrowed = await refreshClaudeOauth({ ...broad, refreshTokenExpiresAt: undefined }, { fetchImpl, now: () => now });
    expect(JSON.parse(fetchImpl.mock.calls[1][1].body).scope).toBe("user:inference");
    expect(parseStoredClaudeOauth(narrowed)).toMatchObject({ scopes: ["user:inference"], refreshTokenExpiresAt: now + 30 * 86400_000 });
    expect(claudeSignInEndsAt("legacy-token")).toBeNull();
  });
  it.each([400, 401, 403, 503])("redacts provider failure bodies (HTTP %s)", async status => {
    const fetchImpl = vi.fn().mockResolvedValue(new Response("private-response", { status }));
    await expect(refreshClaudeOauth(stored, { fetchImpl })).rejects.toMatchObject({ rejected: status !== 503, message: `Claude token refresh failed with HTTP ${status}` });
  });
});
