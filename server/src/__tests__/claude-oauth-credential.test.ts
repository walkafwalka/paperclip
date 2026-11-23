import { describe, expect, it, vi } from "vitest";
import { claudeAccessTokenOf, claudeRefreshDue, claudeRunScopesOf, claudeScopesAllowRun, claudeSignInEndsAt, parseStoredClaudeOauth, refreshClaudeOauth, serializeClaudeOauth } from "../services/claude-oauth-credential.js";

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
  it("delivers a broad login only with full run scope and declares its scopes", () => {
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
  it("ignores a sign-in end that no date can hold, and keeps the renewed tokens", async () => {
    const fetchImpl = vi.fn().mockImplementation(async () => new Response(JSON.stringify({ access_token: "new-access", refresh_token: "new-refresh", expires_in: 28800, refresh_token_expires_in: 1e300 })));
    const next = await refreshClaudeOauth(stored, { fetchImpl, now: () => now });
    expect(parseStoredClaudeOauth(next)).toMatchObject({ accessToken: "new-access", refreshToken: "new-refresh" });
    expect(claudeSignInEndsAt(next)).toBeNull();
    // A stored end that is not a date does not hide a valid end that the provider states.
    const restated = await refreshClaudeOauth({ ...stored, refreshTokenExpiresAt: 0 }, { now: () => now,
      fetchImpl: vi.fn().mockImplementation(async () => new Response(JSON.stringify({ access_token: "new-access", refresh_token: "new-refresh", expires_in: 28800, refresh_token_expires_in: 2 * 86400 }))) });
    expect(claudeSignInEndsAt(restated)).toBe(now + 2 * 86400_000);
    // A stored document that already carries such a number yields no date either.
    expect(claudeSignInEndsAt(JSON.stringify({ claudeAiOauth: { ...parseStoredClaudeOauth(next), refreshTokenExpiresAt: 1e300 } }))).toBeNull();
  });
  it.each([400, 401, 403, 503])("redacts provider failure bodies (HTTP %s)", async status => {
    const fetchImpl = vi.fn().mockResolvedValue(new Response("private-response", { status }));
    await expect(refreshClaudeOauth(stored, { fetchImpl })).rejects.toMatchObject({ rejected: status !== 503, message: `Claude token refresh failed with HTTP ${status}` });
  });
});
