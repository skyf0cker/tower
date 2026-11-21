import { timingSafeEqualStr } from "../shared/hmac";
import type { AdminAuthInfo } from "../shared/types";

export interface AuthEnv {
  CF_ACCESS_TEAM_DOMAIN?: string;
  CF_ACCESS_AUD?: string;
  MCP_API_TOKEN?: string;
}

export type AdminAuthResult =
  | {
      authorized: true;
      status: AdminAuthInfo;
    }
  | {
      authorized: false;
      httpStatus: 401 | 403;
      code: "MISSING_CF_ACCESS_JWT" | "INVALID_CF_ACCESS_JWT" | "UNCONFIGURED_CF_ACCESS";
      reason: string;
    };

export const DELIVERY_SECURITY_HEADERS: Record<string, string> = {
  "cache-control": "private, no-store, no-cache, must-revalidate",
  pragma: "no-cache",
  "x-robots-tag": "noindex, nofollow, noarchive",
  "x-content-type-options": "nosniff",
};

export function stealthNotFoundResponse(): Response {
  return new Response("404 Not Found\n", {
    status: 404,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      ...DELIVERY_SECURITY_HEADERS,
    },
  });
}

// ============================================================
// 1. Edge IP Brute-Force Sliding-Window Rate Limiter
// ============================================================
interface IpBucket {
  failures: number;
  firstAt: number;
  blockedUntil: number;
  lastLoggedAt: number;
}

const ipFailureMap = new Map<string, IpBucket>();
const FAILURE_WINDOW_MS = 5 * 60 * 1000; // 5 minutes
const LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes lockout after 8 failed probes
const MAX_FAILURES = 8;

export function isIpLockedOut(ip: string): boolean {
  const now = Date.now();
  if (ipFailureMap.size > 1000) {
    for (const [k, v] of ipFailureMap) {
      if (v.blockedUntil < now && now - v.firstAt > FAILURE_WINDOW_MS) {
        ipFailureMap.delete(k);
      }
    }
  }
  const bucket = ipFailureMap.get(ip);
  if (!bucket) return false;
  if (bucket.blockedUntil > now) return true;
  if (now - bucket.firstAt > FAILURE_WINDOW_MS) {
    ipFailureMap.delete(ip);
    return false;
  }
  return false;
}

/**
 * Records an authentication failure for `ip`.
 * Returns `shouldLogToDb`: throttles D1 writes if a scanner sends hundreds of requests/sec.
 */
export function recordIpAuthFailure(ip: string): { lockedOut: boolean; shouldLogToDb: boolean } {
  const now = Date.now();
  let bucket = ipFailureMap.get(ip);
  if (!bucket || (bucket.blockedUntil <= now && now - bucket.firstAt > FAILURE_WINDOW_MS)) {
    bucket = { failures: 0, firstAt: now, blockedUntil: 0, lastLoggedAt: 0 };
    ipFailureMap.set(ip, bucket);
  }
  bucket.failures += 1;
  if (bucket.failures >= MAX_FAILURES) {
    bucket.blockedUntil = now + LOCKOUT_MS;
  }
  const shouldLogToDb = now - bucket.lastLoggedAt >= 5000 && bucket.failures <= MAX_FAILURES;
  if (shouldLogToDb) {
    bucket.lastLoggedAt = now;
  }
  return { lockedOut: bucket.blockedUntil > now, shouldLogToDb };
}

// ============================================================
// 2. Cloudflare Access RS256 JWT / JWKS Verifier
// ============================================================
interface CachedJwks {
  issuer: string;
  fetchedAt: number;
  keys: Map<string, CryptoKey>;
}

let jwksCache: CachedJwks | null = null;
const JWKS_TTL_MS = 10 * 60 * 1000; // 10 minutes
let lastForcedRefreshAt = 0;

function normalizeTeamDomain(raw: string): string {
  let clean = raw.trim().replace(/\/+$/, "");
  if (!clean) return "";
  if (!/^https?:\/\//i.test(clean)) {
    if (!clean.includes(".")) {
      clean = `${clean}.cloudflareaccess.com`;
    }
    clean = `https://${clean}`;
  }
  return clean;
}

function base64UrlToBytes(input: string): Uint8Array<ArrayBuffer> {
  const pad = "=".repeat((4 - (input.length % 4)) % 4);
  const b64 = (input + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

function decodeJwtSegment<T>(seg: string): T {
  const bytes = base64UrlToBytes(seg);
  return JSON.parse(new TextDecoder().decode(bytes)) as T;
}

function extractCookieValue(cookieHeader: string | null, name: string): string | null {
  if (!cookieHeader) return null;
  const parts = cookieHeader.split(";");
  for (const part of parts) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) {
      return part.slice(eq + 1).trim();
    }
  }
  return null;
}

async function getCloudflarePublicKey(issuer: string, kid: string): Promise<CryptoKey | null> {
  const now = Date.now();
  if (jwksCache && jwksCache.issuer === issuer && now - jwksCache.fetchedAt < JWKS_TTL_MS) {
    const hit = jwksCache.keys.get(kid);
    if (hit) return hit;
    if (now - lastForcedRefreshAt < 30000) {
      return null;
    }
    lastForcedRefreshAt = now;
  }

  const certsUrl = `${issuer}/cdn-cgi/access/certs`;
  const resp = await fetch(certsUrl, {
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(8000),
  });
  if (!resp.ok) {
    throw new Error(`Failed to fetch Cloudflare Access JWKS (HTTP ${resp.status})`);
  }

  const data = await resp.json<{ keys?: Array<JsonWebKey & { kid?: string }> }>();
  const keyMap = new Map<string, CryptoKey>();

  for (const jwk of data.keys || []) {
    if (!jwk.kid || jwk.kty !== "RSA") continue;
    try {
      const cryptoKey = await crypto.subtle.importKey(
        "jwk",
        jwk,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["verify"]
      );
      keyMap.set(jwk.kid, cryptoKey);
    } catch {
      // Ignore unsupported key entries
    }
  }

  jwksCache = { issuer, fetchedAt: now, keys: keyMap };
  return keyMap.get(kid) || null;
}

function isLocalhostHost(hostname: string): boolean {
  return (
    hostname === "127.0.0.1" ||
    hostname === "localhost" ||
    hostname === "[::1]" ||
    hostname.endsWith(".localhost")
  );
}

export async function verifyAdminAccess(req: Request, env: AuthEnv): Promise<AdminAuthResult> {
  const rawTeam = (env.CF_ACCESS_TEAM_DOMAIN || "").trim();
  const rawAud = (env.CF_ACCESS_AUD || "").trim();
  const hostname = new URL(req.url).hostname;

  // 1. If CF Access env vars are not configured:
  //    Allow local development on 127.0.0.1 / localhost, fail-closed on public deployments!
  if (!rawTeam || !rawAud) {
    if (isLocalhostHost(hostname)) {
      return {
        authorized: true,
        status: {
          mode: "local_dev",
          configured: false,
          email: null,
          team_domain: null,
          logout_url: null,
        },
      };
    }
    return {
      authorized: false,
      httpStatus: 403,
      code: "UNCONFIGURED_CF_ACCESS",
      reason:
        "公网环境已启用安全默认锁定：请配置 Worker 环境变量 CF_ACCESS_TEAM_DOMAIN 与 CF_ACCESS_AUD 后访问管理后台。",
    };
  }

  // 2. Verify Cloudflare Access JWT
  const issuer = normalizeTeamDomain(rawTeam);
  const allowedAuds = new Set(
    rawAud
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
  );

  const token =
    req.headers.get("cf-access-jwt-assertion") ||
    extractCookieValue(req.headers.get("cookie"), "CF_Authorization");

  if (!token) {
    return {
      authorized: false,
      httpStatus: 401,
      code: "MISSING_CF_ACCESS_JWT",
      reason: "未检测到 Cloudflare Access 登录凭证（Cf-Access-Jwt-Assertion），请通过受保护域名登录。",
    };
  }

  try {
    const segments = token.split(".");
    if (segments.length !== 3) {
      throw new Error("Malformed JWT");
    }

    const header = decodeJwtSegment<{ alg?: string; kid?: string }>(segments[0]);
    if (header.alg !== "RS256" || !header.kid) {
      throw new Error("Unsupported JWT algorithm or missing kid");
    }

    const payload = decodeJwtSegment<{
      aud?: string | string[];
      iss?: string;
      exp?: number;
      nbf?: number;
      email?: string;
      sub?: string;
    }>(segments[1]);

    const nowSec = Math.floor(Date.now() / 1000);
    if (!payload.exp || payload.exp <= nowSec - 30) {
      throw new Error("Cloudflare Access JWT has expired");
    }
    if (payload.nbf && payload.nbf > nowSec + 30) {
      throw new Error("Cloudflare Access JWT not yet valid");
    }
    if (!payload.iss || payload.iss.replace(/\/+$/, "") !== issuer) {
      throw new Error(`JWT issuer mismatch (expected ${issuer})`);
    }

    const tokenAuds = Array.isArray(payload.aud) ? payload.aud : payload.aud ? [payload.aud] : [];
    if (!tokenAuds.some((a) => allowedAuds.has(a))) {
      throw new Error("JWT audience (AUD) mismatch");
    }

    const pubKey = await getCloudflarePublicKey(issuer, header.kid);
    if (!pubKey) {
      throw new Error("Matching Cloudflare Access public key not found");
    }

    const signedData = new TextEncoder().encode(`${segments[0]}.${segments[1]}`);
    const signature = base64UrlToBytes(segments[2]);
    const valid = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      pubKey,
      signature,
      signedData
    );
    if (!valid) {
      throw new Error("Invalid RSA signature on Cloudflare Access JWT");
    }

    const email =
      payload.email ||
      req.headers.get("cf-access-authenticated-user-email") ||
      payload.sub ||
      "Authenticated";

    return {
      authorized: true,
      status: {
        mode: "cf_access",
        configured: true,
        email,
        team_domain: issuer,
        logout_url: "/cdn-cgi/access/logout",
      },
    };
  } catch (err) {
    return {
      authorized: false,
      httpStatus: 403,
      code: "INVALID_CF_ACCESS_JWT",
      reason: `Cloudflare Access 凭证校验失败：${err instanceof Error ? err.message : "Invalid token"}`,
    };
  }
}

export type McpAuthResult =
  | { authorized: true; method: "bearer_token" | "cf_access" | "local_dev" }
  | { authorized: false; httpStatus: 401 | 403; code: string; reason: string };

/**
 * Authenticates requests to `/mcp`:
 * 1. If a Bearer / `X-MCP-Token` header is present, verify in constant time against `dbMcpToken` (platform rotatable token) or optional `env.MCP_API_TOKEN`.
 * 2. Otherwise, allow valid Cloudflare Access JWT (e.g. Service Token or browser session).
 * 3. On localhost without `MCP_API_TOKEN` or CF Access configured, allow local development access; fail-closed on public hosts.
 */
export async function verifyMcpAccess(
  req: Request,
  env: AuthEnv,
  dbMcpToken?: string
): Promise<McpAuthResult> {
  const envToken = (env.MCP_API_TOKEN || "").trim();
  const storedToken = (dbMcpToken || "").trim();
  const validTokens = [storedToken, envToken].filter(Boolean);

  const authHeader = req.headers.get("authorization") || "";
  const bearerMatch = authHeader.match(/^Bearer\s+(.+)$/i);
  const providedToken = (bearerMatch?.[1] || req.headers.get("x-mcp-token") || "").trim();

  if (providedToken) {
    if (validTokens.length === 0) {
      return {
        authorized: false,
        httpStatus: 403,
        code: "MCP_TOKEN_NOT_CONFIGURED",
        reason: "服务端未配置 MCP Token，无法使用 Bearer Token 鉴权。",
      };
    }
    if (validTokens.some((candidate) => timingSafeEqualStr(providedToken, candidate))) {
      return { authorized: true, method: "bearer_token" };
    }
    return {
      authorized: false,
      httpStatus: 401,
      code: "INVALID_MCP_TOKEN",
      reason: "MCP Bearer Token 无效。",
    };
  }

  const cfTeam = (env.CF_ACCESS_TEAM_DOMAIN || "").trim();
  const cfAud = (env.CF_ACCESS_AUD || "").trim();
  if (cfTeam && cfAud) {
    const cfResult = await verifyAdminAccess(req, env);
    if (cfResult.authorized) {
      return { authorized: true, method: "cf_access" };
    }
    if (validTokens.length > 0) {
      return {
        authorized: false,
        httpStatus: 401,
        code: "MISSING_MCP_AUTH",
        reason: "缺少鉴权凭证：请提供 Authorization: Bearer <MCP_TOKEN> 或有效 Cloudflare Access 凭证。",
      };
    }
    return {
      authorized: false,
      httpStatus: cfResult.httpStatus,
      code: cfResult.code,
      reason: cfResult.reason,
    };
  }

  const hostname = new URL(req.url).hostname;
  if (!envToken && isLocalhostHost(hostname)) {
    return { authorized: true, method: "local_dev" };
  }

  if (validTokens.length > 0) {
    return {
      authorized: false,
      httpStatus: 401,
      code: "MISSING_MCP_TOKEN",
      reason: "缺少 MCP 鉴权凭证：请在请求头中携带 Authorization: Bearer <MCP_TOKEN>。",
    };
  }

  return {
    authorized: false,
    httpStatus: 403,
    code: "UNCONFIGURED_MCP_AUTH",
    reason: "公网环境默认锁定：请配置 MCP Token 后使用 /mcp。",
  };
}
