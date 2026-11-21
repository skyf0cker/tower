import { Hono } from "hono";
import {
  deriveRuleSetSignature,
  generateHighEntropyMcpToken,
  generateHighEntropySubToken,
  timingSafeEqualStr,
} from "../shared/hmac";
import type { AdminAuthInfo } from "../shared/types";
import {
  type AuthEnv,
  DELIVERY_SECURITY_HEADERS,
  isIpLockedOut,
  recordIpAuthFailure,
  stealthNotFoundResponse,
  verifyAdminAccess,
  verifyMcpAccess,
} from "./auth";
import {
  buildDashboardSnapshot,
  ensureInitialized,
  fetchUpstreamContent,
  getSettings,
  listNodes,
  listPolicyGroups,
  listRules,
  listSubscriptions,
  rebuildNodePool,
  recordAccessLog,
  resetAllData,
  saveSettings,
  upsertPolicyGroupsFromBundle,
} from "./db";
import { compileSurgeProfile, compileStashYaml, detectSurge6FromUa } from "./engine/compiler";
import { parseFullConfigBundle, parseSubscriptionUserInfo } from "./engine/parser";
import { simulateRoute } from "./engine/simulator";
import { handleMcpPost } from "./mcp";
import { probeNodes } from "./probe";

export interface Env extends AuthEnv {
  DB: D1Database;
  ASSETS?: Fetcher;
}

const app = new Hono<{
  Bindings: Env;
  Variables: { authStatus: AdminAuthInfo };
}>();

const BOT_AND_PREVIEW_UA_REGEX =
  /(python-httpx|python-requests|aiohttp|scrapy|sqlmap|masscan|zgrab|nmap|nikto|TelegramBot|Slackbot|Discordbot|WhatsApp|facebookexternalhit|Twitterbot|MicroMessenger|DingTalkBot|LarkUrlPreview)/i;

const PROXY_CLIENT_UA_REGEX =
  /(Surge|Stash|Clash|mihomo|Shadowrocket|Quantumult|Loon|sing-box|v2ray|Hiddify|FlClash|ClashVerge)/i;

app.use("*", async (c, next) => {
  await ensureInitialized(c.env.DB);
  await next();
});

// ============================================================
// 1. Unified Subscription Delivery Endpoint (/sub/:token)
// ============================================================
app.get("/sub/:token", async (c) => {
  const start = Date.now();
  const ip =
    c.req.header("cf-connecting-ip") ||
    c.req.header("x-forwarded-for")?.split(",")[0]?.trim() ||
    "127.0.0.1";

  if (isIpLockedOut(ip)) {
    return stealthNotFoundResponse();
  }

  const db = c.env.DB;
  const settings = await getSettings(db);
  const token = c.req.param("token");
  const ua = c.req.header("user-agent") || "Unknown Client";
  const cf = (c.req.raw as Request & { cf?: { city?: string; country?: string; asOrganization?: string } }).cf;
  const ispGeo =
    cf?.city || cf?.asOrganization
      ? [cf.city || cf.country, cf.asOrganization].filter(Boolean).join(" · ")
      : ip === "127.0.0.1"
        ? "本地回环 (Localhost)"
        : "Direct";

  const tokenOk = timingSafeEqualStr(token, settings.sub_token);
  const isSuspiciousBot = settings.ua_guard_enabled && BOT_AND_PREVIEW_UA_REGEX.test(ua);
  const failsStrictAllowlist = settings.strict_client_ua && !PROXY_CLIENT_UA_REGEX.test(ua);

  if (!tokenOk || isSuspiciousBot || failsStrictAllowlist) {
    const { shouldLogToDb, lockedOut } = recordIpAuthFailure(ip);
    if (shouldLogToDb) {
      const reason = !tokenOk
        ? lockedOut
          ? "Token 错误过多 · IP 临时封禁"
          : "Token 校验失败 · 伪装 404"
        : isSuspiciousBot
          ? "爬虫/预览机器人 UA 拦截"
          : "非代理客户端 UA 拦截 (白名单)";
      await recordAccessLog(db, {
        client_tag: "BLOCK",
        device_ua: ua.slice(0, 64),
        ip,
        isp_geo: reason,
        status_code: 404,
        status_label: "404 伪装拦截",
        target_format: "blocked",
        latency_ms: Math.max(1, Date.now() - start),
      });
    }
    return stealthNotFoundResponse();
  }

  const queryTarget = c.req.query("target")?.toLowerCase();
  let format: "surge" | "surge6" | "stash" = "surge";
  let clientTag: "SURGE" | "STASH" | "CLASH" | "BROWSER" = "BROWSER";

  if (queryTarget === "stash" || queryTarget === "clash" || queryTarget === "yaml") {
    format = "stash";
    clientTag = queryTarget === "clash" ? "CLASH" : "STASH";
  } else if (queryTarget === "surge6") {
    format = "surge6";
    clientTag = "SURGE";
  } else if (queryTarget === "surge" || queryTarget === "surge5") {
    format = "surge";
    clientTag = "SURGE";
  } else if (/Stash/i.test(ua)) {
    format = "stash";
    clientTag = "STASH";
  } else if (/(Clash|mihomo|Shadowrocket)/i.test(ua)) {
    format = "stash";
    clientTag = "CLASH";
  } else if (/Surge/i.test(ua)) {
    format = detectSurge6FromUa(ua) ? "surge6" : "surge";
    clientTag = "SURGE";
  }

  const origin = new URL(c.req.url).origin;
  const [subs, nodes, rules] = await Promise.all([
    listSubscriptions(db),
    listNodes(db),
    listRules(db),
  ]);
  const groups = await listPolicyGroups(db, nodes);

  const vlessQuery = c.req.query("vless");
  const enableVless = vlessQuery === "1" ? true : vlessQuery === "0" ? false : format === "surge6";
  const body =
    format === "stash"
      ? compileStashYaml({ origin, settings, nodes, groups, rules })
      : compileSurgeProfile({
          origin,
          settings,
          nodes,
          groups,
          rules,
          target: format === "surge6" ? "surge6" : "surge",
          enableVless,
        });

  const targetFormat = format === "stash" ? "stash" : enableVless ? "surge6" : "surge";
  const filename =
    format === "stash"
      ? `Tower-v${settings.revision}.yaml`
      : enableVless
        ? `Tower-Surge6-v${settings.revision}.conf`
        : `Tower-v${settings.revision}.conf`;

  const activeQuotaSubs = subs.filter((s) => s.enabled && !s.is_unlimited && s.total_gb > 0);
  const usedBytes = Math.round(activeQuotaSubs.reduce((acc, s) => acc + s.used_gb, 0) * 1024 ** 3);
  const totalBytes = Math.round(activeQuotaSubs.reduce((acc, s) => acc + s.total_gb, 0) * 1024 ** 3);

  await recordAccessLog(db, {
    client_tag: clientTag,
    device_ua: ua.length > 54 ? `${ua.slice(0, 54)}…` : ua,
    ip,
    isp_geo: ispGeo,
    status_code: 200,
    status_label: "200 OK",
    target_format: targetFormat,
    latency_ms: Math.max(1, Date.now() - start),
  });

  const headers: Record<string, string> = {
    "content-type": "text/plain; charset=utf-8",
    "profile-update-interval": "12",
    "content-disposition": `inline; filename="${filename}"`,
    ...DELIVERY_SECURITY_HEADERS,
  };
  if (totalBytes > 0) {
    headers["subscription-userinfo"] = `upload=0; download=${usedBytes}; total=${totalBytes}`;
  }

  return new Response(body, { status: 200, headers });
});

// ============================================================
// 2. Hosted Rule-Set Provider Endpoint (/r/:name)
// ============================================================
const BUILTIN_HOSTED_RULESETS: Record<string, string[]> = {
  "ai-suite.list": [
    "# Tower Built-in Rule-Set · AI & LLM Suite",
    "DOMAIN-SUFFIX,openai.com",
    "DOMAIN-SUFFIX,chatgpt.com",
    "DOMAIN-SUFFIX,oaistatic.com",
    "DOMAIN-SUFFIX,anthropic.com",
    "DOMAIN-SUFFIX,claude.ai",
    "DOMAIN-SUFFIX,gemini.google.com",
    "DOMAIN-SUFFIX,generativelanguage.googleapis.com",
    "DOMAIN-SUFFIX,perplexity.ai",
    "DOMAIN-SUFFIX,cursor.sh",
    "DOMAIN-SUFFIX,cursor.com",
  ],
  "streaming.list": [
    "# Tower Built-in Rule-Set · International Streaming",
    "DOMAIN-SUFFIX,netflix.com",
    "DOMAIN-SUFFIX,nflxvideo.net",
    "DOMAIN-SUFFIX,youtube.com",
    "DOMAIN-SUFFIX,googlevideo.com",
    "DOMAIN-SUFFIX,spotify.com",
    "DOMAIN-SUFFIX,disneyplus.com",
  ],
  "telegram-cidr.list": [
    "# Tower Built-in Rule-Set · Telegram IP-CIDR",
    "IP-CIDR,91.108.4.0/22,no-resolve",
    "IP-CIDR,91.108.8.0/22,no-resolve",
    "IP-CIDR,149.154.160.0/20,no-resolve",
  ],
  "reject-telemetry.list": [
    "# Tower Built-in Rule-Set · Ad & Telemetry Reject",
    "DOMAIN-SUFFIX,doubleclick.net",
    "DOMAIN-SUFFIX,googlesyndication.com",
    "DOMAIN-SUFFIX,app-measurement.com",
  ],
};

app.get("/r/:name", async (c) => {
  const start = Date.now();
  const ip =
    c.req.header("cf-connecting-ip") ||
    c.req.header("x-forwarded-for")?.split(",")[0]?.trim() ||
    "127.0.0.1";

  if (isIpLockedOut(ip)) {
    return stealthNotFoundResponse();
  }

  const name = c.req.param("name").trim();
  const sig = (c.req.query("sig") || "").trim();
  const ua = c.req.header("user-agent") || "Unknown Client";
  const settings = await getSettings(c.env.DB);
  const expectedSig = deriveRuleSetSignature(settings.sub_token, name);

  const sigOk = sig.length > 0 && timingSafeEqualStr(sig, expectedSig);
  const isSuspiciousBot = settings.ua_guard_enabled && BOT_AND_PREVIEW_UA_REGEX.test(ua);

  if (!sigOk || isSuspiciousBot || !BUILTIN_HOSTED_RULESETS[name]) {
    const { shouldLogToDb } = recordIpAuthFailure(ip);
    if (shouldLogToDb) {
      await recordAccessLog(c.env.DB, {
        client_tag: "BLOCK",
        device_ua: ua.slice(0, 64),
        ip,
        isp_geo: !sigOk
          ? `Rule-Set 签名无效 (${name.slice(0, 24)})`
          : isSuspiciousBot
            ? "Rule-Set 爬虫 UA 拦截"
            : `未知 Rule-Set (${name.slice(0, 24)})`,
        status_code: 404,
        status_label: "404 伪装拦截",
        target_format: "ruleset",
        latency_ms: Math.max(1, Date.now() - start),
      });
    }
    return stealthNotFoundResponse();
  }

  const lines = BUILTIN_HOSTED_RULESETS[name];
  return new Response(lines.join("\n") + "\n", {
    status: 200,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      ...DELIVERY_SECURITY_HEADERS,
    },
  });
});

// ============================================================
// 3. Remote MCP Server Endpoint (/mcp) — Streamable HTTP (Stateless)
// ============================================================
const MCP_CORS_HEADERS: Record<string, string> = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "POST, GET, DELETE, OPTIONS",
  "access-control-allow-headers": "content-type, authorization, x-mcp-token, mcp-session-id, mcp-protocol-version",
  ...DELIVERY_SECURITY_HEADERS,
};

app.options("/mcp", () => new Response(null, { status: 204, headers: MCP_CORS_HEADERS }));

app.get("/mcp", () =>
  new Response("Method Not Allowed: Tower MCP uses stateless Streamable HTTP over POST.", {
    status: 405,
    headers: { allow: "POST, OPTIONS, DELETE", ...MCP_CORS_HEADERS },
  })
);

app.delete("/mcp", () => new Response(null, { status: 204, headers: MCP_CORS_HEADERS }));

app.post("/mcp", async (c) => {
  const ip =
    c.req.header("cf-connecting-ip") ||
    c.req.header("x-forwarded-for")?.split(",")[0]?.trim() ||
    "127.0.0.1";

  if (isIpLockedOut(ip)) {
    return c.json({ error: "RATE_LIMITED", message: "鉴权失败次数过多，请稍后重试。" }, 429, MCP_CORS_HEADERS);
  }

  const settings = await getSettings(c.env.DB);
  const authResult = await verifyMcpAccess(c.req.raw, c.env, settings.mcp_token);
  if (!authResult.authorized) {
    if (authResult.code === "INVALID_MCP_TOKEN") {
      recordIpAuthFailure(ip);
    }
    return c.json(
      { error: authResult.code, message: authResult.reason },
      authResult.httpStatus,
      MCP_CORS_HEADERS
    );
  }

  const origin = new URL(c.req.url).origin;
  const resp = await handleMcpPost(c.req.raw, { db: c.env.DB, origin });
  const headers = new Headers(resp.headers);
  for (const [k, v] of Object.entries(MCP_CORS_HEADERS)) {
    headers.set(k, v);
  }
  return new Response(resp.body, { status: resp.status, headers });
});

// ============================================================
// 4. Management Plane REST API (/api/*) — Protected by Cloudflare Access
// ============================================================
app.use("/api/*", async (c, next) => {
  const authResult = await verifyAdminAccess(c.req.raw, c.env);
  if (!authResult.authorized) {
    return c.json(
      {
        error: authResult.code,
        message: authResult.reason,
      },
      authResult.httpStatus,
      DELIVERY_SECURITY_HEADERS
    );
  }
  c.set("authStatus", authResult.status);
  await next();
});

app.get("/api/bootstrap", async (c) => {
  const origin = new URL(c.req.url).origin;
  return c.json(await buildDashboardSnapshot(c.env.DB, origin, c.get("authStatus")), 200, DELIVERY_SECURITY_HEADERS);
});

app.post("/api/reset", async (c) => {
  await resetAllData(c.env.DB);
  const origin = new URL(c.req.url).origin;
  return c.json(await buildDashboardSnapshot(c.env.DB, origin, c.get("authStatus")));
});

app.post("/api/sync", async (c) => {
  await rebuildNodePool(c.env.DB, true);
  const origin = new URL(c.req.url).origin;
  return c.json(await buildDashboardSnapshot(c.env.DB, origin, c.get("authStatus")));
});

// Subscriptions CRUD & Single-Source Sync / Group Extraction
app.post("/api/subscriptions", async (c) => {
  const body = await c.req.json<{
    name: string;
    url?: string;
    fetch_ua?: string;
    fetch_proxy?: string;
    protocol_hint?: string;
    inline_content?: string;
    import_rules_and_groups?: boolean;
  }>();

  const id = `sub_${Date.now().toString(36)}`;
  const now = Date.now();
  const rawUrl = (body.url || "").trim();
  const fetchUa = body.fetch_ua || "auto";
  const fetchProxy = (body.fetch_proxy || "").trim();
  let inlineContent = body.inline_content || "";
  let usedGb = 0;
  let totalGb = 0;
  let expireAt: number | null = null;
  let isUnlimited = 1;
  let lastStatus = rawUrl ? "200 OK" : "本地导入";

  if (rawUrl.startsWith("http://") || rawUrl.startsWith("https://")) {
    try {
      const fetched = await fetchUpstreamContent(rawUrl, fetchUa, fetchProxy);
      inlineContent = fetched.text;
      lastStatus = fetched.statusLabel;
      const quota = parseSubscriptionUserInfo(fetched.userInfoHeader);
      if (quota) {
        usedGb = quota.used_gb;
        totalGb = quota.total_gb;
        expireAt = quota.expire_at;
        isUnlimited = 0;
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : "远程拉取失败";
      if (!inlineContent.trim()) {
        return c.json(
          {
            error: fetchProxy
              ? `通过前置代理拉取失败 (${msg})，请检查 SOCKS5/HTTP 代理地址与账号密码`
              : `无法拉取该订阅链接 (${msg})，可在下方展开「高级配置」配置 SOCKS5 代理拉取，或直接粘贴内容`,
          },
          400
        );
      }
      lastStatus = msg;
    }
  }

  const bundle = parseFullConfigBundle(inlineContent);
  if (bundle.nodes.length === 0 && bundle.rules.length === 0 && bundle.policy_groups.length === 0) {
    return c.json(
      {
        error:
          "未从输入内容中解析出任何有效代理节点（支持 Clash/Stash YAML、Surge .conf、Base64 及 ss/vmess/vless/trojan/hy2/tuic 链接）",
      },
      400
    );
  }

  await c.env.DB.prepare(
    `INSERT INTO subscriptions (id, name, url, fetch_ua, fetch_proxy, protocol_hint, enabled, inline_content, used_gb, total_gb, expire_at, is_unlimited, last_sync_at, last_status, note, created_at)
     VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, '', ?)`
  )
    .bind(
      id,
      body.name.trim(),
      rawUrl || "local://imported-file",
      fetchUa,
      fetchProxy,
      body.protocol_hint?.trim() || bundle.protocol_summary,
      inlineContent,
      usedGb,
      totalGb,
      expireAt,
      isUnlimited,
      now,
      lastStatus,
      now
    )
    .run();

  if (body.import_rules_and_groups) {
    if (bundle.policy_groups.length > 0) {
      await upsertPolicyGroupsFromBundle(c.env.DB, bundle.policy_groups, false);
    }
    for (const r of bundle.rules) {
      const rid = `rl_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 5)}`;
      await c.env.DB.prepare(
        `INSERT INTO rules (id, kind, rule_type, title, payload, target_policy, rule_count, no_resolve, sync_meta, enabled, priority)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`
      )
        .bind(
          rid,
          r.kind,
          r.rule_type,
          r.title,
          r.payload,
          r.target_policy,
          r.rule_count,
          r.no_resolve ? 1 : 0,
          r.sync_meta,
          r.priority
        )
        .run();
    }
  }

  await saveSettings(c.env.DB, { last_full_sync_at: now });
  await rebuildNodePool(c.env.DB, false);
  return c.json(await buildDashboardSnapshot(c.env.DB, new URL(c.req.url).origin, c.get("authStatus")));
});

app.patch("/api/subscriptions/:id", async (c) => {
  const id = c.req.param("id");
  const body = await c.req.json<{
    enabled?: boolean;
    name?: string;
    url?: string;
    fetch_ua?: string;
    fetch_proxy?: string;
    note?: string;
    inline_content?: string;
  }>();

  if (typeof body.enabled === "boolean") {
    await c.env.DB.prepare(`UPDATE subscriptions SET enabled = ? WHERE id = ?`)
      .bind(body.enabled ? 1 : 0, id)
      .run();
  }
  if (typeof body.name === "string") {
    await c.env.DB.prepare(
      `UPDATE subscriptions
       SET name = ?,
           url = COALESCE(?, url),
           fetch_ua = COALESCE(?, fetch_ua),
           fetch_proxy = COALESCE(?, fetch_proxy),
           note = COALESCE(?, note),
           inline_content = COALESCE(?, inline_content)
       WHERE id = ?`
    )
      .bind(
        body.name.trim(),
        body.url?.trim() ?? null,
        body.fetch_ua ?? null,
        typeof body.fetch_proxy === "string" ? body.fetch_proxy.trim() : null,
        body.note ?? null,
        body.inline_content ?? null,
        id
      )
      .run();
  }

  await rebuildNodePool(c.env.DB, false);
  return c.json(await buildDashboardSnapshot(c.env.DB, new URL(c.req.url).origin, c.get("authStatus")));
});

app.post("/api/subscriptions/:id/sync", async (c) => {
  const id = c.req.param("id");
  const subs = await listSubscriptions(c.env.DB);
  const target = subs.find((s) => s.id === id);
  if (!target) return c.json({ error: "订阅源不存在" }, 404);

  const now = Date.now();
  if (target.url.startsWith("http://") || target.url.startsWith("https://")) {
    try {
      const fetched = await fetchUpstreamContent(target.url, target.fetch_ua, target.fetch_proxy);
      const quota = parseSubscriptionUserInfo(fetched.userInfoHeader);
      const bundle = parseFullConfigBundle(fetched.text);
      await c.env.DB.prepare(
        `UPDATE subscriptions
         SET inline_content = ?,
             used_gb = COALESCE(?, used_gb),
             total_gb = COALESCE(?, total_gb),
             expire_at = COALESCE(?, expire_at),
             is_unlimited = CASE WHEN ? IS NOT NULL THEN 0 ELSE is_unlimited END,
             protocol_hint = ?,
             last_sync_at = ?,
             last_status = ?
         WHERE id = ?`
      )
        .bind(
          fetched.text,
          quota?.used_gb ?? null,
          quota?.total_gb ?? null,
          quota?.expire_at ?? null,
          quota?.total_gb ?? null,
          bundle.protocol_summary,
          now,
          fetched.statusLabel,
          id
        )
        .run();
    } catch (err) {
      const msg = err instanceof Error ? err.message : "拉取失败";
      await c.env.DB.prepare(`UPDATE subscriptions SET last_sync_at = ?, last_status = ? WHERE id = ?`)
        .bind(now, msg, id)
        .run();
      return c.json({ error: `同步失败：${msg}` }, 400);
    }
  } else {
    await c.env.DB.prepare(`UPDATE subscriptions SET last_sync_at = ?, last_status = '本地导入' WHERE id = ?`)
      .bind(now, id)
      .run();
  }

  await rebuildNodePool(c.env.DB, false);
  return c.json(await buildDashboardSnapshot(c.env.DB, new URL(c.req.url).origin, c.get("authStatus")));
});

app.post("/api/subscriptions/:id/sync-groups", async (c) => {
  const id = c.req.param("id");
  const body = await c.req.json<{ replace_groups?: boolean; sync_rules?: boolean }>().catch(() => ({
    replace_groups: false,
    sync_rules: false,
  }));
  const subs = await listSubscriptions(c.env.DB);
  const target = subs.find((s) => s.id === id);
  if (!target) return c.json({ error: "订阅源不存在" }, 404);

  const bundle = parseFullConfigBundle(target.inline_content);
  if (bundle.policy_groups.length === 0 && bundle.rules.length === 0) {
    return c.json({ error: "该订阅源内容中未包含任何策略组或规则定义" }, 400);
  }

  if (bundle.policy_groups.length > 0) {
    await upsertPolicyGroupsFromBundle(c.env.DB, bundle.policy_groups, Boolean(body.replace_groups));
  }

  if (body.sync_rules && bundle.rules.length > 0) {
    if (body.replace_groups) {
      await c.env.DB.prepare(`DELETE FROM rules`).run();
    }
    for (const r of bundle.rules) {
      const rid = `rl_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 5)}`;
      await c.env.DB.prepare(
        `INSERT INTO rules (id, kind, rule_type, title, payload, target_policy, rule_count, no_resolve, sync_meta, enabled, priority)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`
      )
        .bind(
          rid,
          r.kind,
          r.rule_type,
          r.title,
          r.payload,
          r.target_policy,
          r.rule_count,
          r.no_resolve ? 1 : 0,
          r.sync_meta,
          r.priority
        )
        .run();
    }
  }

  return c.json(await buildDashboardSnapshot(c.env.DB, new URL(c.req.url).origin, c.get("authStatus")));
});

app.delete("/api/subscriptions/:id", async (c) => {
  const id = c.req.param("id");
  await c.env.DB.prepare(`DELETE FROM subscriptions WHERE id = ?`).bind(id).run();
  await rebuildNodePool(c.env.DB, false);
  return c.json(await buildDashboardSnapshot(c.env.DB, new URL(c.req.url).origin, c.get("authStatus")));
});

app.put("/api/settings", async (c) => {
  const body = await c.req.json<Record<string, unknown>>();
  const current = await getSettings(c.env.DB);
  await saveSettings(c.env.DB, {
    rename_template: typeof body.rename_template === "string" ? body.rename_template : current.rename_template,
    exclude_regex: typeof body.exclude_regex === "string" ? body.exclude_regex : current.exclude_regex,
    max_multiplier: typeof body.max_multiplier === "number" ? body.max_multiplier : current.max_multiplier,
    dedup_enabled: typeof body.dedup_enabled === "boolean" ? body.dedup_enabled : current.dedup_enabled,
    ua_guard_enabled: typeof body.ua_guard_enabled === "boolean" ? body.ua_guard_enabled : current.ua_guard_enabled,
    strict_client_ua: typeof body.strict_client_ua === "boolean" ? body.strict_client_ua : current.strict_client_ua,
    revision: body.bump_revision ? current.revision + 1 : current.revision,
  });
  if (
    typeof body.rename_template === "string" ||
    typeof body.exclude_regex === "string" ||
    typeof body.max_multiplier === "number" ||
    typeof body.dedup_enabled === "boolean"
  ) {
    await rebuildNodePool(c.env.DB, false);
  }
  return c.json(await buildDashboardSnapshot(c.env.DB, new URL(c.req.url).origin, c.get("authStatus")));
});

app.put("/api/settings/sub-token", async (c) => {
  const body = await c.req.json<{ sub_token?: string }>();
  const nextToken = (body.sub_token || "").trim();
  if (nextToken.length < 12 || nextToken.length > 128 || !/^[A-Za-z0-9_-]+$/.test(nextToken)) {
    return c.json(
      { error: "订阅 Token 长度需在 12 ~ 128 位之间，且仅允许大小写字母、数字、下划线或连字符" },
      400
    );
  }
  await saveSettings(c.env.DB, { sub_token: nextToken });
  return c.json(await buildDashboardSnapshot(c.env.DB, new URL(c.req.url).origin, c.get("authStatus")));
});

app.post("/api/settings/rotate-token", async (c) => {
  await saveSettings(c.env.DB, { sub_token: generateHighEntropySubToken() });
  return c.json(await buildDashboardSnapshot(c.env.DB, new URL(c.req.url).origin, c.get("authStatus")));
});

app.put("/api/settings/mcp-token", async (c) => {
  const body = await c.req.json<{ mcp_token?: string }>();
  const nextToken = (body.mcp_token || "").trim();
  if (nextToken.length < 12 || nextToken.length > 128 || !/^[A-Za-z0-9_-]+$/.test(nextToken)) {
    return c.json(
      { error: "MCP Token 长度需在 12 ~ 128 位之间，且仅允许大小写字母、数字、下划线或连字符" },
      400
    );
  }
  await saveSettings(c.env.DB, { mcp_token: nextToken });
  return c.json(await buildDashboardSnapshot(c.env.DB, new URL(c.req.url).origin, c.get("authStatus")));
});

app.post("/api/settings/rotate-mcp-token", async (c) => {
  await saveSettings(c.env.DB, { mcp_token: generateHighEntropyMcpToken() });
  return c.json(await buildDashboardSnapshot(c.env.DB, new URL(c.req.url).origin, c.get("authStatus")));
});

// Real TCP Handshake Latency Probe
app.post("/api/nodes/probe", async (c) => {
  const nodes = (await listNodes(c.env.DB)).filter((n) => n.status === "active");
  await probeNodes(c.env.DB, nodes);
  return c.json(await buildDashboardSnapshot(c.env.DB, new URL(c.req.url).origin, c.get("authStatus")));
});

// Policy Groups CRUD (with Cascade Rename across Rules & Parent Groups!)
app.post("/api/policy-groups", async (c) => {
  const body = await c.req.json<{
    name: string;
    type: string;
    filter_regex?: string;
    fallback_groups?: string[];
    interval_sec?: number;
    tolerance_ms?: number;
  }>();
  const cleanName = body.name.trim();
  const existing = await listPolicyGroups(c.env.DB);
  if (existing.some((g) => g.name === cleanName)) {
    return c.json({ error: `策略组「${cleanName}」已存在` }, 400);
  }
  const id = `pg_${Date.now().toString(36)}`;
  await c.env.DB.prepare(
    `INSERT INTO policy_groups (id, name, type, filter_regex, interval_sec, tolerance_ms, fallback_groups_json, sort_order)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      id,
      cleanName,
      body.type || "select",
      body.filter_regex ?? "",
      body.interval_sec || 300,
      body.tolerance_ms || 20,
      JSON.stringify(body.fallback_groups || []),
      existing.length + 1
    )
    .run();
  return c.json(await buildDashboardSnapshot(c.env.DB, new URL(c.req.url).origin, c.get("authStatus")));
});

app.put("/api/policy-groups/:id", async (c) => {
  const id = c.req.param("id");
  const body = await c.req.json<{
    name: string;
    type: string;
    filter_regex: string;
    fallback_groups: string[];
    interval_sec?: number;
    tolerance_ms?: number;
  }>();

  const allGroups = await listPolicyGroups(c.env.DB);
  const current = allGroups.find((g) => g.id === id);
  if (!current) return c.json({ error: "策略组不存在" }, 404);

  const newName = body.name.trim() || current.name;
  if (newName !== current.name && allGroups.some((g) => g.id !== id && g.name === newName)) {
    return c.json({ error: `已存在同名策略组「${newName}」` }, 400);
  }

  await c.env.DB.prepare(
    `UPDATE policy_groups
     SET name = ?, type = ?, filter_regex = ?, fallback_groups_json = ?, interval_sec = ?, tolerance_ms = ?
     WHERE id = ?`
  )
    .bind(
      newName,
      body.type || current.type,
      body.filter_regex ?? "",
      JSON.stringify((body.fallback_groups || []).filter((x) => x !== newName)),
      body.interval_sec ?? current.interval_sec,
      body.tolerance_ms ?? current.tolerance_ms,
      id
    )
    .run();

  // Cascade rename to linked rules & parent groups!
  if (newName !== current.name) {
    await c.env.DB.prepare(`UPDATE rules SET target_policy = ? WHERE target_policy = ?`)
      .bind(newName, current.name)
      .run();

    for (const g of allGroups) {
      if (g.id !== id && g.fallback_groups.includes(current.name)) {
        const updatedFb = g.fallback_groups.map((item) => (item === current.name ? newName : item));
        await c.env.DB.prepare(`UPDATE policy_groups SET fallback_groups_json = ? WHERE id = ?`)
          .bind(JSON.stringify(updatedFb), g.id)
          .run();
      }
    }
  }

  return c.json(await buildDashboardSnapshot(c.env.DB, new URL(c.req.url).origin, c.get("authStatus")));
});

app.delete("/api/policy-groups/:id", async (c) => {
  const id = c.req.param("id");
  const allGroups = await listPolicyGroups(c.env.DB);
  const target = allGroups.find((g) => g.id === id);
  await c.env.DB.prepare(`DELETE FROM policy_groups WHERE id = ?`).bind(id).run();

  if (target) {
    const remaining = allGroups.filter((g) => g.id !== id);
    const sameNameStillExists = remaining.some((g) => g.name === target.name);
    if (!sameNameStillExists) {
      const fallbackName = remaining[0]?.name || "DIRECT";
      await c.env.DB.prepare(`UPDATE rules SET target_policy = ? WHERE target_policy = ?`)
        .bind(fallbackName, target.name)
        .run();
      for (const g of remaining) {
        if (g.fallback_groups.includes(target.name)) {
          const nextFb = g.fallback_groups.filter((x) => x !== target.name);
          await c.env.DB.prepare(`UPDATE policy_groups SET fallback_groups_json = ? WHERE id = ?`)
            .bind(JSON.stringify(nextFb), g.id)
            .run();
        }
      }
    }
  }

  return c.json(await buildDashboardSnapshot(c.env.DB, new URL(c.req.url).origin, c.get("authStatus")));
});

app.post("/api/rules/scaffold", async (c) => {
  const nodes = (await listNodes(c.env.DB)).filter((n) => n.status === "active");
  const presentRegions = Array.from(new Set(nodes.map((n) => n.region).filter((r) => r !== "GLOBAL")));
  const regionLabels: Record<string, string> = {
    HK: "HK · Auto",
    TW: "TW · Auto",
    JP: "JP · Auto",
    SG: "SG · Auto",
    US: "US · Auto",
    KR: "KR · Auto",
    DE: "DE · Auto",
    UK: "UK · Auto",
  };

  const scaffoldGroups = presentRegions.map((rg, idx) => ({
    name: regionLabels[rg] || `${rg} · Auto`,
    type: "url-test" as const,
    filter_regex: `/^${rg}\\b/`,
    interval_sec: 300,
    tolerance_ms: 20,
    fallback_groups: [],
    sort_order: idx + 1,
  }));

  const createdGroupNames = scaffoldGroups.map((g) => g.name);
  scaffoldGroups.unshift({
    name: "Proxy",
    type: "select" as unknown as "url-test",
    filter_regex: "",
    interval_sec: 300,
    tolerance_ms: 20,
    fallback_groups: [...createdGroupNames, "DIRECT"] as unknown as never[],
    sort_order: 0,
  });

  await upsertPolicyGroupsFromBundle(c.env.DB, scaffoldGroups, false);

  const existingRules = await listRules(c.env.DB);
  if (existingRules.length === 0) {
    const aiTarget =
      createdGroupNames.find((n) => n.startsWith("US") || n.startsWith("JP") || n.startsWith("SG")) || "Proxy";
    const mediaTarget =
      createdGroupNames.find((n) => n.startsWith("HK") || n.startsWith("SG") || n.startsWith("TW")) || "Proxy";

    const stdRules = [
      { id: "rl_ai", kind: "ruleset", type: "RULE-SET", title: "AI & LLM 服务分流", payload: "provider/ai-suite.list", policy: aiTarget, count: 10, noRes: 0, prio: 10 },
      { id: "rl_media", kind: "ruleset", type: "RULE-SET", title: "国际流媒体分流", payload: "provider/streaming.list", policy: mediaTarget, count: 6, noRes: 0, prio: 20 },
      { id: "rl_tg", kind: "ruleset", type: "RULE-SET", title: "Telegram IP-CIDR", payload: "provider/telegram-cidr.list", policy: mediaTarget, count: 3, noRes: 1, prio: 30 },
      { id: "rl_cn", kind: "ruleset", type: "GEOIP", title: "国内 IP 直连", payload: "CN", policy: "DIRECT", count: 1, noRes: 0, prio: 40 },
      { id: "rl_ad", kind: "ruleset", type: "RULE-SET", title: "广告与隐私追踪阻断", payload: "provider/reject-telemetry.list", policy: "REJECT-DROP", count: 3, noRes: 0, prio: 50 },
      { id: "rl_final", kind: "ruleset", type: "FINAL", title: "全局兜底路由策略", payload: "dns-failed", policy: "Proxy", count: 1, noRes: 0, prio: 9999 },
    ];

    for (const r of stdRules) {
      await c.env.DB.prepare(
        `INSERT INTO rules (id, kind, rule_type, title, payload, target_policy, rule_count, no_resolve, sync_meta, enabled, priority)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Tower Built-in', 1, ?)`
      )
        .bind(r.id, r.kind, r.type, r.title, r.payload, r.policy, r.count, r.noRes, r.prio)
        .run();
    }
  }

  return c.json(await buildDashboardSnapshot(c.env.DB, new URL(c.req.url).origin, c.get("authStatus")));
});

// Rules CRUD
app.post("/api/rules", async (c) => {
  const body = await c.req.json<{
    kind?: "override" | "ruleset";
    rule_type: string;
    title?: string;
    payload?: string;
    target_policy: string;
    no_resolve?: boolean;
  }>();
  const id = `rl_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 5)}`;
  const rType = body.rule_type.toUpperCase();
  const kind = body.kind || (rType === "RULE-SET" || rType === "GEOIP" || rType === "FINAL" ? "ruleset" : "override");
  const normalizedPayload = (body.payload || "").trim() || (rType === "FINAL" ? "dns-failed" : "");
  const title =
    body.title?.trim() || (rType === "FINAL" ? "全局兜底路由策略" : `${rType} · ${normalizedPayload}`);

  await c.env.DB.prepare(
    `INSERT INTO rules (id, kind, rule_type, title, payload, target_policy, rule_count, no_resolve, sync_meta, enabled, priority)
     VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, 1, ?)`
  )
    .bind(
      id,
      kind,
      rType,
      title,
      normalizedPayload,
      body.target_policy,
      body.no_resolve ? 1 : 0,
      kind === "ruleset" ? "Rule-Set" : "自定义规则",
      rType === "FINAL" ? 9999 : kind === "override" ? 1 : 50
    )
    .run();
  return c.json(await buildDashboardSnapshot(c.env.DB, new URL(c.req.url).origin, c.get("authStatus")));
});

app.put("/api/rules/:id", async (c) => {
  const id = c.req.param("id");
  const body = await c.req.json<{
    rule_type: string;
    title?: string;
    payload?: string;
    target_policy: string;
    no_resolve?: boolean;
    enabled?: boolean;
    priority?: number;
  }>();
  const rType = body.rule_type.toUpperCase();
  const kind = rType === "RULE-SET" || rType === "GEOIP" || rType === "FINAL" ? "ruleset" : "override";
  const normalizedPayload = (body.payload || "").trim() || (rType === "FINAL" ? "dns-failed" : "");
  const title =
    (body.title || "").trim() || (rType === "FINAL" ? "全局兜底路由策略" : `${rType} · ${normalizedPayload}`);

  await c.env.DB.prepare(
    `UPDATE rules
     SET kind = ?, rule_type = ?, title = ?, payload = ?, target_policy = ?, no_resolve = ?, enabled = COALESCE(?, enabled), priority = COALESCE(?, priority)
     WHERE id = ?`
  )
    .bind(
      kind,
      rType,
      title,
      normalizedPayload,
      body.target_policy,
      body.no_resolve ? 1 : 0,
      typeof body.enabled === "boolean" ? (body.enabled ? 1 : 0) : null,
      typeof body.priority === "number" ? body.priority : null,
      id
    )
    .run();

  return c.json(await buildDashboardSnapshot(c.env.DB, new URL(c.req.url).origin, c.get("authStatus")));
});

app.patch("/api/rules/:id", async (c) => {
  const id = c.req.param("id");
  const body = await c.req.json<{ enabled?: boolean; target_policy?: string; priority?: number }>();
  if (typeof body.enabled === "boolean") {
    await c.env.DB.prepare(`UPDATE rules SET enabled = ? WHERE id = ?`).bind(body.enabled ? 1 : 0, id).run();
  }
  if (typeof body.target_policy === "string") {
    await c.env.DB.prepare(`UPDATE rules SET target_policy = ? WHERE id = ?`).bind(body.target_policy, id).run();
  }
  if (typeof body.priority === "number") {
    await c.env.DB.prepare(`UPDATE rules SET priority = ? WHERE id = ?`).bind(body.priority, id).run();
  }
  return c.json(await buildDashboardSnapshot(c.env.DB, new URL(c.req.url).origin, c.get("authStatus")));
});

app.delete("/api/rules/:id", async (c) => {
  const id = c.req.param("id");
  await c.env.DB.prepare(`DELETE FROM rules WHERE id = ?`).bind(id).run();
  return c.json(await buildDashboardSnapshot(c.env.DB, new URL(c.req.url).origin, c.get("authStatus")));
});

app.post("/api/simulate", async (c) => {
  const { target } = await c.req.json<{ target: string }>();
  const [nodes, rules] = await Promise.all([listNodes(c.env.DB), listRules(c.env.DB)]);
  const groups = await listPolicyGroups(c.env.DB, nodes);
  return c.json(simulateRoute(target || "openai.com", rules, groups, nodes));
});

app.post("/api/publish", async (c) => {
  const current = await getSettings(c.env.DB);
  await saveSettings(c.env.DB, { revision: current.revision + 1, last_full_sync_at: Date.now() });
  return c.json(await buildDashboardSnapshot(c.env.DB, new URL(c.req.url).origin, c.get("authStatus")));
});

export default {
  fetch: app.fetch,
  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(
      (async () => {
        await ensureInitialized(env.DB);
        await rebuildNodePool(env.DB, true);
      })()
    );
  },
} satisfies ExportedHandler<Env>;
