import { matchNodesForGroup } from "../shared/groupMatcher";
import { generateHighEntropyMcpToken, generateHighEntropySubToken } from "../shared/hmac";
import type {
  AccessLogItem,
  AdminAuthInfo,
  DashboardSnapshot,
  PolicyGroup,
  ProxyNode,
  RawNodeConfig,
  RoutingRule,
  SubscriptionItem,
  TowerSettings,
} from "../shared/types";
import { compileSurgeProfile, compileStashYaml } from "./engine/compiler";
import { parseFullConfigBundle, parseSubscriptionUserInfo, type RawParsedNode } from "./engine/parser";
import { computePipelineStats, runIntegrationPipeline, type RawSourceBatch } from "./engine/pipeline";
import { fetchViaProxy } from "./proxyFetch";

const SCHEMA_STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS subscriptions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    fetch_ua TEXT NOT NULL DEFAULT 'auto',
    fetch_proxy TEXT NOT NULL DEFAULT '',
    protocol_hint TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    inline_content TEXT NOT NULL DEFAULT '',
    used_gb REAL NOT NULL DEFAULT 0,
    total_gb REAL NOT NULL DEFAULT 0,
    expire_at INTEGER,
    is_unlimited INTEGER NOT NULL DEFAULT 0,
    raw_node_count INTEGER NOT NULL DEFAULT 0,
    valid_node_count INTEGER NOT NULL DEFAULT 0,
    regions_json TEXT NOT NULL DEFAULT '[]',
    last_sync_at INTEGER,
    last_status TEXT NOT NULL DEFAULT '待同步',
    note TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,
    sub_id TEXT NOT NULL,
    sub_name TEXT NOT NULL,
    raw_name TEXT NOT NULL,
    normalized_name TEXT NOT NULL,
    region TEXT NOT NULL,
    line_tag TEXT NOT NULL,
    protocol TEXT NOT NULL,
    server TEXT NOT NULL,
    port INTEGER NOT NULL,
    cipher_or_param TEXT NOT NULL DEFAULT '',
    raw_config_json TEXT NOT NULL DEFAULT '{}',
    multiplier REAL NOT NULL DEFAULT 1.0,
    latency_ms INTEGER,
    fingerprint TEXT NOT NULL,
    merged_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    filter_reason TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS policy_groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'url-test',
    filter_regex TEXT NOT NULL DEFAULT '.*',
    interval_sec INTEGER NOT NULL DEFAULT 300,
    tolerance_ms INTEGER NOT NULL DEFAULT 20,
    fallback_groups_json TEXT NOT NULL DEFAULT '[]',
    sort_order INTEGER NOT NULL DEFAULT 0
  )`,
  `CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL DEFAULT 'override',
    rule_type TEXT NOT NULL,
    title TEXT NOT NULL,
    payload TEXT NOT NULL,
    target_policy TEXT NOT NULL,
    rule_count INTEGER NOT NULL DEFAULT 1,
    no_resolve INTEGER NOT NULL DEFAULT 0,
    sync_meta TEXT NOT NULL DEFAULT 'Local',
    enabled INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL DEFAULT 10
  )`,
  `CREATE TABLE IF NOT EXISTS access_logs (
    id TEXT PRIMARY KEY,
    client_tag TEXT NOT NULL,
    device_ua TEXT NOT NULL,
    ip TEXT NOT NULL,
    isp_geo TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    status_label TEXT NOT NULL,
    target_format TEXT NOT NULL,
    latency_ms INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
  )`,
];

function generateRandomToken(): string {
  return generateHighEntropySubToken();
}

function makeDefaultSettings(): TowerSettings {
  return {
    sub_token: generateRandomToken(),
    mcp_token: generateHighEntropyMcpToken(),
    rename_template: "{REGION} · {LINE_TAG} · {INDEX:02}",
    exclude_regex: "/(剩余流量|套餐到期|官网|群组|维护|故障|重置)/i",
    max_multiplier: 2.0,
    dedup_enabled: true,
    ua_guard_enabled: true,
    strict_client_ua: false,
    cron_interval_min: 30,
    last_full_sync_at: null,
    revision: 1,
  };
}

let schemaChecked = false;

export async function ensureInitialized(db: D1Database): Promise<void> {
  if (!schemaChecked) {
    for (const sql of SCHEMA_STATEMENTS) {
      await db.prepare(sql).run();
    }
    // Safe additive column migrations in case an older local table exists
    await db.prepare(`ALTER TABLE subscriptions ADD COLUMN fetch_ua TEXT NOT NULL DEFAULT 'auto'`).run().catch(() => {});
    await db.prepare(`ALTER TABLE subscriptions ADD COLUMN fetch_proxy TEXT NOT NULL DEFAULT ''`).run().catch(() => {});
    await db.prepare(`ALTER TABLE subscriptions ADD COLUMN expire_at INTEGER`).run().catch(() => {});
    await db.prepare(`ALTER TABLE nodes ADD COLUMN raw_config_json TEXT NOT NULL DEFAULT '{}'`).run().catch(() => {});
    schemaChecked = true;
  }

  const existing = await db.prepare(`SELECT COUNT(*) as cnt FROM settings`).first<{ cnt: number }>();
  if (!existing || existing.cnt === 0) {
    await saveSettings(db, makeDefaultSettings());
  }
}

export async function resetAllData(db: D1Database): Promise<void> {
  await db.prepare(`DELETE FROM subscriptions`).run();
  await db.prepare(`DELETE FROM nodes`).run();
  await db.prepare(`DELETE FROM policy_groups`).run();
  await db.prepare(`DELETE FROM rules`).run();
  await db.prepare(`DELETE FROM access_logs`).run();
  await db.prepare(`DELETE FROM settings`).run();
  await saveSettings(db, makeDefaultSettings());
}

export async function getSettings(db: D1Database): Promise<TowerSettings> {
  const rows = await db.prepare(`SELECT key, value FROM settings`).all<{ key: string; value: string }>();
  const map: Record<string, string> = {};
  for (const r of rows.results || []) {
    map[r.key] = r.value;
  }

  let mcpToken = (map.mcp_token || "").trim();
  if (!mcpToken) {
    mcpToken = generateHighEntropyMcpToken();
    await db
      .prepare(`INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES ('mcp_token', ?, ?)`)
      .bind(mcpToken, Date.now())
      .run();
  }

  const lastSyncNum = map.last_full_sync_at ? Number(map.last_full_sync_at) : 0;
  return {
    sub_token: map.sub_token || generateRandomToken(),
    mcp_token: mcpToken,
    rename_template: map.rename_template || "{REGION} · {LINE_TAG} · {INDEX:02}",
    exclude_regex: map.exclude_regex ?? "/(剩余流量|套餐到期|官网|群组|维护|故障|重置)/i",
    max_multiplier: map.max_multiplier ? Number(map.max_multiplier) : 2.0,
    dedup_enabled: map.dedup_enabled ? map.dedup_enabled === "true" : true,
    ua_guard_enabled: map.ua_guard_enabled ? map.ua_guard_enabled === "true" : true,
    strict_client_ua: map.strict_client_ua ? map.strict_client_ua === "true" : false,
    cron_interval_min: map.cron_interval_min ? Number(map.cron_interval_min) : 30,
    last_full_sync_at: lastSyncNum > 0 ? lastSyncNum : null,
    revision: map.revision ? Number(map.revision) : 1,
  };
}

export async function saveSettings(db: D1Database, settings: Partial<TowerSettings>): Promise<TowerSettings> {
  const existingRows = await db.prepare(`SELECT COUNT(*) as cnt FROM settings`).first<{ cnt: number }>();
  const base = existingRows && existingRows.cnt > 0 ? await getSettings(db) : makeDefaultSettings();
  const merged: TowerSettings = { ...base, ...settings };
  const now = Date.now();
  for (const [k, v] of Object.entries(merged)) {
    await db
      .prepare(`INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)`)
      .bind(k, v === null ? "0" : String(v), now)
      .run();
  }
  return merged;
}

export async function listSubscriptions(db: D1Database): Promise<SubscriptionItem[]> {
  const res = await db
    .prepare(`SELECT * FROM subscriptions ORDER BY enabled DESC, created_at ASC`)
    .all<Record<string, unknown>>();
  return (res.results || []).map((r) => ({
    id: String(r.id),
    name: String(r.name),
    url: String(r.url),
    fetch_ua: String(r.fetch_ua || "auto"),
    fetch_proxy: String(r.fetch_proxy || ""),
    protocol_hint: String(r.protocol_hint || ""),
    enabled: Number(r.enabled) === 1,
    inline_content: String(r.inline_content || ""),
    used_gb: Number(r.used_gb || 0),
    total_gb: Number(r.total_gb || 0),
    expire_at: r.expire_at ? Number(r.expire_at) : null,
    is_unlimited: Number(r.is_unlimited) === 1,
    raw_node_count: Number(r.raw_node_count || 0),
    valid_node_count: Number(r.valid_node_count || 0),
    regions: JSON.parse(String(r.regions_json || "[]")),
    last_sync_at: r.last_sync_at ? Number(r.last_sync_at) : null,
    last_status: String(r.last_status || "待同步"),
    note: String(r.note || ""),
    created_at: Number(r.created_at || Date.now()),
  }));
}

export async function listNodes(db: D1Database): Promise<ProxyNode[]> {
  const res = await db.prepare(`SELECT * FROM nodes`).all<Record<string, unknown>>();
  return (res.results || []).map((r) => {
    let raw_config: RawNodeConfig = {};
    try {
      raw_config = JSON.parse(String(r.raw_config_json || "{}"));
    } catch {
      raw_config = {};
    }
    return {
      id: String(r.id),
      sub_id: String(r.sub_id),
      sub_name: String(r.sub_name),
      raw_name: String(r.raw_name),
      normalized_name: String(r.normalized_name),
      region: String(r.region),
      line_tag: String(r.line_tag),
      protocol: String(r.protocol),
      server: String(r.server),
      port: Number(r.port),
      cipher_or_param: String(r.cipher_or_param || ""),
      raw_config,
      multiplier: Number(r.multiplier),
      latency_ms: r.latency_ms !== null && r.latency_ms !== undefined ? Number(r.latency_ms) : null,
      fingerprint: String(r.fingerprint),
      merged_count: Number(r.merged_count || 0),
      status: String(r.status) as ProxyNode["status"],
      filter_reason: String(r.filter_reason || ""),
      updated_at: Number(r.updated_at),
    };
  });
}

export async function listPolicyGroups(db: D1Database, nodes?: ProxyNode[]): Promise<PolicyGroup[]> {
  const res = await db
    .prepare(`SELECT * FROM policy_groups ORDER BY sort_order ASC`)
    .all<Record<string, unknown>>();
  const activeNodes = (nodes || []).filter((n) => n.status === "active");
  return (res.results || []).map((r) => {
    const regexStr = String(r.filter_regex ?? "");
    const matched_count = matchNodesForGroup({ filter_regex: regexStr }, activeNodes).length;
    return {
      id: String(r.id),
      name: String(r.name),
      type: String(r.type) as PolicyGroup["type"],
      filter_regex: regexStr,
      interval_sec: Number(r.interval_sec || 300),
      tolerance_ms: Number(r.tolerance_ms || 20),
      fallback_groups: JSON.parse(String(r.fallback_groups_json || "[]")),
      sort_order: Number(r.sort_order || 0),
      matched_count,
    };
  });
}

export async function upsertPolicyGroupsFromBundle(
  db: D1Database,
  parsedGroups: Omit<PolicyGroup, "id" | "matched_count">[],
  replaceExisting = false
): Promise<void> {
  if (replaceExisting) {
    await db.prepare(`DELETE FROM policy_groups`).run();
  }
  const existing = await listPolicyGroups(db);
  const byName = new Map(existing.map((g) => [g.name, g]));

  for (const g of parsedGroups) {
    const prev = byName.get(g.name);
    if (prev) {
      await db
        .prepare(
          `UPDATE policy_groups
           SET type = ?, filter_regex = ?, interval_sec = ?, tolerance_ms = ?, fallback_groups_json = ?, sort_order = ?
           WHERE id = ?`
        )
        .bind(
          g.type,
          g.filter_regex,
          g.interval_sec,
          g.tolerance_ms,
          JSON.stringify(g.fallback_groups),
          g.sort_order,
          prev.id
        )
        .run();
    } else {
      const gid = `pg_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 5)}`;
      await db
        .prepare(
          `INSERT INTO policy_groups (id, name, type, filter_regex, interval_sec, tolerance_ms, fallback_groups_json, sort_order)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .bind(
          gid,
          g.name,
          g.type,
          g.filter_regex,
          g.interval_sec,
          g.tolerance_ms,
          JSON.stringify(g.fallback_groups),
          g.sort_order
        )
        .run();
    }
  }
}

export async function listRules(db: D1Database): Promise<RoutingRule[]> {
  const res = await db
    .prepare(`SELECT * FROM rules ORDER BY kind ASC, priority ASC`)
    .all<Record<string, unknown>>();
  return (res.results || []).map((r) => ({
    id: String(r.id),
    kind: String(r.kind) as RoutingRule["kind"],
    rule_type: String(r.rule_type) as RoutingRule["rule_type"],
    title: String(r.title),
    payload: String(r.payload),
    target_policy: String(r.target_policy),
    rule_count: Number(r.rule_count || 1),
    no_resolve: Number(r.no_resolve) === 1,
    sync_meta: String(r.sync_meta || "Local"),
    enabled: Number(r.enabled) === 1,
    priority: Number(r.priority || 10),
  }));
}

export async function listAccessLogs(db: D1Database, limit = 50): Promise<AccessLogItem[]> {
  const res = await db
    .prepare(`SELECT * FROM access_logs ORDER BY created_at DESC LIMIT ?`)
    .bind(limit)
    .all<Record<string, unknown>>();
  return (res.results || []).map((r) => ({
    id: String(r.id),
    client_tag: String(r.client_tag) as AccessLogItem["client_tag"],
    device_ua: String(r.device_ua),
    ip: String(r.ip),
    isp_geo: String(r.isp_geo),
    status_code: Number(r.status_code),
    status_label: String(r.status_label),
    target_format: String(r.target_format),
    latency_ms: Number(r.latency_ms || 0),
    created_at: Number(r.created_at),
  }));
}

export async function recordAccessLog(
  db: D1Database,
  entry: Omit<AccessLogItem, "id" | "created_at">
): Promise<void> {
  const id = `lg_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
  await db
    .prepare(
      `INSERT INTO access_logs (id, client_tag, device_ua, ip, isp_geo, status_code, status_label, target_format, latency_ms, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      id,
      entry.client_tag,
      entry.device_ua,
      entry.ip,
      entry.isp_geo,
      entry.status_code,
      entry.status_label,
      entry.target_format,
      entry.latency_ms,
      Date.now()
    )
    .run();
}

const UA_PROFILES: Record<string, string> = {
  clash: "Clash.Meta/v1.18.3 mihomo/1.18.3",
  stash: "Stash/2.7.2 Clash/1.18.0",
  surge6: "Surge Mac/6.12.0 SurgeCore/6012000",
  surge: "Surge Mac/3182",
  v2ray: "v2rayNG/1.8.23",
};

export async function fetchUpstreamContent(
  url: string,
  fetchUa: string,
  fetchProxy?: string
): Promise<{ text: string; userInfoHeader: string | null; statusLabel: string }> {
  const uaCandidates =
    fetchUa === "auto"
      ? [UA_PROFILES.clash, UA_PROFILES.v2ray, UA_PROFILES.surge]
      : [UA_PROFILES[fetchUa] || fetchUa];

  const cleanProxy = (fetchProxy || "").trim();
  let lastStatus = "连接失败";
  let fallbackText = "";
  let fallbackHeader: string | null = null;

  for (const ua of uaCandidates) {
    try {
      let status = 0;
      let text = "";
      let userInfoHeader: string | null = null;

      if (cleanProxy) {
        const proxied = await fetchViaProxy(url, ua, cleanProxy);
        status = proxied.status;
        text = proxied.bodyText;
        userInfoHeader = proxied.headers["subscription-userinfo"] || null;
      } else {
        const resp = await fetch(url, {
          headers: {
            "User-Agent": ua,
            Accept: "*/*",
          },
          redirect: "follow",
          signal: AbortSignal.timeout(12000),
        });
        status = resp.status;
        if (resp.ok) {
          text = await resp.text();
          userInfoHeader = resp.headers.get("subscription-userinfo");
        }
      }

      if (status < 200 || status >= 300) {
        lastStatus = `HTTP ${status}`;
        continue;
      }

      if (!fallbackText && text.trim()) {
        fallbackText = text;
        fallbackHeader = userInfoHeader;
      }

      const testParsed = parseFullConfigBundle(text);
      if (testParsed.nodes.length > 0) {
        return { text, userInfoHeader, statusLabel: cleanProxy ? "200 OK (代理)" : "200 OK" };
      }
    } catch (err) {
      if (cleanProxy && err instanceof Error) {
        lastStatus = err.message;
        break;
      }
      lastStatus = err instanceof Error && err.name === "TimeoutError" ? "请求超时" : "网络错误";
    }
  }

  if (fallbackText) {
    return { text: fallbackText, userInfoHeader: fallbackHeader, statusLabel: "0 节点" };
  }
  throw new Error(lastStatus);
}

export async function rebuildNodePool(
  db: D1Database,
  fetchRemote = false
): Promise<{ active: number; raw: number }> {
  const settings = await getSettings(db);
  const subs = await listSubscriptions(db);
  const existingNodes = await listNodes(db);
  const previousLatencies = new Map<string, number>();
  for (const n of existingNodes) {
    if (typeof n.latency_ms === "number" && n.latency_ms > 0) {
      previousLatencies.set(n.fingerprint, n.latency_ms);
    }
  }

  const batches: RawSourceBatch[] = [];
  const now = Date.now();

  for (const s of subs) {
    if (!s.enabled) {
      await db
        .prepare(`UPDATE subscriptions SET raw_node_count = 0, valid_node_count = 0, last_status = '已暂停' WHERE id = ?`)
        .bind(s.id)
        .run();
      continue;
    }

    let contentToParse = s.inline_content;
    let statusLabel = s.url.startsWith("local://") ? "本地导入" : s.last_status || "200 OK";

    if (fetchRemote && (s.url.startsWith("https://") || s.url.startsWith("http://"))) {
      try {
        const fetched = await fetchUpstreamContent(s.url, s.fetch_ua, s.fetch_proxy);
        contentToParse = fetched.text;
        statusLabel = fetched.statusLabel;
        const quota = parseSubscriptionUserInfo(fetched.userInfoHeader);
        const bundle = parseFullConfigBundle(contentToParse);
        await db
          .prepare(
            `UPDATE subscriptions
             SET inline_content = ?,
                 used_gb = COALESCE(?, used_gb),
                 total_gb = COALESCE(?, total_gb),
                 expire_at = COALESCE(?, expire_at),
                 is_unlimited = CASE WHEN ? IS NOT NULL THEN 0 ELSE is_unlimited END,
                 protocol_hint = CASE WHEN protocol_hint = '' THEN ? ELSE protocol_hint END,
                 last_sync_at = ?,
                 last_status = ?
             WHERE id = ?`
          )
          .bind(
            contentToParse,
            quota?.used_gb ?? null,
            quota?.total_gb ?? null,
            quota?.expire_at ?? null,
            quota?.total_gb ?? null,
            bundle.protocol_summary,
            now,
            statusLabel,
            s.id
          )
          .run();
      } catch (err) {
        statusLabel = err instanceof Error ? err.message : "拉取失败";
        await db
          .prepare(`UPDATE subscriptions SET last_sync_at = ?, last_status = ? WHERE id = ?`)
          .bind(now, statusLabel, s.id)
          .run();
      }
    }

    const bundle = parseFullConfigBundle(contentToParse);
    if (!s.protocol_hint && bundle.nodes.length > 0) {
      await db
        .prepare(`UPDATE subscriptions SET protocol_hint = ? WHERE id = ?`)
        .bind(bundle.protocol_summary, s.id)
        .run();
    }

    batches.push({
      sub_id: s.id,
      sub_name: s.name,
      nodes: bundle.nodes as RawParsedNode[],
    });
  }

  const { nodes, subValidCounts } = runIntegrationPipeline(batches, settings, previousLatencies);

  await db.prepare(`DELETE FROM nodes`).run();
  for (const n of nodes) {
    await db
      .prepare(
        `INSERT INTO nodes (id, sub_id, sub_name, raw_name, normalized_name, region, line_tag, protocol, server, port, cipher_or_param, raw_config_json, multiplier, latency_ms, fingerprint, merged_count, status, filter_reason, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        n.id,
        n.sub_id,
        n.sub_name,
        n.raw_name,
        n.normalized_name,
        n.region,
        n.line_tag,
        n.protocol,
        n.server,
        n.port,
        n.cipher_or_param,
        JSON.stringify(n.raw_config || {}),
        n.multiplier,
        n.latency_ms,
        n.fingerprint,
        n.merged_count,
        n.status,
        n.filter_reason,
        n.updated_at
      )
      .run();
  }

  for (const [subId, counts] of Object.entries(subValidCounts)) {
    await db
      .prepare(`UPDATE subscriptions SET raw_node_count = ?, valid_node_count = ?, regions_json = ? WHERE id = ?`)
      .bind(counts.raw, counts.valid, JSON.stringify(counts.regions), subId)
      .run();
  }

  if (fetchRemote && subs.some((s) => s.enabled)) {
    await saveSettings(db, { last_full_sync_at: now });
  }

  return {
    active: nodes.filter((n) => n.status === "active").length,
    raw: nodes.length,
  };
}

export async function buildDashboardSnapshot(
  db: D1Database,
  origin: string,
  auth: AdminAuthInfo = {
    mode: "local_dev",
    configured: false,
    email: null,
    team_domain: null,
    logout_url: null,
  }
): Promise<DashboardSnapshot> {
  const settings = await getSettings(db);
  const subscriptions = await listSubscriptions(db);
  const nodes = await listNodes(db);
  const policy_groups = await listPolicyGroups(db, nodes);
  const rules = await listRules(db);
  const access_logs = await listAccessLogs(db, 50);
  const pipeline = computePipelineStats(nodes);

  const surge = compileSurgeProfile({
    origin,
    settings,
    nodes,
    groups: policy_groups,
    rules,
    target: "surge",
    enableVless: false,
  });
  const surge6 = compileSurgeProfile({
    origin,
    settings,
    nodes,
    groups: policy_groups,
    rules,
    target: "surge6",
    enableVless: true,
  });
  const stash = compileStashYaml({ origin, settings, nodes, groups: policy_groups, rules });
  const stashProviderCount = rules.filter((r) => r.enabled && r.rule_type === "RULE-SET").length;

  return {
    auth,
    settings,
    subscriptions,
    nodes,
    policy_groups,
    rules,
    access_logs,
    pipeline,
    compiled_preview: {
      surge,
      surge6,
      stash,
      surge_line_count: surge.split("\n").length,
      surge6_line_count: surge6.split("\n").length,
      stash_provider_count: stashProviderCount,
    },
  };
}
