import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { matchNodesForGroup } from "../shared/groupMatcher";
import type {
  PolicyGroup,
  ProxyNode,
  RawNodeConfig,
  RoutingRule,
  SubscriptionItem,
} from "../shared/types";
import {
  fetchUpstreamContent,
  getSettings,
  listNodes,
  listPolicyGroups,
  listRules,
  listSubscriptions,
  rebuildNodePool,
  saveSettings,
  upsertPolicyGroupsFromBundle,
} from "./db";
import {
  clashProxyToSurgeRhs,
  compileSingleNodePreview,
  compileStashYaml,
  compileSurgeProfile,
} from "./engine/compiler";
import { parseFullConfigBundle, parseSubscriptionUserInfo } from "./engine/parser";
import { computePipelineStats } from "./engine/pipeline";
import { simulateRoute } from "./engine/simulator";
import { probeNodes } from "./probe";

const SUPPORTED_PROTOCOL_VERSIONS = new Set(["2025-06-18", "2025-03-26", "2024-11-05"]);
const DEFAULT_PROTOCOL_VERSION = "2025-03-26";

const VALID_POLICY_GROUP_TYPES = new Set<PolicyGroup["type"]>(["url-test", "fallback", "select", "smart"]);
const VALID_RULE_TYPES = new Set<RoutingRule["rule_type"]>([
  "DOMAIN-SUFFIX",
  "DOMAIN-KEYWORD",
  "DOMAIN",
  "IP-CIDR",
  "IP-CIDR6",
  "GEOIP",
  "PROCESS-NAME",
  "USER-AGENT",
  "URL-REGEX",
  "RULE-SET",
  "FINAL",
]);

interface JsonRpcRequest {
  jsonrpc: string;
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: "object";
    properties: Record<string, unknown>;
    required?: string[];
  };
}

interface McpToolContext {
  db: D1Database;
  origin: string;
}

const MCP_TOOLS: McpToolDefinition[] = [
  {
    name: "get_platform_state",
    description:
      "获取 Tower 平台当前配置状态，包括全局清洗设置、修订版本 revision、节点流水线统计、所有策略组（含匹配节点数）、分流规则列表以及订阅源摘要（敏感 URL/Proxy/Token 默认脱敏）。",
    inputSchema: {
      type: "object",
      properties: {
        include_sub_token: {
          type: "boolean",
          description: "是否返回完整订阅 Token（默认 false，仅返回脱敏摘要）。",
        },
        include_secrets: {
          type: "boolean",
          description: "是否返回未脱敏的订阅源 URL 与前置代理配置（默认 false）。",
        },
      },
    },
  },
  {
    name: "list_nodes",
    description: "查询当前节点池中的节点，支持按状态、地区、订阅源、协议或关键词筛选，便于编写策略组正则或定位节点 ID。",
    inputSchema: {
      type: "object",
      properties: {
        status: {
          type: "string",
          enum: ["active", "filtered_regex", "filtered_multiplier", "filtered_dedup", "all"],
          description: "节点状态筛选，默认 active。",
        },
        region: {
          type: "string",
          description: "按地区代码过滤（例如 HK、JP、SG、US、TW）。",
        },
        sub_id: {
          type: "string",
          description: "按订阅源 ID 过滤（如 sub_manual_nodes）。",
        },
        protocol: {
          type: "string",
          description: "按协议过滤（例如 VLESS、Trojan、Shadowsocks、Hysteria 2）。",
        },
        query: {
          type: "string",
          description: "按节点名称、协议或服务器地址模糊搜索。",
        },
        limit: {
          type: "number",
          description: "最多返回条数（默认 100，最大 500）。",
        },
      },
    },
  },
  {
    name: "list_subscriptions",
    description:
      "列出所有订阅源及自建节点源（包含流量配额、节点统计、同步状态与地区摘要；订阅 URL 与前置代理凭证默认脱敏）。",
    inputSchema: {
      type: "object",
      properties: {
        enabled_only: {
          type: "boolean",
          description: "是否仅返回已启用的订阅源（默认 false）。",
        },
        include_secrets: {
          type: "boolean",
          description: "是否返回未脱敏的订阅 URL 与前置代理密码（默认 false）。",
        },
        include_content: {
          type: "boolean",
          description: "是否附加原始缓存配置内容 inline_content（仅当同时传 include_secrets: true 时生效）。",
        },
      },
    },
  },
  {
    name: "upsert_subscription",
    description:
      "新增或更新一个订阅源（远程订阅 URL 或本地配置内容）。传 id 或 match_name 时更新已有订阅，否则新建；支持自动拉取并重建节点池。",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "要更新的订阅源 ID。" },
        match_name: { type: "string", description: "按原订阅源名称定位已有订阅进行更新或改名。" },
        name: { type: "string", description: "订阅源名称（新建时必填）。" },
        url: { type: "string", description: "远程订阅链接 http(s)://...，本地配置可留空或传 local://..." },
        fetch_ua: {
          type: "string",
          description: "远程拉取 User-Agent（auto / clash / stash / surge6 / surge / v2ray 或自定义 UA）。",
        },
        fetch_proxy: {
          type: "string",
          description: "可选前置 SOCKS5 / HTTP 代理（如 socks5://user:pass@host:port）。",
        },
        enabled: { type: "boolean", description: "是否启用该订阅源。" },
        note: { type: "string", description: "备注信息。" },
        inline_content: {
          type: "string",
          description: "直接写入的原始配置内容（支持 Clash YAML / Surge .conf / Base64 / 分享链接）。",
        },
        fetch_now: {
          type: "boolean",
          description: "对于远程 URL：新建时默认 true，更新时传 true 立即从上游重新拉取。",
        },
        import_rules_and_groups: {
          type: "boolean",
          description: "仅新建时生效：若订阅含策略组与规则，是否同步导入（默认 false）。",
        },
      },
    },
  },
  {
    name: "delete_subscription",
    description: "按 id 或 name 删除一个订阅源，并自动重算重建节点池。",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "订阅源 ID。" },
        name: { type: "string", description: "订阅源名称（与 id 二选一）。" },
      },
    },
  },
  {
    name: "sync_subscriptions",
    description: "立即同步指定订阅源或全部已启用订阅源（拉取最新上游节点并重建节点池）。",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "可选：仅同步指定订阅源 ID；省略则同步全部已启用订阅。" },
        name: { type: "string", description: "可选：按订阅源名称指定同步目标。" },
        fetch_remote: {
          type: "boolean",
          description: "是否请求远程 URL（默认 true；传 false 时仅使用本地缓存内容重跑清洗流水线）。",
        },
      },
    },
  },
  {
    name: "add_manual_node",
    description:
      "添加或覆盖自建/手动单条节点（支持 vless:// / trojan:// / ss:// / vmess:// / hy2:// / tuic:// / anytls:// 分享链接、Surge [Proxy] 行或 Clash YAML 节点片段）。默认写入受托管的 local://manual-nodes 自建节点源并立即重建节点池。",
    inputSchema: {
      type: "object",
      properties: {
        node_spec: {
          type: "string",
          description: "节点分享链接、Surge [Proxy] 配置行，或 Clash YAML proxies 片段。",
        },
        name: {
          type: "string",
          description: "可选：覆盖节点名称（仅当 node_spec 解析出单个节点时生效）。",
        },
        sub_id: {
          type: "string",
          description: "可选：目标本地订阅源 ID，默认 sub_manual_nodes。",
        },
        sub_name: {
          type: "string",
          description: "可选：首次自动创建自建节点源时使用的名称（默认「自建 / 手动节点」）。",
        },
        replace_existing: {
          type: "boolean",
          description: "若目标自建源中已存在同指纹或同原名节点，是否自动替换覆盖（默认 true）。",
        },
      },
      required: ["node_spec"],
    },
  },
  {
    name: "delete_manual_node",
    description:
      "从本地/自建订阅源（local://）中删除匹配的节点并重建节点池。远程机场订阅的节点不支持单条物理删除，请改用 update_settings(exclude_regex) 或停用订阅。",
    inputSchema: {
      type: "object",
      properties: {
        node_id: { type: "string", description: "要删除的节点 ID。" },
        name: { type: "string", description: "按标准名或原名匹配节点。" },
        server: { type: "string", description: "按服务器域名或 IP 匹配。" },
        port: { type: "number", description: "配合 server 使用的端口过滤。" },
        sub_id: { type: "string", description: "可选：限定在指定本地订阅源 ID 内删除。" },
      },
    },
  },
  {
    name: "get_node_detail",
    description:
      "查看单个节点的完整详情、命中的策略组以及 Surge 5 / Surge 6 / Stash 实时编译预览（敏感参数默认脱敏，传 include_secrets: true 可查看完整密钥/UUID）。",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "节点 ID。" },
        name: { type: "string", description: "节点标准名或原名（与 id 二选一）。" },
        include_secrets: {
          type: "boolean",
          description: "是否返回未脱敏的密码、UUID、PSK 与 REALITY 密钥（默认 false）。",
        },
      },
    },
  },
  {
    name: "probe_nodes",
    description:
      "对节点执行真实 TCP 握手延迟测速并更新 D1 中的 latency_ms。支持按节点 ID 列表、地区、订阅源或关键词筛选目标节点。",
    inputSchema: {
      type: "object",
      properties: {
        node_ids: {
          type: "array",
          items: { type: "string" },
          description: "可选：指定要测速的节点 ID 列表。",
        },
        region: { type: "string", description: "可选：仅测速指定地区代码（如 HK、JP、US）。" },
        sub_id: { type: "string", description: "可选：仅测速指定订阅源下的节点。" },
        query: { type: "string", description: "可选：按名称、协议或地址过滤目标节点。" },
        timeout_ms: { type: "number", description: "单节点 TCP 握手超时毫秒（默认 2500，范围 500~8000）。" },
        limit: { type: "number", description: "单次最多探测节点数（默认 50，最大 150）。" },
      },
    },
  },
  {
    name: "upsert_policy_group",
    description:
      "创建或更新策略组（url-test / fallback / select / smart）。若传入 id 或 match_name 定位已有策略组并修改 name，会自动级联更新关联规则和父策略组的引用。",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "要更新的策略组 ID；省略时按 match_name 或 name 匹配，未匹配则新建。",
        },
        match_name: {
          type: "string",
          description: "按原策略组名称定位（用于按名称改名场景）。",
        },
        name: {
          type: "string",
          description: "策略组名称（必填）。",
        },
        type: {
          type: "string",
          enum: ["url-test", "fallback", "select", "smart"],
          description: "策略组类型，新建时默认 select。",
        },
        filter_regex: {
          type: "string",
          description: "节点名称匹配正则（支持 /pattern/flags 或普通正则，留空表示不按正则匹配节点）。",
        },
        fallback_groups: {
          type: "array",
          items: { type: "string" },
          description: "嵌套子策略组或内建策略列表（如 ['HK · Auto', 'DIRECT']）。",
        },
        interval_sec: {
          type: "number",
          description: "测速间隔（秒），默认 300。",
        },
        tolerance_ms: {
          type: "number",
          description: "测速容差（毫秒），默认 20。",
        },
        sort_order: {
          type: "number",
          description: "排序权重（越小越靠前）。",
        },
      },
      required: ["name"],
    },
  },
  {
    name: "delete_policy_group",
    description: "删除指定策略组（按 id 或 name），并自动将引用该组的规则回退到剩余策略组或 DIRECT。",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "策略组 ID。" },
        name: { type: "string", description: "策略组名称（与 id 二选一）。" },
      },
    },
  },
  {
    name: "upsert_rule",
    description: "新增或更新一条分流规则（支持 DOMAIN-SUFFIX、DOMAIN、DOMAIN-KEYWORD、IP-CIDR、GEOIP、RULE-SET、FINAL 等）。",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "已有规则 ID；传入则更新，省略则新建。",
        },
        rule_type: {
          type: "string",
          enum: [
            "DOMAIN-SUFFIX",
            "DOMAIN-KEYWORD",
            "DOMAIN",
            "IP-CIDR",
            "IP-CIDR6",
            "GEOIP",
            "PROCESS-NAME",
            "USER-AGENT",
            "URL-REGEX",
            "RULE-SET",
            "FINAL",
          ],
          description: "规则类型。",
        },
        payload: {
          type: "string",
          description: "匹配内容（如 openai.com、CN、provider/ai-suite.list；FINAL 规则可留空，默认 dns-failed）。",
        },
        target_policy: {
          type: "string",
          description: "目标策略组或内建动作（如 Proxy、DIRECT、REJECT-DROP）。",
        },
        title: {
          type: "string",
          description: "规则可读标题（可选）。",
        },
        kind: {
          type: "string",
          enum: ["override", "ruleset"],
          description: "规则类别（默认按 rule_type 自动推断）。",
        },
        no_resolve: {
          type: "boolean",
          description: "IP/RULE-SET 是否附加 no-resolve。",
        },
        enabled: {
          type: "boolean",
          description: "是否启用该规则（默认 true）。",
        },
        priority: {
          type: "number",
          description: "规则优先级（数字越小越先匹配，FINAL 默认 9999）。",
        },
      },
      required: ["rule_type", "target_policy"],
    },
  },
  {
    name: "delete_rule",
    description: "按 ID 删除一条分流规则。",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "要删除的规则 ID。" },
      },
      required: ["id"],
    },
  },
  {
    name: "scaffold_policy_and_rules",
    description: "根据当前有效节点包含的地区自动生成标准地区策略组（如 HK/JP/SG/US · Auto 与 Proxy）及基础内置分流规则（若当前无规则）。",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "update_settings",
    description:
      "更新平台节点清洗与安全策略设置（重命名模板、排除正则、最大倍率、入口去重、UA 守卫等）。修改清洗参数时会自动重建节点池。",
    inputSchema: {
      type: "object",
      properties: {
        rename_template: {
          type: "string",
          description: "节点重命名模板，如 '{REGION} · {LINE_TAG} · {INDEX:02}'。",
        },
        exclude_regex: {
          type: "string",
          description: "排除伪节点的正则表达式。",
        },
        max_multiplier: {
          type: "number",
          description: "允许的最大节点倍率（例如 2.0）。",
        },
        dedup_enabled: {
          type: "boolean",
          description: "是否开启按 protocol:server:port 入口指纹去重。",
        },
        ua_guard_enabled: {
          type: "boolean",
          description: "是否开启爬虫/预览机器人 UA 拦截。",
        },
        strict_client_ua: {
          type: "boolean",
          description: "是否开启严格代理客户端 UA 白名单。",
        },
        bump_revision: {
          type: "boolean",
          description: "是否同时递增修订版本 revision。",
        },
      },
    },
  },
  {
    name: "simulate_route",
    description: "输入域名、URL、IP 或进程名，模拟当前规则与策略组拓扑下的命中链路及最终解析节点。",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "待测试的目标（如 'openai.com'、'https://claude.ai/chat'、'91.108.4.1'）。",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "compile_profile",
    description:
      "实时编译最新的 Surge 5 (.conf)、Surge 6 (.conf，原生支持 VLESS) 或 Stash / Clash.Meta (.yaml) 配置产物并返回完整配置内容与编译摘要。",
    inputSchema: {
      type: "object",
      properties: {
        format: {
          type: "string",
          enum: ["surge", "surge6", "stash"],
          description: "目标产物格式：surge（Surge 5）、surge6（Surge 6，默认启用 VLESS）或 stash。",
        },
        enable_vless: {
          type: "boolean",
          description: "仅 Surge 生效：是否输出 VLESS 节点（surge 默认 false，surge6 默认 true）。",
        },
        bump_revision: {
          type: "boolean",
          description: "是否在编译前先递增 revision 版本号（默认 false）。",
        },
      },
      required: ["format"],
    },
  },
  {
    name: "publish_revision",
    description: "递增平台 revision 版本号以正式发布当前策略配置；可选先拉取上游订阅并重建节点池。",
    inputSchema: {
      type: "object",
      properties: {
        sync_subscriptions: {
          type: "boolean",
          description: "是否在发布前先从上游拉取所有已启用的订阅源并重建节点池（默认 false）。",
        },
      },
    },
  },
];

function maskToken(token: string): string {
  if (token.length <= 8) return "***";
  return `${token.slice(0, 6)}...${token.slice(-4)} (len=${token.length})`;
}

function maskUrl(rawUrl: string): string {
  const clean = (rawUrl || "").trim();
  if (!clean || clean.startsWith("local://")) return clean;
  try {
    const u = new URL(clean);
    const firstSeg = u.pathname.split("/").filter(Boolean)[0];
    return `${u.origin}${firstSeg ? `/${firstSeg}` : ""}/... (redacted)`;
  } catch {
    return maskToken(clean);
  }
}

function maskProxyUrl(rawProxy: string): string {
  const clean = (rawProxy || "").trim();
  if (!clean) return "";
  const urlMatch = clean.match(/^([a-z0-9+.-]+:\/\/)[^@]+@(.+)$/i);
  if (urlMatch) {
    return `${urlMatch[1]}***@${urlMatch[2]}`;
  }
  if (!clean.includes("://")) {
    const parts = clean.split(":");
    if (parts.length >= 4) {
      return `${parts[0]}:${parts[1]}:***`;
    }
  }
  return clean;
}

const SENSITIVE_SURGE_KV_REGEX =
  /(^|[,\s])((?:password|username|psk|uuid|reality-public-key|reality-short-id|encryption|obfs-password)\s*=\s*)("[^"]*"|[^,]*)/gi;

function redactSurgeRhs(rhs: string | null): string | null {
  if (!rhs) return null;
  return rhs.replace(SENSITIVE_SURGE_KV_REGEX, "$1$2***");
}

function redactClashProxy(obj: Record<string, unknown> | null): Record<string, unknown> | null {
  if (!obj) return null;
  const out: Record<string, unknown> = { ...obj };
  for (const key of ["password", "uuid", "psk", "obfs-password", "private-key", "encryption"]) {
    if (key in out && out[key] !== undefined && out[key] !== "") {
      out[key] = "***";
    }
  }
  const realityOpts = out["reality-opts"];
  if (realityOpts && typeof realityOpts === "object" && !Array.isArray(realityOpts)) {
    const clonedReality: Record<string, unknown> = { ...(realityOpts as Record<string, unknown>) };
    if ("public-key" in clonedReality && clonedReality["public-key"]) {
      clonedReality["public-key"] = "***";
    }
    if ("short-id" in clonedReality && clonedReality["short-id"]) {
      clonedReality["short-id"] = "***";
    }
    out["reality-opts"] = clonedReality;
  }
  return out;
}

function redactRawConfig(raw: RawNodeConfig): RawNodeConfig {
  const out: RawNodeConfig = {};
  if (raw.surge_rhs) {
    out.surge_rhs = redactSurgeRhs(raw.surge_rhs) ?? undefined;
  }
  if (raw.clash_proxy) {
    out.clash_proxy = redactClashProxy(raw.clash_proxy) ?? undefined;
  }
  return out;
}

function formatSubscriptionSummary(
  s: SubscriptionItem,
  includeSecrets: boolean,
  includeContent = false
) {
  return {
    id: s.id,
    name: s.name,
    url: includeSecrets ? s.url : maskUrl(s.url),
    is_local: s.url.startsWith("local://"),
    fetch_ua: s.fetch_ua,
    fetch_proxy: includeSecrets ? s.fetch_proxy : maskProxyUrl(s.fetch_proxy),
    protocol_hint: s.protocol_hint,
    enabled: s.enabled,
    used_gb: s.used_gb,
    total_gb: s.total_gb,
    expire_at: s.expire_at,
    is_unlimited: s.is_unlimited,
    raw_node_count: s.raw_node_count,
    valid_node_count: s.valid_node_count,
    regions: s.regions,
    last_sync_at: s.last_sync_at,
    last_status: s.last_status,
    note: s.note,
    content_bytes: s.inline_content.length,
    ...(includeContent && includeSecrets ? { inline_content: s.inline_content } : {}),
  };
}

const MANUAL_SUB_ID = "sub_manual_nodes";
const MANUAL_SUB_URL = "local://manual-nodes";
const MANUAL_SUB_DEFAULT_NAME = "自建 / 手动节点";

function isYamlContent(text: string): boolean {
  const trimmed = text.trim();
  return trimmed.includes("proxies:") || trimmed.startsWith("- name:") || trimmed.startsWith("- {");
}

function encodeUtf8Base64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let bin = "";
  for (const b of bytes) {
    bin += String.fromCharCode(b);
  }
  return btoa(bin);
}

function decodeBase64Utf8(input: string): string | null {
  const cleaned = input.trim().replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  if (!cleaned) return null;
  try {
    const padded = cleaned + "=".repeat((4 - (cleaned.length % 4)) % 4);
    const bin = atob(padded);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  } catch {
    return null;
  }
}

function applyNameOverrideToLine(line: string, nameOverride: string): string {
  const cleanName = nameOverride.trim();
  if (!cleanName) return line;
  if (/^vmess:\/\//i.test(line)) {
    const payload = line.slice(8).split("#")[0];
    const decoded = decodeBase64Utf8(payload);
    if (decoded && decoded.trim().startsWith("{")) {
      try {
        const obj = JSON.parse(decoded) as Record<string, unknown>;
        obj.ps = cleanName;
        return `vmess://${encodeUtf8Base64(JSON.stringify(obj))}`;
      } catch {
        // fallback below
      }
    }
  }
  if (/^[a-z0-9+.-]+:\/\//i.test(line)) {
    const base = line.split("#")[0];
    return `${base}#${encodeURIComponent(cleanName)}`;
  }
  const eqIdx = line.indexOf("=");
  if (eqIdx !== -1) {
    return `${cleanName} = ${line.slice(eqIdx + 1).trim()}`;
  }
  return line;
}

interface NormalizedManualLine {
  line: string;
  raw_name: string;
  fingerprint: string;
}

function normalizeManualNodeInput(
  nodeSpec: string,
  nameOverride?: string
): { items: NormalizedManualLine[]; error?: undefined } | { items?: undefined; error: string } {
  const trimmed = nodeSpec.trim();
  if (!trimmed) {
    return { error: "参数错误：node_spec 不能为空。" };
  }

  const bundle = parseFullConfigBundle(trimmed);
  if (bundle.nodes.length === 0) {
    return {
      error:
        "未能从 node_spec 中解析出任何有效代理节点（支持 vless:// / trojan:// / ss:// / vmess:// / hy2:// / tuic:// / anytls:// 分享链接、Surge [Proxy] 行或 Clash YAML proxies 片段）。",
    };
  }

  const cleanOverride = nameOverride?.trim() || "";

  if (isYamlContent(trimmed)) {
    const items: NormalizedManualLine[] = [];
    const now = Date.now();
    for (let i = 0; i < bundle.nodes.length; i++) {
      const raw = bundle.nodes[i];
      const finalName = bundle.nodes.length === 1 && cleanOverride ? cleanOverride : raw.raw_name;
      const tempNode: ProxyNode = {
        id: `tmp_${i}`,
        sub_id: MANUAL_SUB_ID,
        sub_name: MANUAL_SUB_DEFAULT_NAME,
        raw_name: finalName,
        normalized_name: finalName,
        region: raw.region,
        line_tag: raw.line_tag,
        protocol: raw.protocol,
        server: raw.server,
        port: raw.port,
        cipher_or_param: raw.cipher_or_param,
        raw_config: raw.raw_config,
        multiplier: raw.multiplier,
        latency_ms: null,
        fingerprint: `${raw.protocol.toLowerCase()}:${raw.server.toLowerCase()}:${raw.port}`,
        merged_count: 0,
        status: "active",
        filter_reason: "",
        updated_at: now,
      };
      const rhs = clashProxyToSurgeRhs(tempNode, true);
      if (!rhs) {
        return {
          error: `节点「${finalName}」（协议 ${raw.protocol}）暂不支持转为单行 Surge 语法，请改用 upsert_subscription 传入完整 YAML。`,
        };
      }
      items.push({
        line: `${finalName} = ${rhs}`,
        raw_name: finalName,
        fingerprint: tempNode.fingerprint,
      });
    }
    return { items };
  }

  const collectLineNodes = (textSource: string): NormalizedManualLine[] => {
    const collected: NormalizedManualLine[] = [];
    for (const rawLine of textSource.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (
        !line ||
        line.startsWith("#") ||
        line.startsWith("//") ||
        line.startsWith(";") ||
        (line.startsWith("[") && line.endsWith("]"))
      ) {
        continue;
      }
      const single = parseFullConfigBundle(line);
      if (single.nodes.length === 1) {
        const n = single.nodes[0];
        collected.push({
          line,
          raw_name: n.raw_name,
          fingerprint: `${n.protocol.toLowerCase()}:${n.server.toLowerCase()}:${n.port}`,
        });
      }
    }
    return collected;
  };

  let items = collectLineNodes(trimmed);
  if (items.length === 0) {
    const decoded = decodeBase64Utf8(trimmed);
    if (decoded) {
      items = collectLineNodes(decoded);
    }
  }

  if (items.length === 0) {
    return { error: "未能提取出有效单行节点配置，请检查格式。" };
  }

  if (items.length === 1 && cleanOverride) {
    items[0] = {
      ...items[0],
      line: applyNameOverrideToLine(items[0].line, cleanOverride),
      raw_name: cleanOverride,
    };
  }

  return { items };
}

interface RemovedLocalNode {
  raw_name: string;
  fingerprint: string;
  server: string;
  port: number;
}

function removeMatchingNodesFromLocalContent(
  inlineContent: string,
  matcher: (node: RemovedLocalNode) => boolean
): { nextContent: string; removed: RemovedLocalNode[] } {
  const removed: RemovedLocalNode[] = [];
  if (!inlineContent.trim()) {
    return { nextContent: "", removed };
  }

  if (isYamlContent(inlineContent)) {
    try {
      const doc = parseYaml(inlineContent) as Record<string, unknown> | Array<Record<string, unknown>>;
      const filterItem = (item: Record<string, unknown>): boolean => {
        if (!item || typeof item !== "object") return true;
        const single = parseFullConfigBundle(stringifyYaml([item]));
        if (single.nodes.length !== 1) return true;
        const n = single.nodes[0];
        const candidate: RemovedLocalNode = {
          raw_name: n.raw_name,
          fingerprint: `${n.protocol.toLowerCase()}:${n.server.toLowerCase()}:${n.port}`,
          server: n.server,
          port: n.port,
        };
        if (matcher(candidate)) {
          removed.push(candidate);
          return false;
        }
        return true;
      };

      if (Array.isArray(doc)) {
        const nextArr = doc.filter((item) => filterItem(item));
        return { nextContent: nextArr.length > 0 ? stringifyYaml(nextArr) : "", removed };
      }
      if (doc && typeof doc === "object" && Array.isArray(doc.proxies)) {
        const nextProxies = (doc.proxies as Array<Record<string, unknown>>).filter((item) => filterItem(item));
        const nextDoc = { ...doc, proxies: nextProxies };
        return { nextContent: stringifyYaml(nextDoc), removed };
      }
    } catch {
      // fall through to line-based handler
    }
  }

  const keptLines: string[] = [];
  for (const rawLine of inlineContent.split(/\r?\n/)) {
    const trimmed = rawLine.trim();
    if (
      !trimmed ||
      trimmed.startsWith("#") ||
      trimmed.startsWith("//") ||
      trimmed.startsWith(";") ||
      (trimmed.startsWith("[") && trimmed.endsWith("]"))
    ) {
      keptLines.push(rawLine);
      continue;
    }
    const single = parseFullConfigBundle(trimmed);
    if (single.nodes.length === 1) {
      const n = single.nodes[0];
      const candidate: RemovedLocalNode = {
        raw_name: n.raw_name,
        fingerprint: `${n.protocol.toLowerCase()}:${n.server.toLowerCase()}:${n.port}`,
        server: n.server,
        port: n.port,
      };
      if (matcher(candidate)) {
        removed.push(candidate);
        continue;
      }
    }
    keptLines.push(rawLine);
  }

  const nextContent = keptLines.join("\n").replace(/\n{3,}/g, "\n\n").trim();
  return { nextContent, removed };
}

interface McpToolResult {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
}

function toolOk(data: unknown): McpToolResult {
  return {
    content: [
      {
        type: "text",
        text: typeof data === "string" ? data : JSON.stringify(data, null, 2),
      },
    ],
  };
}

function toolError(message: string): McpToolResult {
  return {
    isError: true,
    content: [{ type: "text", text: message }],
  };
}

async function executeTool(
  name: string,
  args: Record<string, unknown>,
  ctx: McpToolContext
): Promise<McpToolResult> {
  const { db, origin } = ctx;

  switch (name) {
    case "get_platform_state": {
      const includeToken = args.include_sub_token === true;
      const includeSecrets = args.include_secrets === true;
      const [settings, subscriptions, nodes, rules] = await Promise.all([
        getSettings(db),
        listSubscriptions(db),
        listNodes(db),
        listRules(db),
      ]);
      const policyGroups = await listPolicyGroups(db, nodes);
      const pipeline = computePipelineStats(nodes);

      return toolOk({
        settings: {
          ...settings,
          sub_token: includeToken ? settings.sub_token : maskToken(settings.sub_token),
          mcp_token: maskToken(settings.mcp_token),
        },
        pipeline,
        policy_groups: policyGroups,
        rules,
        subscriptions: subscriptions.map((s) => formatSubscriptionSummary(s, includeSecrets)),
      });
    }

    case "list_nodes": {
      const statusFilter = typeof args.status === "string" ? args.status : "active";
      const regionFilter = typeof args.region === "string" ? args.region.trim().toUpperCase() : "";
      const subIdFilter = typeof args.sub_id === "string" ? args.sub_id.trim() : "";
      const protoFilter = typeof args.protocol === "string" ? args.protocol.trim().toLowerCase() : "";
      const query = typeof args.query === "string" ? args.query.trim().toLowerCase() : "";
      const rawLimit = typeof args.limit === "number" ? Math.floor(args.limit) : 100;
      const limit = Math.max(1, Math.min(500, rawLimit));

      let nodes = await listNodes(db);
      if (statusFilter !== "all") {
        nodes = nodes.filter((n) => n.status === statusFilter);
      }
      if (regionFilter) {
        nodes = nodes.filter((n) => n.region.toUpperCase() === regionFilter);
      }
      if (subIdFilter) {
        nodes = nodes.filter((n) => n.sub_id === subIdFilter);
      }
      if (protoFilter) {
        nodes = nodes.filter((n) => n.protocol.toLowerCase().includes(protoFilter));
      }
      if (query) {
        nodes = nodes.filter(
          (n) =>
            n.normalized_name.toLowerCase().includes(query) ||
            n.raw_name.toLowerCase().includes(query) ||
            n.protocol.toLowerCase().includes(query) ||
            n.server.toLowerCase().includes(query)
        );
      }

      return toolOk({
        total_matched: nodes.length,
        returned: Math.min(nodes.length, limit),
        nodes: nodes.slice(0, limit).map((n) => ({
          id: n.id,
          sub_id: n.sub_id,
          normalized_name: n.normalized_name,
          raw_name: n.raw_name,
          sub_name: n.sub_name,
          region: n.region,
          line_tag: n.line_tag,
          protocol: n.protocol,
          server: n.server,
          port: n.port,
          fingerprint: n.fingerprint,
          multiplier: n.multiplier,
          latency_ms: n.latency_ms,
          status: n.status,
          filter_reason: n.filter_reason,
        })),
      });
    }

    case "list_subscriptions": {
      const enabledOnly = args.enabled_only === true;
      const includeSecrets = args.include_secrets === true;
      const includeContent = args.include_content === true;
      let subs = await listSubscriptions(db);
      if (enabledOnly) {
        subs = subs.filter((s) => s.enabled);
      }
      return toolOk({
        total: subs.length,
        subscriptions: subs.map((s) => formatSubscriptionSummary(s, includeSecrets, includeContent)),
      });
    }

    case "upsert_subscription": {
      const allSubs = await listSubscriptions(db);
      const idArg = typeof args.id === "string" ? args.id.trim() : "";
      const matchNameArg = typeof args.match_name === "string" ? args.match_name.trim() : "";
      const existing = idArg
        ? allSubs.find((s) => s.id === idArg)
        : matchNameArg
          ? allSubs.find((s) => s.name === matchNameArg)
          : undefined;

      if (idArg && !existing) {
        return toolError(`未找到 ID 为「${idArg}」的订阅源。`);
      }
      if (matchNameArg && !existing) {
        return toolError(`未找到名称为「${matchNameArg}」的订阅源。`);
      }

      const now = Date.now();

      if (existing) {
        const nextName = typeof args.name === "string" && args.name.trim() ? args.name.trim() : existing.name;
        const nextUrl =
          typeof args.url === "string" ? args.url.trim() || "local://imported-file" : existing.url;
        const nextFetchUa =
          typeof args.fetch_ua === "string" && args.fetch_ua.trim() ? args.fetch_ua.trim() : existing.fetch_ua;
        const nextFetchProxy =
          typeof args.fetch_proxy === "string" ? args.fetch_proxy.trim() : existing.fetch_proxy;
        const nextEnabled = typeof args.enabled === "boolean" ? args.enabled : existing.enabled;
        const nextNote = typeof args.note === "string" ? args.note : existing.note;

        let nextInlineContent =
          typeof args.inline_content === "string" ? args.inline_content : existing.inline_content;
        let nextProtocolHint = existing.protocol_hint;
        let nextUsedGb = existing.used_gb;
        let nextTotalGb = existing.total_gb;
        let nextExpireAt = existing.expire_at;
        let nextIsUnlimited = existing.is_unlimited ? 1 : 0;
        let nextLastSyncAt = existing.last_sync_at;
        let nextLastStatus = existing.last_status;

        const isRemoteUrl = nextUrl.startsWith("http://") || nextUrl.startsWith("https://");
        const urlChangedToRemote =
          typeof args.url === "string" && nextUrl !== existing.url && isRemoteUrl;
        const shouldFetchNow =
          isRemoteUrl &&
          (args.fetch_now === true || (urlChangedToRemote && typeof args.inline_content !== "string"));

        if (shouldFetchNow) {
          try {
            const fetched = await fetchUpstreamContent(nextUrl, nextFetchUa, nextFetchProxy);
            nextInlineContent = fetched.text;
            nextLastSyncAt = now;
            nextLastStatus = fetched.statusLabel;
            const bundle = parseFullConfigBundle(fetched.text);
            if (bundle.protocol_summary) {
              nextProtocolHint = bundle.protocol_summary;
            }
            const quota = parseSubscriptionUserInfo(fetched.userInfoHeader);
            if (quota) {
              nextUsedGb = quota.used_gb;
              nextTotalGb = quota.total_gb;
              nextExpireAt = quota.expire_at;
              nextIsUnlimited = 0;
            }
          } catch (err) {
            const msg = err instanceof Error ? err.message : "远程拉取失败";
            await db
              .prepare(`UPDATE subscriptions SET last_sync_at = ?, last_status = ? WHERE id = ?`)
              .bind(now, msg, existing.id)
              .run();
            return toolError(`更新订阅失败：${msg}`);
          }
        } else if (typeof args.inline_content === "string") {
          const bundle = parseFullConfigBundle(nextInlineContent);
          if (
            nextInlineContent.trim() &&
            bundle.nodes.length === 0 &&
            bundle.rules.length === 0 &&
            bundle.policy_groups.length === 0
          ) {
            return toolError(
              "未从 inline_content 中解析出任何有效代理节点（支持 Clash YAML、Surge .conf、Base64 及分享链接）。"
            );
          }
          if (bundle.nodes.length > 0) {
            nextProtocolHint = bundle.protocol_summary;
          }
          if (!isRemoteUrl) {
            nextLastSyncAt = now;
            nextLastStatus = "本地导入";
          }
        }

        await db
          .prepare(
            `UPDATE subscriptions
             SET name = ?, url = ?, fetch_ua = ?, fetch_proxy = ?, protocol_hint = ?, enabled = ?, inline_content = ?, used_gb = ?, total_gb = ?, expire_at = ?, is_unlimited = ?, last_sync_at = ?, last_status = ?, note = ?
             WHERE id = ?`
          )
          .bind(
            nextName,
            nextUrl,
            nextFetchUa,
            nextFetchProxy,
            nextProtocolHint,
            nextEnabled ? 1 : 0,
            nextInlineContent,
            nextUsedGb,
            nextTotalGb,
            nextExpireAt,
            nextIsUnlimited,
            nextLastSyncAt,
            nextLastStatus,
            nextNote,
            existing.id
          )
          .run();

        await rebuildNodePool(db, false);
        const [refreshedSubs, refreshedNodes] = await Promise.all([listSubscriptions(db), listNodes(db)]);
        const refreshed = refreshedSubs.find((s) => s.id === existing.id);
        return toolOk({
          action: "updated",
          subscription: refreshed ? formatSubscriptionSummary(refreshed, false) : null,
          pipeline: computePipelineStats(refreshedNodes),
        });
      }

      // Create new subscription
      const cleanName = typeof args.name === "string" ? args.name.trim() : "";
      if (!cleanName) {
        return toolError("参数错误：新建订阅源时 name 不能为空。");
      }

      const rawUrl = typeof args.url === "string" ? args.url.trim() : "";
      const fetchUa = typeof args.fetch_ua === "string" && args.fetch_ua.trim() ? args.fetch_ua.trim() : "auto";
      const fetchProxy = typeof args.fetch_proxy === "string" ? args.fetch_proxy.trim() : "";
      const enabled = typeof args.enabled === "boolean" ? args.enabled : true;
      const note = typeof args.note === "string" ? args.note : "";
      let inlineContent = typeof args.inline_content === "string" ? args.inline_content : "";

      const isRemoteUrl = rawUrl.startsWith("http://") || rawUrl.startsWith("https://");
      if (!isRemoteUrl && !inlineContent.trim()) {
        return toolError("参数错误：新建订阅源时需提供有效的 http(s):// url 或 inline_content。");
      }

      let usedGb = 0;
      let totalGb = 0;
      let expireAt: number | null = null;
      let isUnlimited = 1;
      let lastStatus = isRemoteUrl ? "待同步" : "本地导入";

      if (isRemoteUrl && args.fetch_now !== false) {
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
            return toolError(
              fetchProxy
                ? `通过前置代理拉取失败 (${msg})，请检查 SOCKS5/HTTP 代理地址与账号密码。`
                : `无法拉取该订阅链接 (${msg})，可传入 fetch_proxy 或直接提供 inline_content。`
            );
          }
          lastStatus = msg;
        }
      }

      const bundle = parseFullConfigBundle(inlineContent);
      if (
        inlineContent.trim() &&
        bundle.nodes.length === 0 &&
        bundle.rules.length === 0 &&
        bundle.policy_groups.length === 0
      ) {
        return toolError(
          "未从输入内容中解析出任何有效代理节点（支持 Clash/Stash YAML、Surge .conf、Base64 及分享链接）。"
        );
      }

      const newId = `sub_${now.toString(36)}_${Math.random().toString(36).slice(2, 5)}`;
      await db
        .prepare(
          `INSERT INTO subscriptions (id, name, url, fetch_ua, fetch_proxy, protocol_hint, enabled, inline_content, used_gb, total_gb, expire_at, is_unlimited, last_sync_at, last_status, note, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .bind(
          newId,
          cleanName,
          rawUrl || "local://imported-file",
          fetchUa,
          fetchProxy,
          bundle.protocol_summary,
          enabled ? 1 : 0,
          inlineContent,
          usedGb,
          totalGb,
          expireAt,
          isUnlimited,
          now,
          lastStatus,
          note,
          now
        )
        .run();

      if (args.import_rules_and_groups === true) {
        if (bundle.policy_groups.length > 0) {
          await upsertPolicyGroupsFromBundle(db, bundle.policy_groups, false);
        }
        for (const r of bundle.rules) {
          const rid = `rl_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 5)}`;
          await db
            .prepare(
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

      await saveSettings(db, { last_full_sync_at: now });
      await rebuildNodePool(db, false);
      const [refreshedSubs, refreshedNodes] = await Promise.all([listSubscriptions(db), listNodes(db)]);
      const created = refreshedSubs.find((s) => s.id === newId);
      return toolOk({
        action: "created",
        subscription: created ? formatSubscriptionSummary(created, false) : null,
        pipeline: computePipelineStats(refreshedNodes),
      });
    }

    case "delete_subscription": {
      const idArg = typeof args.id === "string" ? args.id.trim() : "";
      const nameArg = typeof args.name === "string" ? args.name.trim() : "";
      if (!idArg && !nameArg) {
        return toolError("参数错误：请提供 id 或 name。");
      }

      const subs = await listSubscriptions(db);
      const target = idArg ? subs.find((s) => s.id === idArg) : subs.find((s) => s.name === nameArg);
      if (!target) {
        return toolError(`未找到目标订阅源（${idArg || nameArg}）。`);
      }

      await db.prepare(`DELETE FROM subscriptions WHERE id = ?`).bind(target.id).run();
      await rebuildNodePool(db, false);
      const nodes = await listNodes(db);

      return toolOk({
        action: "deleted",
        deleted_subscription: formatSubscriptionSummary(target, false),
        pipeline: computePipelineStats(nodes),
      });
    }

    case "sync_subscriptions": {
      const idArg = typeof args.id === "string" ? args.id.trim() : "";
      const nameArg = typeof args.name === "string" ? args.name.trim() : "";
      const fetchRemote = args.fetch_remote !== false;

      if (idArg || nameArg) {
        const subs = await listSubscriptions(db);
        const target = idArg ? subs.find((s) => s.id === idArg) : subs.find((s) => s.name === nameArg);
        if (!target) {
          return toolError(`未找到目标订阅源（${idArg || nameArg}）。`);
        }

        const now = Date.now();
        if (fetchRemote && (target.url.startsWith("http://") || target.url.startsWith("https://"))) {
          try {
            const fetched = await fetchUpstreamContent(target.url, target.fetch_ua, target.fetch_proxy);
            const quota = parseSubscriptionUserInfo(fetched.userInfoHeader);
            const bundle = parseFullConfigBundle(fetched.text);
            await db
              .prepare(
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
                target.id
              )
              .run();
          } catch (err) {
            const msg = err instanceof Error ? err.message : "拉取失败";
            await db
              .prepare(`UPDATE subscriptions SET last_sync_at = ?, last_status = ? WHERE id = ?`)
              .bind(now, msg, target.id)
              .run();
            return toolError(`同步订阅「${target.name}」失败：${msg}`);
          }
        } else {
          await db
            .prepare(`UPDATE subscriptions SET last_sync_at = ?, last_status = ? WHERE id = ?`)
            .bind(now, target.url.startsWith("local://") ? "本地导入" : target.last_status, target.id)
            .run();
        }

        await rebuildNodePool(db, false);
        const [refreshedSubs, nodes] = await Promise.all([listSubscriptions(db), listNodes(db)]);
        const refreshed = refreshedSubs.find((s) => s.id === target.id);
        return toolOk({
          scope: "single",
          fetch_remote: fetchRemote,
          subscriptions: refreshed ? [formatSubscriptionSummary(refreshed, false)] : [],
          pipeline: computePipelineStats(nodes),
        });
      }

      await rebuildNodePool(db, fetchRemote);
      const [refreshedSubs, nodes] = await Promise.all([listSubscriptions(db), listNodes(db)]);
      return toolOk({
        scope: "all",
        fetch_remote: fetchRemote,
        subscriptions: refreshedSubs.map((s) => formatSubscriptionSummary(s, false)),
        pipeline: computePipelineStats(nodes),
      });
    }

    case "add_manual_node": {
      const nodeSpec = typeof args.node_spec === "string" ? args.node_spec : "";
      const nameOverride = typeof args.name === "string" ? args.name.trim() : undefined;
      const targetSubId = typeof args.sub_id === "string" && args.sub_id.trim() ? args.sub_id.trim() : MANUAL_SUB_ID;
      const subNameArg = typeof args.sub_name === "string" && args.sub_name.trim() ? args.sub_name.trim() : "";
      const replaceExisting = args.replace_existing !== false;

      const normalized = normalizeManualNodeInput(nodeSpec, nameOverride);
      if (normalized.error || !normalized.items) {
        return toolError(normalized.error || "节点解析失败。");
      }

      const allSubs = await listSubscriptions(db);
      const existingSub = allSubs.find((s) => s.id === targetSubId);
      const now = Date.now();

      if (existingSub) {
        if (!existingSub.url.startsWith("local://")) {
          return toolError(
            "目标订阅源为远程 URL，请勿向远程订阅直接写入手动节点，请留空 sub_id 使用默认自建节点源。"
          );
        }
        if (isYamlContent(existingSub.inline_content)) {
          return toolError(
            "目标本地订阅源当前为 YAML 格式，请使用 upsert_subscription 更新其 inline_content，或留空 sub_id 使用默认 sub_manual_nodes。"
          );
        }
      } else if (targetSubId !== MANUAL_SUB_ID) {
        return toolError(`未找到 ID 为「${targetSubId}」的本地订阅源。`);
      } else {
        await db
          .prepare(
            `INSERT INTO subscriptions (id, name, url, fetch_ua, fetch_proxy, protocol_hint, enabled, inline_content, used_gb, total_gb, expire_at, is_unlimited, last_sync_at, last_status, note, created_at)
             VALUES (?, ?, ?, 'auto', '', '', 1, '', 0, 0, NULL, 1, ?, '本地导入', 'MCP 手动添加节点', ?)`
          )
          .bind(MANUAL_SUB_ID, subNameArg || MANUAL_SUB_DEFAULT_NAME, MANUAL_SUB_URL, now, now)
          .run();
      }

      let baseContent = existingSub ? existingSub.inline_content : "";
      if (replaceExisting && baseContent.trim()) {
        const incomingNames = new Set(normalized.items.map((item) => item.raw_name));
        const incomingFps = new Set(normalized.items.map((item) => item.fingerprint));
        baseContent = removeMatchingNodesFromLocalContent(
          baseContent,
          (candidate) => incomingNames.has(candidate.raw_name) || incomingFps.has(candidate.fingerprint)
        ).nextContent;
      }

      const combinedLines = [
        ...(baseContent.trim() ? [baseContent.trim()] : []),
        ...normalized.items.map((item) => item.line),
      ];
      const nextContent = combinedLines.join("\n");
      const updatedBundle = parseFullConfigBundle(nextContent);

      await db
        .prepare(
          `UPDATE subscriptions
           SET inline_content = ?, protocol_hint = ?, last_sync_at = ?, last_status = '本地导入'
           WHERE id = ?`
        )
        .bind(nextContent, updatedBundle.protocol_summary, now, targetSubId)
        .run();

      await rebuildNodePool(db, false);
      const [refreshedSubs, allNodes] = await Promise.all([listSubscriptions(db), listNodes(db)]);
      const updatedSub = refreshedSubs.find((s) => s.id === targetSubId);
      const incomingNames = new Set(normalized.items.map((item) => item.raw_name));
      const incomingFps = new Set(normalized.items.map((item) => item.fingerprint));
      const matchedAddedNodes = allNodes.filter(
        (n) => n.sub_id === targetSubId && (incomingNames.has(n.raw_name) || incomingFps.has(n.fingerprint))
      );

      return toolOk({
        action: "added",
        subscription: updatedSub ? formatSubscriptionSummary(updatedSub, false) : null,
        added_count: normalized.items.length,
        nodes: matchedAddedNodes.map((n) => ({
          id: n.id,
          sub_id: n.sub_id,
          normalized_name: n.normalized_name,
          raw_name: n.raw_name,
          protocol: n.protocol,
          server: n.server,
          port: n.port,
          fingerprint: n.fingerprint,
          status: n.status,
          filter_reason: n.filter_reason,
        })),
        pipeline: computePipelineStats(allNodes),
      });
    }

    case "delete_manual_node": {
      const nodeIdArg = typeof args.node_id === "string" ? args.node_id.trim() : "";
      const nameArg = typeof args.name === "string" ? args.name.trim() : "";
      const serverArg = typeof args.server === "string" ? args.server.trim().toLowerCase() : "";
      const portArg = typeof args.port === "number" ? args.port : undefined;
      const subIdArg = typeof args.sub_id === "string" ? args.sub_id.trim() : "";

      if (!nodeIdArg && !nameArg && !serverArg) {
        return toolError("参数错误：请至少提供 node_id、name 或 server 之一。");
      }

      const [allNodes, allSubs] = await Promise.all([listNodes(db), listSubscriptions(db)]);
      const subById = new Map(allSubs.map((s) => [s.id, s]));

      const matched = allNodes.filter((n) => {
        if (subIdArg && n.sub_id !== subIdArg) return false;
        if (nodeIdArg && n.id !== nodeIdArg) return false;
        if (nameArg && n.normalized_name !== nameArg && n.raw_name !== nameArg) return false;
        if (serverArg && n.server.toLowerCase() !== serverArg) return false;
        if (typeof portArg === "number" && n.port !== portArg) return false;
        return true;
      });

      if (matched.length === 0) {
        return toolError("未找到符合条件的节点。");
      }

      const localMatches = matched.filter((n) => subById.get(n.sub_id)?.url.startsWith("local://"));
      const remoteMatches = matched.filter((n) => {
        const sub = subById.get(n.sub_id);
        return sub && !sub.url.startsWith("local://");
      });

      if (localMatches.length === 0 && remoteMatches.length > 0) {
        return toolError(
          "匹配到的节点全部来自远程订阅源，远程订阅源的节点无法单条物理删除。请改用 update_settings(exclude_regex) 过滤，或用 upsert_subscription(enabled=false) 停用对应订阅。"
        );
      }

      const targetsBySub = new Map<string, ProxyNode[]>();
      for (const n of localMatches) {
        const list = targetsBySub.get(n.sub_id) || [];
        list.push(n);
        targetsBySub.set(n.sub_id, list);
      }

      const now = Date.now();
      const deletedNodes: Array<{
        id: string;
        sub_id: string;
        normalized_name: string;
        raw_name: string;
        server: string;
        port: number;
      }> = [];

      for (const [subId, targetNodes] of targetsBySub) {
        const sub = subById.get(subId);
        if (!sub) continue;
        const targetPairs = new Set(targetNodes.map((n) => `${n.raw_name}\0${n.fingerprint}`));
        const { nextContent, removed } = removeMatchingNodesFromLocalContent(
          sub.inline_content,
          (candidate) => targetPairs.has(`${candidate.raw_name}\0${candidate.fingerprint}`)
        );
        if (removed.length > 0) {
          const nextBundle = parseFullConfigBundle(nextContent);
          await db
            .prepare(
              `UPDATE subscriptions
               SET inline_content = ?, protocol_hint = ?, last_sync_at = ?
               WHERE id = ?`
            )
            .bind(nextContent, nextBundle.nodes.length > 0 ? nextBundle.protocol_summary : "", now, subId)
            .run();
          for (const tn of targetNodes) {
            deletedNodes.push({
              id: tn.id,
              sub_id: tn.sub_id,
              normalized_name: tn.normalized_name,
              raw_name: tn.raw_name,
              server: tn.server,
              port: tn.port,
            });
          }
        }
      }

      await rebuildNodePool(db, false);
      const refreshedNodes = await listNodes(db);

      return toolOk({
        action: "deleted",
        deleted_count: deletedNodes.length,
        deleted_nodes: deletedNodes,
        ...(remoteMatches.length > 0
          ? {
              skipped_remote_count: remoteMatches.length,
              note: "部分同名/同服务器节点属于远程订阅源，已自动跳过。",
            }
          : {}),
        pipeline: computePipelineStats(refreshedNodes),
      });
    }

    case "get_node_detail": {
      const idArg = typeof args.id === "string" ? args.id.trim() : "";
      const nameArg = typeof args.name === "string" ? args.name.trim() : "";
      const includeSecrets = args.include_secrets === true;

      if (!idArg && !nameArg) {
        return toolError("参数错误：请提供 id 或 name。");
      }

      const [nodes, groups] = await Promise.all([listNodes(db), listPolicyGroups(db)]);
      let node: ProxyNode | undefined;
      if (idArg) {
        node = nodes.find((n) => n.id === idArg);
      } else {
        const lower = nameArg.toLowerCase();
        node =
          nodes.find((n) => n.normalized_name === nameArg) ||
          nodes.find((n) => n.raw_name === nameArg) ||
          nodes.find((n) => n.normalized_name.toLowerCase() === lower || n.raw_name.toLowerCase() === lower);
      }

      if (!node) {
        return toolError(`未找到目标节点（${idArg || nameArg}）。`);
      }

      const matchedPolicyGroups = groups
        .filter((g) => matchNodesForGroup(g, [node]).length > 0)
        .map((g) => ({ id: g.id, name: g.name, type: g.type }));

      const compiled = compileSingleNodePreview(node);

      return toolOk({
        node: {
          ...node,
          cipher_or_param: includeSecrets ? node.cipher_or_param : node.cipher_or_param ? "***" : "",
          raw_config: includeSecrets ? node.raw_config : redactRawConfig(node.raw_config),
        },
        matched_policy_groups: matchedPolicyGroups,
        compiled_preview: includeSecrets
          ? compiled
          : {
              surge5: redactSurgeRhs(compiled.surge5),
              surge6: redactSurgeRhs(compiled.surge6),
              stash: redactClashProxy(compiled.stash),
            },
      });
    }

    case "probe_nodes": {
      const nodeIds = Array.isArray(args.node_ids)
        ? args.node_ids.filter((x): x is string => typeof x === "string").map((x) => x.trim()).filter(Boolean)
        : [];
      const regionFilter = typeof args.region === "string" ? args.region.trim().toUpperCase() : "";
      const subIdFilter = typeof args.sub_id === "string" ? args.sub_id.trim() : "";
      const query = typeof args.query === "string" ? args.query.trim().toLowerCase() : "";
      const timeoutMs = typeof args.timeout_ms === "number" ? args.timeout_ms : 2500;
      const rawLimit = typeof args.limit === "number" ? Math.floor(args.limit) : 50;
      const limit = Math.max(1, Math.min(150, rawLimit));

      let targets = (await listNodes(db)).filter((n) => n.status === "active");
      if (nodeIds.length > 0) {
        const idSet = new Set(nodeIds);
        targets = targets.filter((n) => idSet.has(n.id));
      }
      if (regionFilter) {
        targets = targets.filter((n) => n.region.toUpperCase() === regionFilter);
      }
      if (subIdFilter) {
        targets = targets.filter((n) => n.sub_id === subIdFilter);
      }
      if (query) {
        targets = targets.filter(
          (n) =>
            n.normalized_name.toLowerCase().includes(query) ||
            n.raw_name.toLowerCase().includes(query) ||
            n.protocol.toLowerCase().includes(query) ||
            n.server.toLowerCase().includes(query)
        );
      }

      targets = targets.slice(0, limit);
      if (targets.length === 0) {
        return toolOk({
          probed_count: 0,
          reachable_count: 0,
          unreachable_count: 0,
          avg_latency_ms: null,
          results: [],
        });
      }

      const summary = await probeNodes(db, targets, { timeoutMs });
      return toolOk(summary);
    }

    case "upsert_policy_group": {
      const cleanName = typeof args.name === "string" ? args.name.trim() : "";
      if (!cleanName) {
        return toolError("参数错误：name 不能为空。");
      }

      const rawType = typeof args.type === "string" ? args.type.trim() : undefined;
      if (rawType && !VALID_POLICY_GROUP_TYPES.has(rawType as PolicyGroup["type"])) {
        return toolError(`无效的策略组类型「${rawType}」，仅支持 url-test / fallback / select / smart。`);
      }

      const allGroups = await listPolicyGroups(db);
      const idArg = typeof args.id === "string" ? args.id.trim() : "";
      const matchNameArg = typeof args.match_name === "string" ? args.match_name.trim() : "";

      const existing = idArg
        ? allGroups.find((g) => g.id === idArg)
        : matchNameArg
          ? allGroups.find((g) => g.name === matchNameArg)
          : allGroups.find((g) => g.name === cleanName);

      if (idArg && !existing) {
        return toolError(`未找到 ID 为「${idArg}」的策略组。`);
      }

      const fallbackGroupsArg = Array.isArray(args.fallback_groups)
        ? args.fallback_groups.filter((x): x is string => typeof x === "string").map((x) => x.trim()).filter(Boolean)
        : undefined;

      if (existing) {
        if (cleanName !== existing.name && allGroups.some((g) => g.id !== existing.id && g.name === cleanName)) {
          return toolError(`已存在同名策略组「${cleanName}」。`);
        }

        const nextType = (rawType as PolicyGroup["type"]) || existing.type;
        const nextRegex = typeof args.filter_regex === "string" ? args.filter_regex : existing.filter_regex;
        const nextFallback = (fallbackGroupsArg ?? existing.fallback_groups).filter((x) => x !== cleanName);
        const nextInterval = typeof args.interval_sec === "number" ? args.interval_sec : existing.interval_sec;
        const nextTolerance = typeof args.tolerance_ms === "number" ? args.tolerance_ms : existing.tolerance_ms;
        const nextSort = typeof args.sort_order === "number" ? args.sort_order : existing.sort_order;

        await db
          .prepare(
            `UPDATE policy_groups
             SET name = ?, type = ?, filter_regex = ?, fallback_groups_json = ?, interval_sec = ?, tolerance_ms = ?, sort_order = ?
             WHERE id = ?`
          )
          .bind(
            cleanName,
            nextType,
            nextRegex,
            JSON.stringify(nextFallback),
            nextInterval,
            nextTolerance,
            nextSort,
            existing.id
          )
          .run();

        if (cleanName !== existing.name) {
          await db
            .prepare(`UPDATE rules SET target_policy = ? WHERE target_policy = ?`)
            .bind(cleanName, existing.name)
            .run();

          for (const g of allGroups) {
            if (g.id !== existing.id && g.fallback_groups.includes(existing.name)) {
              const updatedFb = g.fallback_groups.map((item) => (item === existing.name ? cleanName : item));
              await db
                .prepare(`UPDATE policy_groups SET fallback_groups_json = ? WHERE id = ?`)
                .bind(JSON.stringify(updatedFb), g.id)
                .run();
            }
          }
        }

        const nodes = await listNodes(db);
        const refreshed = (await listPolicyGroups(db, nodes)).find((g) => g.id === existing.id);
        return toolOk({
          action: "updated",
          renamed_from: cleanName !== existing.name ? existing.name : null,
          policy_group: refreshed,
        });
      }

      const newId = `pg_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 5)}`;
      const nextType = (rawType as PolicyGroup["type"]) || "select";
      const nextRegex = typeof args.filter_regex === "string" ? args.filter_regex : "";
      const nextFallback = (fallbackGroupsArg || []).filter((x) => x !== cleanName);
      const nextInterval = typeof args.interval_sec === "number" ? args.interval_sec : 300;
      const nextTolerance = typeof args.tolerance_ms === "number" ? args.tolerance_ms : 20;
      const nextSort = typeof args.sort_order === "number" ? args.sort_order : allGroups.length + 1;

      await db
        .prepare(
          `INSERT INTO policy_groups (id, name, type, filter_regex, interval_sec, tolerance_ms, fallback_groups_json, sort_order)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .bind(
          newId,
          cleanName,
          nextType,
          nextRegex,
          nextInterval,
          nextTolerance,
          JSON.stringify(nextFallback),
          nextSort
        )
        .run();

      const nodes = await listNodes(db);
      const created = (await listPolicyGroups(db, nodes)).find((g) => g.id === newId);
      return toolOk({ action: "created", policy_group: created });
    }

    case "delete_policy_group": {
      const idArg = typeof args.id === "string" ? args.id.trim() : "";
      const nameArg = typeof args.name === "string" ? args.name.trim() : "";
      if (!idArg && !nameArg) {
        return toolError("参数错误：请提供 id 或 name。");
      }

      const allGroups = await listPolicyGroups(db);
      const target = idArg ? allGroups.find((g) => g.id === idArg) : allGroups.find((g) => g.name === nameArg);
      if (!target) {
        return toolError(`未找到目标策略组（${idArg || nameArg}）。`);
      }

      await db.prepare(`DELETE FROM policy_groups WHERE id = ?`).bind(target.id).run();

      const remaining = allGroups.filter((g) => g.id !== target.id);
      const sameNameStillExists = remaining.some((g) => g.name === target.name);
      let fallbackName: string | null = null;

      if (!sameNameStillExists) {
        fallbackName = remaining[0]?.name || "DIRECT";
        await db
          .prepare(`UPDATE rules SET target_policy = ? WHERE target_policy = ?`)
          .bind(fallbackName, target.name)
          .run();
        for (const g of remaining) {
          if (g.fallback_groups.includes(target.name)) {
            const nextFb = g.fallback_groups.filter((x) => x !== target.name);
            await db
              .prepare(`UPDATE policy_groups SET fallback_groups_json = ? WHERE id = ?`)
              .bind(JSON.stringify(nextFb), g.id)
              .run();
          }
        }
      }

      return toolOk({
        action: "deleted",
        deleted_group: { id: target.id, name: target.name },
        rules_fallback_to: fallbackName,
      });
    }

    case "upsert_rule": {
      const rType = typeof args.rule_type === "string" ? args.rule_type.trim().toUpperCase() : "";
      if (!VALID_RULE_TYPES.has(rType as RoutingRule["rule_type"])) {
        return toolError(`无效的规则类型「${rType}」。`);
      }
      const rawPayload = typeof args.payload === "string" ? args.payload.trim() : "";
      const payload = rawPayload || (rType === "FINAL" ? "dns-failed" : "");
      const targetPolicy = typeof args.target_policy === "string" ? args.target_policy.trim() : "";
      if (!targetPolicy || (rType !== "FINAL" && !payload)) {
        return toolError("参数错误：target_policy 不能为空，且非 FINAL 规则的 payload 不能为空。");
      }

      const inferredKind: "override" | "ruleset" =
        rType === "RULE-SET" || rType === "GEOIP" || rType === "FINAL" ? "ruleset" : "override";
      const kind: "override" | "ruleset" =
        args.kind === "override" || args.kind === "ruleset" ? args.kind : inferredKind;
      const title =
        typeof args.title === "string" && args.title.trim()
          ? args.title.trim()
          : rType === "FINAL"
            ? "全局兜底路由策略"
            : `${rType} · ${payload}`;
      const noResolve = args.no_resolve === true ? 1 : 0;
      const idArg = typeof args.id === "string" ? args.id.trim() : "";

      if (idArg) {
        const existing = (await listRules(db)).find((r) => r.id === idArg);
        if (!existing) {
          return toolError(`未找到 ID 为「${idArg}」的规则。`);
        }

        await db
          .prepare(
            `UPDATE rules
             SET kind = ?, rule_type = ?, title = ?, payload = ?, target_policy = ?, no_resolve = ?, enabled = COALESCE(?, enabled), priority = COALESCE(?, priority)
             WHERE id = ?`
          )
          .bind(
            kind,
            rType,
            title,
            payload,
            targetPolicy,
            noResolve,
            typeof args.enabled === "boolean" ? (args.enabled ? 1 : 0) : null,
            typeof args.priority === "number" ? args.priority : null,
            idArg
          )
          .run();

        const updated = (await listRules(db)).find((r) => r.id === idArg);
        return toolOk({ action: "updated", rule: updated });
      }

      const newId = `rl_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 5)}`;
      const enabled = typeof args.enabled === "boolean" ? (args.enabled ? 1 : 0) : 1;
      const priority =
        typeof args.priority === "number"
          ? args.priority
          : rType === "FINAL"
            ? 9999
            : kind === "override"
              ? 1
              : 50;

      await db
        .prepare(
          `INSERT INTO rules (id, kind, rule_type, title, payload, target_policy, rule_count, no_resolve, sync_meta, enabled, priority)
           VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)`
        )
        .bind(
          newId,
          kind,
          rType,
          title,
          payload,
          targetPolicy,
          noResolve,
          kind === "ruleset" ? "Rule-Set" : "MCP 规则",
          enabled,
          priority
        )
        .run();

      const created = (await listRules(db)).find((r) => r.id === newId);
      return toolOk({ action: "created", rule: created });
    }

    case "delete_rule": {
      const id = typeof args.id === "string" ? args.id.trim() : "";
      if (!id) {
        return toolError("参数错误：id 不能为空。");
      }
      const existing = (await listRules(db)).find((r) => r.id === id);
      if (!existing) {
        return toolError(`未找到 ID 为「${id}」的规则。`);
      }
      await db.prepare(`DELETE FROM rules WHERE id = ?`).bind(id).run();
      return toolOk({ action: "deleted", deleted_rule: existing });
    }

    case "scaffold_policy_and_rules": {
      const nodes = (await listNodes(db)).filter((n) => n.status === "active");
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

      const scaffoldGroups: Omit<PolicyGroup, "id" | "matched_count">[] = presentRegions.map((rg, idx) => ({
        name: regionLabels[rg] || `${rg} · Auto`,
        type: "url-test",
        filter_regex: `/^${rg}\\b/`,
        interval_sec: 300,
        tolerance_ms: 20,
        fallback_groups: [],
        sort_order: idx + 1,
      }));

      const createdGroupNames = scaffoldGroups.map((g) => g.name);
      scaffoldGroups.unshift({
        name: "Proxy",
        type: "select",
        filter_regex: "",
        interval_sec: 300,
        tolerance_ms: 20,
        fallback_groups: [...createdGroupNames, "DIRECT"],
        sort_order: 0,
      });

      await upsertPolicyGroupsFromBundle(db, scaffoldGroups, false);

      const existingRules = await listRules(db);
      let rulesSeeded = 0;
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
          await db
            .prepare(
              `INSERT INTO rules (id, kind, rule_type, title, payload, target_policy, rule_count, no_resolve, sync_meta, enabled, priority)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Tower Built-in', 1, ?)`
            )
            .bind(r.id, r.kind, r.type, r.title, r.payload, r.policy, r.count, r.noRes, r.prio)
            .run();
        }
        rulesSeeded = stdRules.length;
      }

      const refreshedGroups = await listPolicyGroups(db, nodes);
      return toolOk({
        upserted_groups: scaffoldGroups.length,
        rules_seeded: rulesSeeded,
        policy_groups: refreshedGroups,
      });
    }

    case "update_settings": {
      const current = await getSettings(db);
      const next = await saveSettings(db, {
        rename_template: typeof args.rename_template === "string" ? args.rename_template : current.rename_template,
        exclude_regex: typeof args.exclude_regex === "string" ? args.exclude_regex : current.exclude_regex,
        max_multiplier: typeof args.max_multiplier === "number" ? args.max_multiplier : current.max_multiplier,
        dedup_enabled: typeof args.dedup_enabled === "boolean" ? args.dedup_enabled : current.dedup_enabled,
        ua_guard_enabled: typeof args.ua_guard_enabled === "boolean" ? args.ua_guard_enabled : current.ua_guard_enabled,
        strict_client_ua: typeof args.strict_client_ua === "boolean" ? args.strict_client_ua : current.strict_client_ua,
        revision: args.bump_revision === true ? current.revision + 1 : current.revision,
      });

      const needsRebuild =
        typeof args.rename_template === "string" ||
        typeof args.exclude_regex === "string" ||
        typeof args.max_multiplier === "number" ||
        typeof args.dedup_enabled === "boolean";

      let pipelineStats = null;
      if (needsRebuild) {
        await rebuildNodePool(db, false);
        pipelineStats = computePipelineStats(await listNodes(db));
      }

      return toolOk({
        settings: {
          ...next,
          sub_token: maskToken(next.sub_token),
          mcp_token: maskToken(next.mcp_token),
        },
        node_pool_rebuilt: needsRebuild,
        pipeline: pipelineStats,
      });
    }

    case "simulate_route": {
      const target = typeof args.target === "string" ? args.target.trim() : "";
      if (!target) {
        return toolError("参数错误：target 不能为空。");
      }
      const [nodes, rules] = await Promise.all([listNodes(db), listRules(db)]);
      const groups = await listPolicyGroups(db, nodes);
      return toolOk(simulateRoute(target, rules, groups, nodes));
    }

    case "compile_profile": {
      const format =
        args.format === "stash"
          ? "stash"
          : args.format === "surge6"
            ? "surge6"
            : args.format === "surge"
              ? "surge"
              : null;
      if (!format) {
        return toolError("参数错误：format 必须为 'surge'、'surge6' 或 'stash'。");
      }
      const enableVless = typeof args.enable_vless === "boolean" ? args.enable_vless : format === "surge6";
      const bumpRevision = args.bump_revision === true;

      let settings = await getSettings(db);
      if (bumpRevision) {
        settings = await saveSettings(db, {
          revision: settings.revision + 1,
          last_full_sync_at: Date.now(),
        });
      }

      const [nodes, rules] = await Promise.all([listNodes(db), listRules(db)]);
      const groups = await listPolicyGroups(db, nodes);
      const content =
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

      const activeNodeCount = nodes.filter((n) => n.status === "active").length;
      const enabledRuleCount = rules.filter((r) => r.enabled).length;
      const filename =
        format === "stash"
          ? `Tower-v${settings.revision}.yaml`
          : format === "surge6"
            ? `Tower-Surge6-v${settings.revision}.conf`
            : `Tower-v${settings.revision}.conf`;

      return toolOk({
        format,
        ...(format === "stash" ? {} : { enable_vless: enableVless }),
        filename,
        revision: settings.revision,
        line_count: content.split("\n").length,
        active_node_count: activeNodeCount,
        policy_group_count: groups.length,
        enabled_rule_count: enabledRuleCount,
        content,
      });
    }

    case "publish_revision": {
      const syncSubscriptions = args.sync_subscriptions === true;
      let syncSummary: { active: number; raw: number } | null = null;
      if (syncSubscriptions) {
        syncSummary = await rebuildNodePool(db, true);
      }

      const current = await getSettings(db);
      const updated = await saveSettings(db, {
        revision: current.revision + 1,
        last_full_sync_at: Date.now(),
      });

      const [nodes, rules] = await Promise.all([listNodes(db), listRules(db)]);
      const groups = await listPolicyGroups(db, nodes);
      const surge = compileSurgeProfile({
        origin,
        settings: updated,
        nodes,
        groups,
        rules,
        target: "surge",
        enableVless: false,
      });
      const surge6 = compileSurgeProfile({
        origin,
        settings: updated,
        nodes,
        groups,
        rules,
        target: "surge6",
        enableVless: true,
      });
      const stash = compileStashYaml({ origin, settings: updated, nodes, groups, rules });

      return toolOk({
        published: true,
        revision: updated.revision,
        synced_subscriptions: syncSubscriptions,
        sync_summary: syncSummary,
        compiled_summary: {
          active_nodes: nodes.filter((n) => n.status === "active").length,
          policy_groups: groups.length,
          enabled_rules: rules.filter((r) => r.enabled).length,
          surge_line_count: surge.split("\n").length,
          surge6_line_count: surge6.split("\n").length,
          stash_line_count: stash.split("\n").length,
          stash_provider_count: rules.filter((r) => r.enabled && r.rule_type === "RULE-SET").length,
        },
      });
    }

    default:
      return toolError(`未知工具：${name}`);
  }
}

async function handleJsonRpcMessage(
  msg: unknown,
  ctx: McpToolContext
): Promise<JsonRpcResponse | null> {
  if (!msg || typeof msg !== "object" || Array.isArray(msg)) {
    return {
      jsonrpc: "2.0",
      id: null,
      error: { code: -32600, message: "Invalid Request" },
    };
  }

  const req = msg as JsonRpcRequest;
  const hasId = req.id !== undefined && req.id !== null;
  const id = req.id ?? null;

  if (req.jsonrpc !== "2.0" || typeof req.method !== "string") {
    return {
      jsonrpc: "2.0",
      id,
      error: { code: -32600, message: "Invalid JSON-RPC 2.0 request" },
    };
  }

  // Notifications (no id) require no JSON-RPC response body
  if (!hasId) {
    return null;
  }

  const params = req.params && typeof req.params === "object" ? req.params : {};

  switch (req.method) {
    case "initialize": {
      const requested = typeof params.protocolVersion === "string" ? params.protocolVersion : "";
      const protocolVersion = SUPPORTED_PROTOCOL_VERSIONS.has(requested)
        ? requested
        : DEFAULT_PROTOCOL_VERSION;
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion,
          capabilities: {
            tools: { listChanged: false },
          },
          serverInfo: {
            name: "tower-mcp",
            version: "0.1.0",
          },
          instructions:
            "Tower MCP Server：用于管理订阅源与自建节点（增改删、同步拉取、TCP 测速、单节点详情与多端编译预览），编排策略组、分流规则与节点清洗设置，进行路由命中模拟，以及编译/发布 Surge 5 / Surge 6 / Stash 配置产物。",
        },
      };
    }

    case "ping":
      return { jsonrpc: "2.0", id, result: {} };

    case "tools/list":
      return {
        jsonrpc: "2.0",
        id,
        result: { tools: MCP_TOOLS },
      };

    case "tools/call": {
      const toolName = typeof params.name === "string" ? params.name : "";
      if (!toolName) {
        return {
          jsonrpc: "2.0",
          id,
          error: { code: -32602, message: "Missing required parameter: name" },
        };
      }
      const toolArgs =
        params.arguments && typeof params.arguments === "object" && !Array.isArray(params.arguments)
          ? (params.arguments as Record<string, unknown>)
          : {};
      try {
        const result = await executeTool(toolName, toolArgs, ctx);
        return { jsonrpc: "2.0", id, result };
      } catch (err) {
        return {
          jsonrpc: "2.0",
          id,
          result: toolError(`工具执行失败：${err instanceof Error ? err.message : String(err)}`),
        };
      }
    }

    default:
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32601, message: `Method not found: ${req.method}` },
      };
  }
}

export async function handleMcpPost(req: Request, ctx: McpToolContext): Promise<Response> {
  let payload: unknown;
  try {
    payload = await req.json();
  } catch {
    return Response.json(
      {
        jsonrpc: "2.0",
        id: null,
        error: { code: -32700, message: "Parse error: invalid JSON body" },
      },
      { status: 400 }
    );
  }

  if (Array.isArray(payload)) {
    if (payload.length === 0) {
      return Response.json(
        {
          jsonrpc: "2.0",
          id: null,
          error: { code: -32600, message: "Invalid Request: empty batch" },
        },
        { status: 400 }
      );
    }
    const responses: JsonRpcResponse[] = [];
    for (const item of payload) {
      const res = await handleJsonRpcMessage(item, ctx);
      if (res) responses.push(res);
    }
    if (responses.length === 0) {
      return new Response(null, { status: 202 });
    }
    return Response.json(responses, { status: 200 });
  }

  const response = await handleJsonRpcMessage(payload, ctx);
  if (!response) {
    return new Response(null, { status: 202 });
  }
  return Response.json(response, { status: 200 });
}
