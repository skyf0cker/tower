import { parse as parseYaml } from "yaml";
import type { PolicyGroup, RawNodeConfig, RoutingRule } from "../../shared/types";

export interface RawParsedNode {
  raw_name: string;
  protocol: string;
  server: string;
  port: number;
  cipher_or_param: string;
  raw_config: RawNodeConfig;
  region: string;
  line_tag: string;
  multiplier: number;
  latency_ms: number | null;
}

export interface UserInfoQuota {
  used_gb: number;
  total_gb: number;
  expire_at: number | null;
}

export interface ParsedFullBundle {
  nodes: RawParsedNode[];
  policy_groups: Omit<PolicyGroup, "id" | "matched_count">[];
  rules: Omit<RoutingRule, "id">[];
  protocol_summary: string;
}

const BUILTIN_POLICIES = new Set(["DIRECT", "REJECT", "REJECT-DROP", "REJECT-TINYGIF", "PASS"]);

const REGION_PATTERNS: Array<{ code: string; regex: RegExp }> = [
  { code: "HK", regex: /(香港|深港|沪港|广港|HK|HKG|Hong\s*Kong)/i },
  { code: "TW", regex: /(台湾|台北|新北|彰化|台中|高雄|TW|TPE|Taiwan|Taipei|Hinet)/i },
  { code: "JP", regex: /(日本|东京|大阪|埼玉|长野|JP|NRT|KIX|TYO|Japan|Tokyo|Osaka|ap-northeast)/i },
  { code: "SG", regex: /(新加坡|狮城|SG|SIN|Singapore|ap-southeast-1)/i },
  { code: "US", regex: /(美国|美西|美东|圣何塞|洛杉矶|硅谷|西雅图|芝加哥|达拉斯|纽约|波特兰|US|USA|SJC|LAX|SEA|ORD|NYC|United\s*States|America|us-west|us-east)/i },
  { code: "KR", regex: /(韩国|首尔|春川|釜山|KR|ICN|SEL|Korea|Seoul)/i },
  { code: "DE", regex: /(德国|法兰克福|慕尼黑|DE|FRA|Germany|Frankfurt)/i },
  { code: "UK", regex: /(英国|伦敦|曼彻斯特|UK|GB|LHR|LON|London|Britain|United\s*Kingdom)/i },
  { code: "FR", regex: /(法国|巴黎|FR|CDG|France|Paris)/i },
  { code: "NL", regex: /(荷兰|阿姆斯特丹|NL|AMS|Netherlands|Amsterdam)/i },
  { code: "CA", regex: /(加拿大|多伦多|温哥华|CA|YYZ|YVR|Canada|Toronto|Vancouver)/i },
  { code: "AU", regex: /(澳大利亚|澳洲|悉尼|墨尔本|AU|SYD|MEL|Australia|Sydney)/i },
  { code: "IN", regex: /(印度|孟买|IN|BOM|India|Mumbai)/i },
  { code: "TR", regex: /(土耳其|伊斯坦布尔|TR|IST|Turkey|Türkiye)/i },
  { code: "AR", regex: /(阿根廷|布宜诺斯|AR|Argentina)/i },
  { code: "RU", regex: /(俄罗斯|莫斯科|伯力|RU|Russia|Moscow)/i },
  { code: "MY", regex: /(马来西亚|吉隆坡|MY|KUL|Malaysia)/i },
  { code: "TH", regex: /(泰国|曼谷|TH|BKK|Thailand)/i },
];

export function detectRegion(name: string, server = ""): string {
  const combined = `${name} ${server}`;
  for (const item of REGION_PATTERNS) {
    if (item.regex.test(combined)) return item.code;
  }
  return "GLOBAL";
}

export function detectLineTag(name: string, protocol: string): string {
  if (/IEPL/i.test(name)) return "IEPL";
  if (/IPLC/i.test(name)) return "IPLC";
  if (/AIA|公有云|专线/i.test(name)) return "专线";
  if (/(家宽|住宅|原生|ISP|Residential|Hinet|ATT|Verizon)/i.test(name)) return "ISP";
  if (/(CN2|GIA)/i.test(name)) return "GIA";
  if (/BGP/i.test(name)) return "BGP";
  if (/(游戏|Game|UDP|低延迟)/i.test(name)) return "Game";
  if (/(流媒体|解锁|NF|Netflix|Disney|AI|GPT|OpenAI)/i.test(name)) return "Media";
  if (/(自建|Static|Direct)/i.test(name)) return "Static";
  const p = protocol.toLowerCase();
  if (p.includes("hysteria")) return "HY2";
  if (p.includes("tuic")) return "TUIC";
  if (p.includes("snell")) return "Snell";
  return "Relay";
}

export function detectMultiplier(name: string): number {
  const patterns = [
    /(?:倍率|rate)\s*[:：]?\s*(\d+(?:\.\d+)?)/i,
    /[*×xX]\s*(\d+(?:\.\d+)?)(?![a-zA-Z0-9])/i,
    /(\d+(?:\.\d+)?)\s*(?:[xX×]|倍)(?![a-zA-Z0-9])/i,
  ];
  for (const pat of patterns) {
    const m = name.match(pat);
    if (m && m[1]) {
      const val = parseFloat(m[1]);
      if (!Number.isNaN(val) && val >= 0 && val <= 50) {
        return val;
      }
    }
  }
  return 1.0;
}

export function normalizeProtocolLabel(proto: string): string {
  const p = proto.toLowerCase().trim();
  if (p === "ss" || p === "shadowsocks") return "Shadowsocks";
  if (p === "ssr") return "SSR";
  if (p === "snell") return "Snell";
  if (p === "trojan") return "Trojan";
  if (p === "hysteria2" || p === "hy2") return "Hysteria 2";
  if (p === "hysteria") return "Hysteria";
  if (p === "tuic" || p === "tuic-v5" || p === "tuic5") return "TUIC";
  if (p === "vless") return "VLESS";
  if (p === "vmess") return "VMess";
  if (p === "anytls") return "AnyTLS";
  if (p === "socks5" || p === "socks5-tls") return "SOCKS5";
  if (p === "http" || p === "https") return "HTTPS";
  if (p === "wireguard") return "WireGuard";
  return proto || "Proxy";
}

export function parseSubscriptionUserInfo(header: string | null): UserInfoQuota | null {
  if (!header) return null;
  const map: Record<string, number> = {};
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim().toLowerCase();
    const v = Number(part.slice(idx + 1).trim());
    if (k && !Number.isNaN(v)) map[k] = v;
  }
  if (typeof map.total === "number" && map.total > 0) {
    const usedBytes = (map.upload || 0) + (map.download || 0);
    return {
      used_gb: Math.round((usedBytes / 1024 ** 3) * 100) / 100,
      total_gb: Math.round((map.total / 1024 ** 3) * 100) / 100,
      expire_at: map.expire ? map.expire * 1000 : null,
    };
  }
  return null;
}

function escapeRegexLiteral(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function safeDecodeBase64(input: string): string | null {
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

function maybeUnwrapSubscriptionBase64(rawText: string): string {
  const trimmed = rawText.trim();
  if (
    !trimmed ||
    trimmed.includes("proxies:") ||
    trimmed.includes("[Proxy]") ||
    trimmed.includes("://") ||
    trimmed.includes(" = ")
  ) {
    return trimmed;
  }
  const decoded = safeDecodeBase64(trimmed);
  if (decoded && (decoded.includes("://") || decoded.includes("proxies:") || decoded.includes("="))) {
    return decoded;
  }
  return trimmed;
}

function parseUriLine(line: string): RawParsedNode | null {
  if (/^vmess:\/\//i.test(line)) {
    const payload = line.slice(8).split("#")[0];
    const jsonStr = safeDecodeBase64(payload);
    if (jsonStr && jsonStr.trim().startsWith("{")) {
      try {
        const v = JSON.parse(jsonStr) as Record<string, unknown>;
        const name = String(v.ps || v.add || "VMess Node").trim();
        const server = String(v.add || "").trim();
        const port = Number(v.port || 443);
        const uuid = String(v.id || "");
        if (!server || !port || !uuid) return null;
        const net = String(v.net || "tcp");
        const tls = v.tls === "tls" || v.tls === true || Number(v.port) === 443;
        const sni = String(v.sni || v.host || "");
        const clashProxy: Record<string, unknown> = {
          name,
          type: "vmess",
          server,
          port,
          uuid,
          alterId: Number(v.aid || 0),
          cipher: String(v.scy || "auto"),
          udp: true,
          tls,
        };
        if (sni) clashProxy.servername = sni;
        if (net === "ws") {
          clashProxy.network = "ws";
          clashProxy["ws-opts"] = {
            path: String(v.path || "/"),
            headers: v.host ? { Host: String(v.host) } : undefined,
          };
        } else if (net === "grpc") {
          clashProxy.network = "grpc";
          clashProxy["grpc-opts"] = { "grpc-service-name": String(v.path || "") };
        }
        return {
          raw_name: name,
          protocol: "VMess",
          server,
          port,
          cipher_or_param: uuid,
          raw_config: { clash_proxy: clashProxy },
          region: detectRegion(name, server),
          line_tag: detectLineTag(name, "VMess"),
          multiplier: detectMultiplier(name),
          latency_ms: null,
        };
      } catch {
        return null;
      }
    }
  }

  if (/^ss:\/\//i.test(line)) {
    try {
      const hashIdx = line.indexOf("#");
      const rawHash = hashIdx !== -1 ? decodeURIComponent(line.slice(hashIdx + 1)) : "";
      const withoutHash = (hashIdx !== -1 ? line.slice(5, hashIdx) : line.slice(5)).trim();
      const [mainPart, queryPart] = withoutHash.split("?");

      let cipher = "aes-256-gcm";
      let password = "";
      let server = "";
      let port = 443;

      if (mainPart.includes("@")) {
        const atIdx = mainPart.lastIndexOf("@");
        const userPart = mainPart.slice(0, atIdx);
        const hostPort = mainPart.slice(atIdx + 1).replace(/\/$/, "");
        const decodedUser = userPart.includes(":")
          ? decodeURIComponent(userPart)
          : safeDecodeBase64(userPart) || userPart;
        const colonIdx = decodedUser.indexOf(":");
        if (colonIdx !== -1) {
          cipher = decodedUser.slice(0, colonIdx);
          password = decodedUser.slice(colonIdx + 1);
        } else {
          password = decodedUser;
        }
        const hpUrl = new URL(`http://${hostPort}`);
        server = hpUrl.hostname;
        port = Number(hpUrl.port || 443);
      } else {
        const decodedAll = safeDecodeBase64(mainPart);
        if (!decodedAll || !decodedAll.includes("@")) return null;
        const atIdx = decodedAll.lastIndexOf("@");
        const userPart = decodedAll.slice(0, atIdx);
        const hostPort = decodedAll.slice(atIdx + 1);
        const colonIdx = userPart.indexOf(":");
        cipher = userPart.slice(0, colonIdx);
        password = userPart.slice(colonIdx + 1);
        const hpUrl = new URL(`http://${hostPort}`);
        server = hpUrl.hostname;
        port = Number(hpUrl.port || 443);
      }

      if (!server || !port) return null;
      const name = (rawHash || `${server}:${port}`).trim();
      const clashProxy: Record<string, unknown> = {
        name,
        type: "ss",
        server,
        port,
        cipher,
        password,
        udp: true,
      };
      if (queryPart) {
        const params = new URLSearchParams(queryPart);
        const plugin = params.get("plugin");
        if (plugin && plugin.includes("obfs")) {
          clashProxy.plugin = "obfs";
          const modeMatch = plugin.match(/obfs=(\w+)/);
          const hostMatch = plugin.match(/obfs-host=([^;]+)/);
          clashProxy["plugin-opts"] = {
            mode: modeMatch?.[1] || "tls",
            host: hostMatch?.[1] || server,
          };
        }
      }

      return {
        raw_name: name,
        protocol: cipher.startsWith("2022-") ? "SS-2022" : "Shadowsocks",
        server,
        port,
        cipher_or_param: `${cipher}:${password}`,
        raw_config: { clash_proxy: clashProxy },
        region: detectRegion(name, server),
        line_tag: detectLineTag(name, "Shadowsocks"),
        multiplier: detectMultiplier(name),
        latency_ms: null,
      };
    } catch {
      return null;
    }
  }

  if (/^(trojan|vless|hysteria2|hy2|tuic|anytls):\/\//i.test(line)) {
    try {
      const url = new URL(line);
      const scheme = url.protocol.replace(":", "").toLowerCase();
      const proto = normalizeProtocolLabel(scheme);
      const server = url.hostname;
      const port = Number(url.port || 443);
      if (!server) return null;
      const name = decodeURIComponent(url.hash.replace(/^#/, "") || `${server}:${port}`).trim();
      const q = url.searchParams;
      const sni = q.get("sni") || q.get("peer") || q.get("servername") || "";
      const insecure = q.get("allowInsecure") === "1" || q.get("insecure") === "1";

      const clashProxy: Record<string, unknown> = {
        name,
        type: scheme === "hy2" ? "hysteria2" : scheme,
        server,
        port,
        udp: true,
      };

      if (scheme === "trojan" || scheme === "anytls") {
        clashProxy.password = decodeURIComponent(url.username);
        if (sni) clashProxy.sni = sni;
        if (insecure) clashProxy["skip-cert-verify"] = true;
        if (q.get("type") === "ws") {
          clashProxy.network = "ws";
          clashProxy["ws-opts"] = {
            path: q.get("path") || "/",
            headers: q.get("host") ? { Host: q.get("host") } : undefined,
          };
        }
      } else if (scheme === "vless") {
        clashProxy.uuid = decodeURIComponent(url.username);
        const security = (q.get("security") || "").toLowerCase();
        clashProxy.tls = security === "tls" || security === "reality";
        if (sni) clashProxy.servername = sni;
        if (insecure) clashProxy["skip-cert-verify"] = true;
        if (q.get("flow")) clashProxy.flow = q.get("flow");
        if (q.get("fp")) clashProxy["client-fingerprint"] = q.get("fp");
        const enc = (q.get("encryption") || "").trim();
        if (enc && enc.toLowerCase() !== "none") {
          clashProxy.encryption = enc;
        }
        const alpnParam = (q.get("alpn") || "").trim();
        if (alpnParam) {
          const alpnList = alpnParam
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean);
          if (alpnList.length > 0) clashProxy.alpn = alpnList;
        }
        if (security === "reality") {
          const pbk = (q.get("pbk") || "").trim();
          const sid = (q.get("sid") || "").trim();
          clashProxy["reality-opts"] = {
            "public-key": pbk,
            ...(sid ? { "short-id": sid } : {}),
          };
        }
        const netType = (q.get("type") || "").toLowerCase();
        const hostParam = (q.get("host") || "").trim();
        if (netType === "ws") {
          clashProxy.network = "ws";
          clashProxy["ws-opts"] = {
            path: q.get("path") || "/",
            ...(hostParam ? { headers: { Host: hostParam } } : {}),
          };
        } else if (netType === "httpupgrade") {
          clashProxy.network = "httpupgrade";
          clashProxy["ws-opts"] = {
            path: q.get("path") || "/",
            "v2ray-http-upgrade": true,
            ...(hostParam ? { headers: { Host: hostParam } } : {}),
          };
        } else if (netType === "grpc") {
          clashProxy.network = "grpc";
          const svc = q.get("serviceName") || q.get("service-name") || "";
          const authority = (q.get("authority") || "").trim();
          const grpcMode = (q.get("mode") || "").trim();
          clashProxy["grpc-opts"] = {
            "grpc-service-name": svc,
            ...(authority ? { "grpc-authority": authority } : {}),
            ...(grpcMode ? { "grpc-mode": grpcMode } : {}),
          };
        } else if (netType === "xhttp" || netType === "splithttp") {
          clashProxy.network = "xhttp";
          const xhttpMode = (q.get("mode") || "").trim();
          clashProxy["xhttp-opts"] = {
            path: q.get("path") || "/",
            ...(hostParam ? { host: hostParam } : {}),
            ...(xhttpMode ? { mode: xhttpMode } : {}),
          };
        }
      } else if (scheme === "hysteria2" || scheme === "hy2") {
        clashProxy.password = decodeURIComponent(url.username || q.get("auth") || "");
        if (sni) clashProxy.sni = sni;
        if (insecure) clashProxy["skip-cert-verify"] = true;
        if (q.get("obfs")) {
          clashProxy.obfs = q.get("obfs");
          if (q.get("obfs-password")) clashProxy["obfs-password"] = q.get("obfs-password");
        }
      } else if (scheme === "tuic") {
        clashProxy.uuid = decodeURIComponent(url.username);
        clashProxy.password = decodeURIComponent(url.password);
        if (sni) clashProxy.sni = sni;
        if (insecure) clashProxy["skip-cert-verify"] = true;
        if (q.get("congestion_control")) clashProxy["congestion-controller"] = q.get("congestion_control");
      }

      return {
        raw_name: name,
        protocol: proto,
        server,
        port,
        cipher_or_param: decodeURIComponent(url.username),
        raw_config: { clash_proxy: clashProxy },
        region: detectRegion(name, server),
        line_tag: detectLineTag(name, proto),
        multiplier: detectMultiplier(name),
        latency_ms: null,
      };
    } catch {
      return null;
    }
  }

  return null;
}

/**
 * Resolves parsed group member names into `fallback_groups` (sub-policy names) + `filter_regex` (node match rule).
 */
function resolveImportedGroupMembers(params: {
  memberTokens: string[];
  explicitRegex: string;
  includeAll: boolean;
  allGroupNames: Set<string>;
  rawNodeNames: Set<string>;
}): { fallback_groups: string[]; filter_regex: string } {
  const { memberTokens, explicitRegex, includeAll, allGroupNames, rawNodeNames } = params;
  const fallback_groups: string[] = [];
  const referencedRawNodes: string[] = [];

  for (const token of memberTokens) {
    const clean = token.trim().replace(/^["']|["']$/g, "").trim();
    if (!clean) continue;
    const upper = clean.toUpperCase();
    if (BUILTIN_POLICIES.has(upper)) {
      const normBuiltin = upper === "REJECT-TINYGIF" ? "REJECT" : upper;
      if (!fallback_groups.includes(normBuiltin)) fallback_groups.push(normBuiltin);
    } else if (allGroupNames.has(clean)) {
      if (!fallback_groups.includes(clean)) fallback_groups.push(clean);
    } else {
      referencedRawNodes.push(clean);
    }
  }

  const cleanedExplicit = explicitRegex.trim().replace(/^\(\?i\)/i, "");
  if (cleanedExplicit) {
    return { fallback_groups, filter_regex: cleanedExplicit };
  }
  if (includeAll) {
    return { fallback_groups, filter_regex: ".*" };
  }
  if (referencedRawNodes.length > 0) {
    const localHits = referencedRawNodes.filter((n) => rawNodeNames.has(n)).length;
    if (
      rawNodeNames.size >= 15 &&
      localHits >= referencedRawNodes.length * 0.9 &&
      referencedRawNodes.length >= rawNodeNames.size * 0.9
    ) {
      return { fallback_groups, filter_regex: ".*" };
    }
    // Otherwise build an exact alternation regex matching those specific raw node names!
    const escaped = referencedRawNodes.slice(0, 120).map(escapeRegexLiteral);
    return { fallback_groups, filter_regex: `^(${escaped.join("|")})$` };
  }
  // Pure sub-group selector (e.g. ChatGPT -> [US, JP, SG])
  return {
    fallback_groups,
    filter_regex: fallback_groups.length > 0 ? "" : ".*",
  };
}

export function parseFullConfigBundle(rawText: string): ParsedFullBundle {
  const text = maybeUnwrapSubscriptionBase64(rawText);
  const nodes: RawParsedNode[] = [];
  const policy_groups: Omit<PolicyGroup, "id" | "matched_count">[] = [];
  const rules: Omit<RoutingRule, "id">[] = [];

  if (!text.trim()) {
    return { nodes, policy_groups, rules, protocol_summary: "Empty" };
  }

  // 1. Try YAML (Clash / Stash / Mihomo)
  if (text.includes("proxies:") || text.trim().startsWith("- name:") || text.trim().startsWith("- {")) {
    try {
      const doc = parseYaml(text) as Record<string, unknown> | Array<Record<string, unknown>>;
      const proxyList = Array.isArray(doc)
        ? doc
        : Array.isArray(doc?.proxies)
          ? (doc.proxies as Array<Record<string, unknown>>)
          : [];

      for (const item of proxyList) {
        if (!item || typeof item !== "object") continue;
        const name = String(item.name || "").trim();
        const server = String(item.server || "").trim();
        const port = Number(item.port || 0);
        const typeRaw = String(item.type || "trojan");
        if (!name || !server || !port) continue;
        const cipherStr = String(item.cipher || "");
        const proto =
          typeRaw === "ss" && cipherStr.startsWith("2022-")
            ? "SS-2022"
            : normalizeProtocolLabel(typeRaw);
        nodes.push({
          raw_name: name,
          protocol: proto,
          server,
          port,
          cipher_or_param: String(item.password || item.uuid || item.psk || cipherStr || ""),
          raw_config: { clash_proxy: { ...item } },
          region: detectRegion(name, server),
          line_tag: detectLineTag(name, proto),
          multiplier: detectMultiplier(name),
          latency_ms: null,
        });
      }

      if (!Array.isArray(doc) && doc && typeof doc === "object") {
        const rawGroups = Array.isArray(doc["proxy-groups"])
          ? (doc["proxy-groups"] as Array<Record<string, unknown>>)
          : [];
        const allGroupNames = new Set(
          rawGroups.map((g) => String(g?.name || "").trim()).filter(Boolean)
        );
        const rawNodeNames = new Set(nodes.map((n) => n.raw_name));

        rawGroups.forEach((g, idx) => {
          const gName = String(g.name || "").trim();
          const gType = String(g.type || "select").toLowerCase();
          if (!gName) return;
          const validType = (["url-test", "fallback", "select", "smart"].includes(gType)
            ? gType
            : "select") as PolicyGroup["type"];
          const memberTokens = Array.isArray(g.proxies) ? g.proxies.map((x) => String(x)) : [];
          const explicitRegex = String(g.filter || "");
          const includeAll = Boolean(g["include-all"] || g["include-all-proxies"]);

          const resolved = resolveImportedGroupMembers({
            memberTokens,
            explicitRegex,
            includeAll,
            allGroupNames,
            rawNodeNames,
          });

          policy_groups.push({
            name: gName,
            type: validType,
            filter_regex: resolved.filter_regex,
            interval_sec: Number(g.interval || 300),
            tolerance_ms: Number(g.tolerance || 30),
            fallback_groups: resolved.fallback_groups,
            sort_order: idx + 1,
          });
        });

        const rawProviders =
          doc["rule-providers"] && typeof doc["rule-providers"] === "object"
            ? (doc["rule-providers"] as Record<string, Record<string, unknown>>)
            : {};

        const rawRules = Array.isArray(doc.rules) ? (doc.rules as string[]) : [];
        rawRules.slice(0, 500).forEach((rLine, idx) => {
          const parts = String(rLine).split(",").map((s) => s.trim());
          if (parts.length < 2) return;
          const rTypeRaw = parts[0].toUpperCase();
          if (rTypeRaw === "MATCH" || rTypeRaw === "FINAL") {
            rules.push({
              kind: "ruleset",
              rule_type: "FINAL",
              title: "全局兜底路由策略",
              payload: "dns-failed",
              target_policy: parts[1],
              rule_count: 1,
              no_resolve: false,
              sync_meta: "Imported YAML",
              enabled: true,
              priority: 9999,
            });
          } else if (rTypeRaw === "RULE-SET" && parts.length >= 3) {
            const provName = parts[1];
            const provUrl = String(rawProviders[provName]?.url || provName);
            rules.push({
              kind: "ruleset",
              rule_type: "RULE-SET",
              title: `Rule-Set · ${provName}`,
              payload: provUrl,
              target_policy: parts[2],
              rule_count: 1,
              no_resolve: parts.includes("no-resolve"),
              sync_meta: "Remote Provider",
              enabled: true,
              priority: idx + 1,
            });
          } else if (parts.length >= 3) {
            rules.push({
              kind: rTypeRaw === "GEOIP" ? "ruleset" : "override",
              rule_type: rTypeRaw as RoutingRule["rule_type"],
              title: `${rTypeRaw} · ${parts[1]}`,
              payload: parts[1],
              target_policy: parts[2],
              rule_count: 1,
              no_resolve: parts.includes("no-resolve"),
              sync_meta: "Imported YAML",
              enabled: true,
              priority: rTypeRaw === "GEOIP" ? 9000 + idx : idx + 1,
            });
          }
        });
      }

      if (nodes.length > 0 || policy_groups.length > 0) {
        const protos = Array.from(new Set(nodes.map((n) => n.protocol))).slice(0, 3);
        return {
          nodes,
          policy_groups,
          rules,
          protocol_summary: `${protos.join(" / ") || "Config"} · Clash/Stash YAML`,
        };
      }
    } catch {
      // Fall through to Surge / URI parser
    }
  }

  // 2. Surge .conf Sections + Standalone Surge / URI Lines
  let currentSection = "proxy";
  const lines = text.split(/\r?\n/);
  const pendingSurgeGroupLines: string[] = [];

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith("//") || line.startsWith(";")) continue;

    if (line.startsWith("[") && line.endsWith("]")) {
      currentSection = line.slice(1, -1).trim().toLowerCase();
      continue;
    }

    if (/^[a-z0-9+.-]+:\/\//i.test(line)) {
      const uriNode = parseUriLine(line);
      if (uriNode) nodes.push(uriNode);
      continue;
    }

    if (currentSection === "proxy group" && line.includes("=")) {
      pendingSurgeGroupLines.push(line);
      continue;
    }

    if (currentSection === "rule" && line.includes(",")) {
      const parts = line.split(",").map((p) => p.trim().replace(/^["']|["']$/g, "").trim());
      const rType = parts[0].toUpperCase();
      if (rType === "FINAL" && parts.length >= 2) {
        rules.push({
          kind: "ruleset",
          rule_type: "FINAL",
          title: "全局兜底路由策略",
          payload: parts[2] || "dns-failed",
          target_policy: parts[1],
          rule_count: 1,
          no_resolve: false,
          sync_meta: "Imported Surge",
          enabled: true,
          priority: 9999,
        });
      } else if (rType === "RULE-SET" && parts.length >= 3) {
        const shortName = parts[1].split("/").pop() || parts[1];
        rules.push({
          kind: "ruleset",
          rule_type: "RULE-SET",
          title: `Rule-Set · ${shortName}`,
          payload: parts[1],
          target_policy: parts[2],
          rule_count: 1,
          no_resolve: parts.includes("no-resolve"),
          sync_meta: "Remote Rule-Set",
          enabled: true,
          priority: rules.length + 1,
        });
      } else if (parts.length >= 3 && rType !== "AND" && rType !== "OR" && rType !== "NOT") {
        rules.push({
          kind: rType === "GEOIP" ? "ruleset" : "override",
          rule_type: rType as RoutingRule["rule_type"],
          title: `${rType} · ${parts[1]}`,
          payload: parts[1],
          target_policy: parts[2],
          rule_count: 1,
          no_resolve: parts.includes("no-resolve"),
          sync_meta: "Imported Surge",
          enabled: true,
          priority: rType === "GEOIP" ? 9000 + rules.length : rules.length + 1,
        });
      }
      continue;
    }

    if ((currentSection === "proxy" || !text.includes("[General]")) && line.includes("=") && line.includes(",")) {
      const eqIdx = line.indexOf("=");
      const name = line.slice(0, eqIdx).trim();
      const rhs = line.slice(eqIdx + 1).trim();
      const parts = rhs.split(",").map((p) => p.trim());
      const protoRaw = (parts[0] || "").toLowerCase();
      if (!name || ["direct", "reject", "reject-tinygif", "reject-drop"].includes(protoRaw)) {
        continue;
      }
      if (parts.length >= 3) {
        const server = parts[1];
        const port = Number(parts[2]);
        if (!server || Number.isNaN(port)) continue;
        const kvMap: Record<string, string> = {};
        for (const p of parts.slice(3)) {
          const i = p.indexOf("=");
          if (i !== -1) {
            kvMap[p.slice(0, i).trim().toLowerCase()] = p.slice(i + 1).trim();
          }
        }
        const proto =
          protoRaw === "ss" && (kvMap["encrypt-method"] || "").startsWith("2022-")
            ? "SS-2022"
            : normalizeProtocolLabel(protoRaw);

        nodes.push({
          raw_name: name,
          protocol: proto,
          server,
          port,
          cipher_or_param: kvMap.password || kvMap.psk || kvMap.username || "",
          raw_config: { surge_rhs: rhs },
          region: detectRegion(name, server),
          line_tag: detectLineTag(name, proto),
          multiplier: detectMultiplier(name),
          latency_ms: null,
        });
      }
    }
  }

  // Resolve Surge [Proxy Group] lines now that all group names and node names are known!
  if (pendingSurgeGroupLines.length > 0) {
    const allGroupNames = new Set(
      pendingSurgeGroupLines
        .map((l) => l.slice(0, l.indexOf("=")).trim().replace(/^["']|["']$/g, ""))
        .filter(Boolean)
    );
    const rawNodeNames = new Set(nodes.map((n) => n.raw_name));

    pendingSurgeGroupLines.forEach((line, idx) => {
      const eqIdx = line.indexOf("=");
      const gName = line.slice(0, eqIdx).trim().replace(/^["']|["']$/g, "");
      const parts = line
        .slice(eqIdx + 1)
        .split(",")
        .map((p) => p.trim())
        .filter(Boolean);
      const gTypeRaw = (parts[0] || "select").toLowerCase();
      const kvOptions: Record<string, string> = {};
      const memberTokens: string[] = [];

      for (const token of parts.slice(1)) {
        const kvIdx = token.indexOf("=");
        if (kvIdx !== -1) {
          const k = token.slice(0, kvIdx).trim().toLowerCase();
          const v = token.slice(kvIdx + 1).trim().replace(/^"|"$/g, "");
          kvOptions[k] = v;
        } else {
          memberTokens.push(token);
        }
      }

      if (kvOptions["include-other-group"]) {
        for (const extra of kvOptions["include-other-group"].split(",")) {
          if (extra.trim()) memberTokens.push(extra.trim());
        }
      }

      const explicitRegex = kvOptions["policy-regex-filter"] || "";
      const includeAll =
        kvOptions["include-all-proxies"] === "1" || kvOptions["include-all-proxies"] === "true";

      const resolved = resolveImportedGroupMembers({
        memberTokens,
        explicitRegex,
        includeAll,
        allGroupNames,
        rawNodeNames,
      });

      policy_groups.push({
        name: gName,
        type: (["url-test", "fallback", "select", "smart"].includes(gTypeRaw)
          ? gTypeRaw
          : "select") as PolicyGroup["type"],
        filter_regex: resolved.filter_regex,
        interval_sec: kvOptions.interval ? Number(kvOptions.interval) || 300 : 300,
        tolerance_ms: kvOptions.tolerance ? Number(kvOptions.tolerance) || 20 : 20,
        fallback_groups: resolved.fallback_groups,
        sort_order: idx + 1,
      });
    });
  }

  const protos = Array.from(new Set(nodes.map((n) => n.protocol))).slice(0, 3);
  return {
    nodes,
    policy_groups,
    rules,
    protocol_summary: protos.length > 0 ? `${protos.join(" / ")}${pendingSurgeGroupLines.length > 0 ? " · Surge .conf" : ""}` : "Mixed",
  };
}

export function parseSubscriptionContent(rawText: string): RawParsedNode[] {
  return parseFullConfigBundle(rawText).nodes;
}
