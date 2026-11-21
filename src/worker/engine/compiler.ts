import { stringify as stringifyYaml } from "yaml";
import { matchNodesForGroup } from "../../shared/groupMatcher";
import { deriveRuleSetSignature } from "../../shared/hmac";
import type { PolicyGroup, ProxyNode, RoutingRule, TowerSettings } from "../../shared/types";

const BUILTIN_TARGETS = new Set(["DIRECT", "REJECT", "REJECT-DROP", "REJECT-TINYGIF", "REJECT-NO-DROP"]);
const SURGE_BUILTIN_RULESETS = new Set(["SYSTEM", "LAN"]);

function normalizeTargetPolicy(rawTarget: string): string {
  return rawTarget.replace(/^["']|["']$/g, "").trim();
}

function ruleEvaluationTier(r: RoutingRule): number {
  if (r.rule_type === "FINAL") return 3;
  if (r.rule_type === "GEOIP") return 2;
  if ((r.rule_type === "IP-CIDR" || r.rule_type === "IP-CIDR6") && !r.no_resolve) return 1;
  return 0;
}

function compareRulesCanonical(a: RoutingRule, b: RoutingRule): number {
  const tierDiff = ruleEvaluationTier(a) - ruleEvaluationTier(b);
  if (tierDiff !== 0) return tierDiff;
  return a.priority - b.priority;
}

function buildRuleSetUrl(origin: string, subToken: string, payload: string): string {
  if (/^https?:\/\//i.test(payload)) {
    return payload;
  }
  const cleanName = payload.replace(/^provider\//, "").trim();
  const sig = deriveRuleSetSignature(subToken, cleanName);
  return `${origin}/r/${encodeURIComponent(cleanName)}?sig=${sig}`;
}

function formatSurgeParamValue(val: string): string {
  if (/[,"\s]/.test(val)) {
    return `"${val.replace(/"/g, '\\"')}"`;
  }
  return val;
}

function formatSurgeWsHeaders(headers: Record<string, unknown> | undefined): string | null {
  if (!headers || typeof headers !== "object") return null;
  const pairs: string[] = [];
  for (const [rawKey, rawVal] of Object.entries(headers)) {
    if (rawVal === undefined || rawVal === null) continue;
    const val = String(rawVal).trim();
    if (!val) continue;
    const key = rawKey.trim().toLowerCase() === "host" ? "Host" : rawKey.trim();
    if (!key) continue;
    pairs.push(`${key}:${val}`);
  }
  if (pairs.length === 0) return null;
  return formatSurgeParamValue(pairs.join("|"));
}

function splitSurgeCsv(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"' && line[i - 1] !== "\\") {
      inQuotes = !inQuotes;
      cur += ch;
    } else if (ch === "," && !inQuotes) {
      out.push(cur.trim());
      cur = "";
    } else {
      cur += ch;
    }
  }
  if (cur.trim() || out.length > 0) {
    out.push(cur.trim());
  }
  return out;
}

function stripOuterQuotes(val: string | undefined): string {
  if (!val) return "";
  const trimmed = val.trim();
  if (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2) {
    return trimmed.slice(1, -1).replace(/\\"/g, '"');
  }
  return trimmed;
}

export function detectSurge6FromUa(ua: string): boolean {
  if (!/Surge/i.test(ua)) return false;

  const coreMatch = ua.match(/SurgeCore\/(\d+)/i);
  if (coreMatch && Number(coreMatch[1]) >= 6011000) {
    return true;
  }

  const macSemver = ua.match(/Surge(?:\s+|%20)Mac\/(\d+)\.(\d+)/i);
  if (macSemver) {
    const major = Number(macSemver[1]);
    const minor = Number(macSemver[2]);
    return major > 6 || (major === 6 && minor >= 11);
  }

  const semver = ua.match(/Surge(?:(?:\s+|%20)iOS)?\/(\d+)\.(\d+)/i);
  if (semver) {
    return Number(semver[1]) >= 6;
  }

  const buildMatch = ua.match(/Surge(?:(?:\s+|%20)Mac)?\/(\d+)(?![\d.])/i);
  if (buildMatch) {
    return Number(buildMatch[1]) >= 12800;
  }

  return false;
}

export function clashProxyToSurgeRhs(n: ProxyNode, enableVless = false): string | null {
  const cp = n.raw_config?.clash_proxy;
  const p = String(cp?.type || n.protocol).toLowerCase();
  const rhsProto = n.raw_config?.surge_rhs?.split(",")[0]?.trim().toLowerCase() || "";

  if ((p === "vless" || rhsProto === "vless") && !enableVless) {
    return null;
  }

  if (n.raw_config?.surge_rhs) {
    return n.raw_config.surge_rhs;
  }

  if (p === "ssr") {
    return null;
  }

  if (p === "vless") {
    const uuid = String(cp?.uuid || n.cipher_or_param || "").trim();
    if (!uuid) return null;

    const net = String(cp?.network || "").trim().toLowerCase();
    if (net && !["tcp", "raw", "ws", "httpupgrade", "grpc", "xhttp", "splithttp"].includes(net)) {
      return null;
    }

    const realityOpts = cp?.["reality-opts"] as
      | { "public-key"?: unknown; "short-id"?: unknown }
      | undefined;
    const realityPublicKey =
      realityOpts?.["public-key"] != null ? String(realityOpts["public-key"]).trim() : "";
    const realityShortId =
      realityOpts?.["short-id"] != null ? String(realityOpts["short-id"]).trim() : "";
    const sni = String(cp?.servername || cp?.sni || "").trim();
    const encryption = String(cp?.encryption || "").trim();

    const hasReality = Boolean(realityPublicKey);
    const hasEncryption = Boolean(encryption && encryption.toLowerCase() !== "none");
    const hasTls = !hasReality && (cp?.tls === true || (cp?.tls !== false && Boolean(sni)));

    if (hasReality && (net === "ws" || net === "httpupgrade")) {
      return null;
    }
    if (net === "grpc" && !hasReality && !hasTls) {
      return null;
    }

    const parts = ["vless", n.server, String(n.port), `username=${uuid}`];

    const rawFlow = String(cp?.flow || "").trim();
    if (rawFlow && rawFlow.toLowerCase() !== "none") {
      const isVision = /^xtls-rprx-vision/i.test(rawFlow);
      const isStreamNet = net === "ws" || net === "httpupgrade" || net === "xhttp" || net === "splithttp";
      const visionSupported =
        !isVision ||
        (net !== "grpc" && (!isStreamNet || hasEncryption) && (hasReality || hasTls || hasEncryption));
      if (visionSupported) {
        parts.push(`flow=${rawFlow}`);
      }
    }

    if (hasEncryption) {
      parts.push(`encryption=${formatSurgeParamValue(encryption)}`);
    }

    if (hasReality) {
      if (sni) parts.push(`sni=${sni}`);
      parts.push(`reality-public-key=${realityPublicKey}`);
      if (realityShortId) {
        parts.push(`reality-short-id=${realityShortId}`);
      }
    } else if (hasTls) {
      parts.push("tls=true");
      if (sni) parts.push(`sni=${sni}`);
      if (cp?.alpn) {
        const alpnList = Array.isArray(cp.alpn)
          ? cp.alpn.map((x) => String(x).trim()).filter(Boolean)
          : String(cp.alpn)
              .split(",")
              .map((s) => s.trim())
              .filter(Boolean);
        if (alpnList.length > 0) {
          parts.push(`alpn=${formatSurgeParamValue(alpnList.join(","))}`);
        }
      }
    }

    const wsOpts = cp?.["ws-opts"] as
      | { path?: unknown; headers?: Record<string, unknown>; "v2ray-http-upgrade"?: unknown }
      | undefined;
    const httpupgradeOpts = cp?.["httpupgrade-opts"] as
      | { path?: unknown; host?: unknown; headers?: Record<string, unknown> }
      | undefined;
    const grpcOpts = cp?.["grpc-opts"] as
      | {
          "grpc-service-name"?: unknown;
          "grpc-authority"?: unknown;
          authority?: unknown;
          "grpc-mode"?: unknown;
          mode?: unknown;
        }
      | undefined;
    const xhttpOpts = (cp?.["xhttp-opts"] || cp?.["splithttp-opts"]) as
      | { path?: unknown; host?: unknown; mode?: unknown }
      | undefined;

    if (net === "ws") {
      parts.push("ws=true");
      if (wsOpts?.["v2ray-http-upgrade"]) parts.push("ws-http-upgrade=true");
      if (wsOpts?.path) parts.push(`ws-path=${formatSurgeParamValue(String(wsOpts.path))}`);
      const wsHeaders = formatSurgeWsHeaders(wsOpts?.headers);
      if (wsHeaders) parts.push(`ws-headers=${wsHeaders}`);
    } else if (net === "httpupgrade") {
      parts.push("ws=true", "ws-http-upgrade=true");
      const path = httpupgradeOpts?.path ?? wsOpts?.path;
      if (path) parts.push(`ws-path=${formatSurgeParamValue(String(path))}`);
      const rawHeaders =
        httpupgradeOpts?.headers ??
        wsOpts?.headers ??
        (httpupgradeOpts?.host ? { Host: httpupgradeOpts.host } : undefined);
      const wsHeaders = formatSurgeWsHeaders(rawHeaders);
      if (wsHeaders) parts.push(`ws-headers=${wsHeaders}`);
    } else if (net === "grpc") {
      parts.push("grpc=true");
      if (grpcOpts?.["grpc-service-name"]) {
        parts.push(`grpc-service-name=${formatSurgeParamValue(String(grpcOpts["grpc-service-name"]))}`);
      }
      const authority = grpcOpts?.["grpc-authority"] ?? grpcOpts?.authority;
      if (authority) {
        parts.push(`grpc-authority=${formatSurgeParamValue(String(authority))}`);
      }
      const grpcMode = String(grpcOpts?.["grpc-mode"] ?? grpcOpts?.mode ?? "").trim().toLowerCase();
      if (grpcMode === "multi") {
        parts.push("grpc-mode=multi");
      }
    } else if (net === "xhttp" || net === "splithttp") {
      parts.push("xhttp=true");
      if (xhttpOpts?.path) parts.push(`xhttp-path=${formatSurgeParamValue(String(xhttpOpts.path))}`);
      if (xhttpOpts?.host) parts.push(`xhttp-host=${formatSurgeParamValue(String(xhttpOpts.host))}`);
      if (xhttpOpts?.mode) parts.push(`xhttp-mode=${formatSurgeParamValue(String(xhttpOpts.mode))}`);
    }

    if (cp?.["skip-cert-verify"] && !hasReality) {
      parts.push("skip-cert-verify=true");
    }
    return parts.join(", ");
  }

  if (p === "ss" || p.includes("shadowsocks") || p === "ss-2022") {
    const cipher = String(cp?.cipher || "aes-256-gcm");
    const password = String(cp?.password || n.cipher_or_param || "");
    const parts = [
      `ss`,
      n.server,
      String(n.port),
      `encrypt-method=${cipher}`,
      `password=${password}`,
      `udp-relay=${cp?.udp !== false}`,
    ];
    const pluginOpts = cp?.["plugin-opts"] as Record<string, unknown> | undefined;
    if (cp?.plugin === "obfs" && pluginOpts) {
      parts.push(`obfs=${pluginOpts.mode || "tls"}`);
      if (pluginOpts.host) parts.push(`obfs-host=${pluginOpts.host}`);
    }
    return parts.join(", ");
  }

  if (p === "trojan" || p === "anytls") {
    const password = String(cp?.password || n.cipher_or_param || "");
    const sni = String(cp?.sni || cp?.servername || n.server);
    const skipVerify = Boolean(cp?.["skip-cert-verify"]);
    const parts = [
      p === "anytls" ? "anytls" : "trojan",
      n.server,
      String(n.port),
      `password=${password}`,
      `sni=${sni}`,
      `skip-cert-verify=${skipVerify}`,
      `udp-relay=${cp?.udp !== false}`,
    ];
    const wsOpts = cp?.["ws-opts"] as { path?: string; headers?: { Host?: string } } | undefined;
    if (cp?.network === "ws") {
      parts.push("ws=true");
      if (wsOpts?.path) parts.push(`ws-path=${wsOpts.path}`);
      if (wsOpts?.headers?.Host) parts.push(`ws-headers=Host:${wsOpts.headers.Host}`);
    }
    return parts.join(", ");
  }

  if (p === "vmess") {
    const uuid = String(cp?.uuid || n.cipher_or_param || "");
    const tls = Boolean(cp?.tls);
    const sni = String(cp?.servername || cp?.sni || "");
    const parts = [
      "vmess",
      n.server,
      String(n.port),
      `username=${uuid}`,
      "vmess-aead=true",
      `tls=${tls}`,
    ];
    if (sni) parts.push(`sni=${sni}`);
    if (cp?.["skip-cert-verify"]) parts.push("skip-cert-verify=true");
    const wsOpts = cp?.["ws-opts"] as { path?: string; headers?: { Host?: string } } | undefined;
    if (cp?.network === "ws") {
      parts.push("ws=true");
      if (wsOpts?.path) parts.push(`ws-path=${wsOpts.path}`);
      if (wsOpts?.headers?.Host) parts.push(`ws-headers=Host:${wsOpts.headers.Host}`);
    }
    return parts.join(", ");
  }

  if (p === "snell") {
    const psk = String(cp?.psk || n.cipher_or_param || "");
    const ver = Number(cp?.version || 4);
    return `snell, ${n.server}, ${n.port}, psk=${psk}, version=${ver}, reuse=true`;
  }

  if (p.includes("hysteria")) {
    const password = String(cp?.password || n.cipher_or_param || "");
    const parts = [`hysteria2`, n.server, String(n.port), `password=${password}`];
    if (cp?.sni) parts.push(`sni=${cp.sni}`);
    if (cp?.["skip-cert-verify"]) parts.push("skip-cert-verify=true");
    return parts.join(", ");
  }

  if (p.includes("tuic")) {
    const uuid = String(cp?.uuid || "");
    const password = String(cp?.password || n.cipher_or_param || "");
    const parts = [`tuic-v5`, n.server, String(n.port), `password=${password}`];
    if (uuid) parts.push(`uuid=${uuid}`);
    if (cp?.sni) parts.push(`sni=${cp.sni}`);
    return parts.join(", ");
  }

  if (p.includes("socks")) {
    return `socks5, ${n.server}, ${n.port}`;
  }

  if (p.includes("http")) {
    return `https, ${n.server}, ${n.port}`;
  }

  return null;
}

export function nodeToClashObject(n: ProxyNode): Record<string, unknown> | null {
  if (n.raw_config?.clash_proxy) {
    const cp = n.raw_config.clash_proxy;
    if (String(cp.type || "").toLowerCase() === "snell" && Number(cp.version || 4) >= 4) {
      return null;
    }
    return {
      ...cp,
      name: n.normalized_name,
    };
  }

  const rhs = n.raw_config?.surge_rhs || "";
  const parts = splitSurgeCsv(rhs);
  const proto = (parts[0] || n.protocol).toLowerCase();
  const kv: Record<string, string> = {};
  for (const seg of parts.slice(3)) {
    const idx = seg.indexOf("=");
    if (idx !== -1) kv[seg.slice(0, idx).trim().toLowerCase()] = stripOuterQuotes(seg.slice(idx + 1));
  }

  if (proto === "ss") {
    return {
      name: n.normalized_name,
      type: "ss",
      server: n.server,
      port: n.port,
      cipher: kv["encrypt-method"] || "aes-256-gcm",
      password: kv.password || n.cipher_or_param,
      udp: kv["udp-relay"] !== "false",
    };
  }
  if (proto === "snell") {
    const ver = Number(kv.version || 4);
    if (ver >= 4) {
      return null;
    }
    return {
      name: n.normalized_name,
      type: "snell",
      server: n.server,
      port: n.port,
      psk: kv.psk || n.cipher_or_param,
      version: ver,
    };
  }
  if (proto === "vmess") {
    return {
      name: n.normalized_name,
      type: "vmess",
      server: n.server,
      port: n.port,
      uuid: kv.username || n.cipher_or_param,
      alterId: 0,
      cipher: "auto",
      tls: kv.tls === "true",
      ...(kv.sni ? { servername: kv.sni } : {}),
      ...(kv.ws === "true" ? { network: "ws", "ws-opts": { path: kv["ws-path"] || "/" } } : {}),
    };
  }
  if (proto === "hysteria2") {
    return {
      name: n.normalized_name,
      type: "hysteria2",
      server: n.server,
      port: n.port,
      password: kv.password || n.cipher_or_param,
      ...(kv.sni ? { sni: kv.sni } : {}),
    };
  }
  if (proto.startsWith("tuic")) {
    return {
      name: n.normalized_name,
      type: "tuic",
      server: n.server,
      port: n.port,
      uuid: kv.uuid || "",
      password: kv.password || n.cipher_or_param,
    };
  }
  if (proto === "vless") {
    const obj: Record<string, unknown> = {
      name: n.normalized_name,
      type: "vless",
      server: n.server,
      port: n.port,
      uuid: kv.username || n.cipher_or_param,
      udp: true,
      tls: kv.tls === "true" || Boolean(kv["reality-public-key"]) || (kv.tls !== "false" && Boolean(kv.sni)),
    };
    if (kv.flow) obj.flow = kv.flow;
    if (kv.sni) obj.servername = kv.sni;
    if (kv.encryption) obj.encryption = kv.encryption;
    if (kv.alpn) {
      const alpnList = kv.alpn
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      if (alpnList.length > 0) obj.alpn = alpnList;
    }
    if (kv["reality-public-key"]) {
      obj["reality-opts"] = {
        "public-key": kv["reality-public-key"],
        ...(kv["reality-short-id"] ? { "short-id": kv["reality-short-id"] } : {}),
      };
    }
    if (kv.ws === "true") {
      obj.network = kv["ws-http-upgrade"] === "true" ? "httpupgrade" : "ws";
      const wsOpts: Record<string, unknown> = { path: kv["ws-path"] || "/" };
      if (kv["ws-headers"]) {
        const headers: Record<string, string> = {};
        for (const pair of kv["ws-headers"].split("|")) {
          const colonIdx = pair.indexOf(":");
          if (colonIdx !== -1) {
            const hKey = pair.slice(0, colonIdx).trim();
            const hVal = pair.slice(colonIdx + 1).trim();
            if (hKey && hVal) {
              headers[hKey.toLowerCase() === "host" ? "Host" : hKey] = hVal;
            }
          }
        }
        if (Object.keys(headers).length > 0) {
          wsOpts.headers = headers;
        }
      }
      obj["ws-opts"] = wsOpts;
    } else if (kv.grpc === "true") {
      obj.network = "grpc";
      const grpcOpts: Record<string, unknown> = {
        "grpc-service-name": kv["grpc-service-name"] || "",
      };
      if (kv["grpc-authority"]) grpcOpts["grpc-authority"] = kv["grpc-authority"];
      if (kv["grpc-mode"]) grpcOpts["grpc-mode"] = kv["grpc-mode"];
      obj["grpc-opts"] = grpcOpts;
    } else if (kv.xhttp === "true") {
      obj.network = "xhttp";
      const xhttpOpts: Record<string, unknown> = {
        path: kv["xhttp-path"] || "/",
      };
      if (kv["xhttp-host"]) xhttpOpts.host = kv["xhttp-host"];
      if (kv["xhttp-mode"]) xhttpOpts.mode = kv["xhttp-mode"];
      obj["xhttp-opts"] = xhttpOpts;
    }
    if (kv["skip-cert-verify"] === "true") obj["skip-cert-verify"] = true;
    return obj;
  }
  if (proto === "anytls") {
    return {
      name: n.normalized_name,
      type: "anytls",
      server: n.server,
      port: n.port,
      password: kv.password || n.cipher_or_param,
      sni: kv.sni || n.server,
      "skip-cert-verify": kv["skip-cert-verify"] === "true",
      udp: kv["udp-relay"] !== "false",
    };
  }
  return {
    name: n.normalized_name,
    type: "trojan",
    server: n.server,
    port: n.port,
    password: kv.password || n.cipher_or_param,
    sni: kv.sni || n.server,
    "skip-cert-verify": kv["skip-cert-verify"] === "true",
    udp: true,
  };
}

export function compileSingleNodePreview(node: ProxyNode): {
  surge5: string | null;
  surge6: string | null;
  stash: Record<string, unknown> | null;
} {
  return {
    surge5: clashProxyToSurgeRhs(node, false),
    surge6: clashProxyToSurgeRhs(node, true),
    stash: nodeToClashObject(node),
  };
}

function resolveGroupMemberNames(
  g: PolicyGroup,
  allGroupNames: Set<string>,
  activeNodes: ProxyNode[],
  allowedNodeNames: Set<string>
): string[] {
  const members: string[] = [];
  for (const sub of g.fallback_groups) {
    const norm = sub === "REJECT" ? "REJECT-DROP" : sub;
    if ((allGroupNames.has(sub) || BUILTIN_TARGETS.has(norm)) && sub !== g.name) {
      if (!members.includes(norm)) members.push(norm);
    }
  }
  const matched = matchNodesForGroup(g, activeNodes);
  for (const n of matched) {
    if (allowedNodeNames.has(n.normalized_name) && !members.includes(n.normalized_name)) {
      members.push(n.normalized_name);
    }
  }
  return members.length > 0 ? members : ["DIRECT"];
}

export function compileSurgeProfile(params: {
  origin: string;
  settings: TowerSettings;
  nodes: ProxyNode[];
  groups: PolicyGroup[];
  rules: RoutingRule[];
  target?: "surge" | "surge6";
  enableVless?: boolean;
}): string {
  const { origin, settings, nodes, groups, rules, target = "surge" } = params;
  const effectiveEnableVless = params.enableVless ?? (target === "surge6");
  const managedUrl =
    target === "surge6"
      ? `${origin}/sub/${settings.sub_token}?target=surge6${effectiveEnableVless ? "" : "&vless=0"}`
      : `${origin}/sub/${settings.sub_token}?target=surge${effectiveEnableVless ? "&vless=1" : ""}`;
  const activeNodes = nodes.filter((n) => n.status === "active");

  const lines: string[] = [
    `#!MANAGED-CONFIG ${managedUrl} interval=43200 strict=false`,
    `# Generated by Tower · ${effectiveEnableVless ? "Surge 6 (VLESS)" : "Surge 5"} · Revision v${settings.revision}`,
    "",
    "[General]",
    "loglevel = notify",
    "ipv6 = true",
    "dns-server = 223.5.5.5, 119.29.29.29, system",
    "encrypted-dns-server = https://dns.alidns.com/dns-query",
    "skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local",
    "proxy-test-url = http://cp.cloudflare.com/generate_204",
    "internet-test-url = http://connectivitycheck.platform.hicloud.com/generate_204",
    "test-timeout = 3",
    "",
    "[Proxy]",
  ];

  const effectiveGroups: PolicyGroup[] =
    groups.length > 0
      ? groups
      : [
          {
            id: "pg_default",
            name: "Proxy",
            type: "select",
            filter_regex: ".*",
            interval_sec: 300,
            tolerance_ms: 30,
            fallback_groups: [],
            sort_order: 1,
          },
        ];

  const allGroupNames = new Set(effectiveGroups.map((g) => g.name));

  const emittedSurgeSet = new Set<string>();
  for (const n of activeNodes) {
    const rhs = clashProxyToSurgeRhs(n, effectiveEnableVless);
    if (rhs) {
      let safeName = n.normalized_name.trim();
      if (BUILTIN_TARGETS.has(safeName.toUpperCase()) || allGroupNames.has(safeName)) {
        safeName = `${safeName} (Node)`;
      }
      lines.push(`${safeName} = ${rhs}`);
      emittedSurgeSet.add(safeName);
    }
  }

  lines.push("", "[Proxy Group]");

  for (const g of effectiveGroups) {
    const members = resolveGroupMemberNames(g, allGroupNames, activeNodes, emittedSurgeSet);
    const mode = g.type === "smart" ? "smart" : g.type;
    if (mode === "select") {
      lines.push(`${g.name} = select, ${members.join(", ")}`);
    } else {
      lines.push(
        `${g.name} = ${mode}, ${members.join(", ")}, url=http://cp.cloudflare.com/generate_204, interval=${g.interval_sec}, tolerance=${g.tolerance_ms}`
      );
    }
  }

  lines.push("", "[Rule]");
  const defaultFallback =
    effectiveGroups.find((g) => g.type === "select")?.name || effectiveGroups[0]?.name || "DIRECT";

  const resolveValidRuleTarget = (rawTarget: string): string => {
    const cleaned = normalizeTargetPolicy(rawTarget);
    const upper = cleaned.toUpperCase();
    if (BUILTIN_TARGETS.has(upper)) return upper;
    if (allGroupNames.has(cleaned) || emittedSurgeSet.has(cleaned)) return cleaned;
    return defaultFallback;
  };

  const sortedRules = [...rules].filter((r) => r.enabled).sort(compareRulesCanonical);

  for (const r of sortedRules) {
    const target = resolveValidRuleTarget(r.target_policy);
    if (r.rule_type === "FINAL") {
      lines.push(`FINAL,${target},dns-failed`);
    } else if (r.rule_type === "RULE-SET") {
      const upperPayload = r.payload.trim().toUpperCase();
      if (SURGE_BUILTIN_RULESETS.has(upperPayload)) {
        lines.push(`RULE-SET,${upperPayload},${target}${r.no_resolve ? ",no-resolve" : ""}`);
      } else {
        const url = buildRuleSetUrl(origin, settings.sub_token, r.payload);
        lines.push(`RULE-SET,${url},${target}${r.no_resolve ? ",no-resolve" : ""}`);
      }
    } else if (r.rule_type === "GEOIP") {
      lines.push(`GEOIP,${r.payload},${target}${r.no_resolve ? ",no-resolve" : ""}`);
    } else {
      lines.push(`${r.rule_type},${r.payload},${target}${r.no_resolve ? ",no-resolve" : ""}`);
    }
  }

  if (!sortedRules.some((r) => r.rule_type === "FINAL")) {
    if (sortedRules.length === 0) {
      lines.push("GEOIP,CN,DIRECT");
    }
    lines.push(`FINAL,${defaultFallback},dns-failed`);
  }

  return lines.join("\n");
}

export function compileStashYaml(params: {
  origin: string;
  settings: TowerSettings;
  nodes: ProxyNode[];
  groups: PolicyGroup[];
  rules: RoutingRule[];
}): string {
  const { origin, settings, nodes, groups, rules } = params;
  const activeNodes = nodes.filter((n) => n.status === "active");

  const proxies = activeNodes
    .map((n) => nodeToClashObject(n))
    .filter((item): item is Record<string, unknown> => Boolean(item));
  const allowedClashSet = new Set(proxies.map((p) => String(p.name)));

  const effectiveGroups: PolicyGroup[] =
    groups.length > 0
      ? groups
      : [
          {
            id: "pg_default",
            name: "Proxy",
            type: "select",
            filter_regex: ".*",
            interval_sec: 300,
            tolerance_ms: 30,
            fallback_groups: [],
            sort_order: 1,
          },
        ];

  const allGroupNames = new Set(effectiveGroups.map((g) => g.name));

  const proxyGroups = effectiveGroups.map((g) => {
    const members = resolveGroupMemberNames(g, allGroupNames, activeNodes, allowedClashSet).map((m) =>
      m === "REJECT-DROP" ? "REJECT" : m
    );
    if (g.type === "select") {
      return {
        name: g.name,
        type: "select",
        proxies: members,
      };
    }
    return {
      name: g.name,
      type: g.type === "smart" ? "url-test" : g.type,
      url: "http://cp.cloudflare.com/generate_204",
      interval: g.interval_sec,
      tolerance: g.tolerance_ms,
      proxies: members,
    };
  });

  const ruleProviders: Record<string, unknown> = {};
  const yamlRules: string[] = [];

  const sortedRules = [...rules].filter((r) => r.enabled).sort(compareRulesCanonical);

  for (const r of sortedRules) {
    const cleanedTarget = normalizeTargetPolicy(r.target_policy);
    const target = cleanedTarget.toUpperCase().startsWith("REJECT") ? "REJECT" : cleanedTarget;
    if (r.rule_type === "FINAL") {
      yamlRules.push(`MATCH,${target}`);
    } else if (r.rule_type === "RULE-SET") {
      const upperPayload = r.payload.trim().toUpperCase();
      if (upperPayload === "LAN") {
        yamlRules.push(`GEOIP,LAN,${target},no-resolve`);
      } else if (upperPayload === "SYSTEM") {
        yamlRules.push(`DOMAIN-SUFFIX,local,${target}`);
      } else {
        const providerKey = r.payload
          .split("/")
          .pop()!
          .replace(/\.(list|yaml|txt)$/i, "")
          .replace(/[^a-zA-Z0-9_-]/g, "-");
        const url = buildRuleSetUrl(origin, settings.sub_token, r.payload);
        ruleProviders[providerKey] = {
          type: "http",
          behavior: r.no_resolve ? "ipcidr" : "classical",
          url,
          interval: 86400,
        };
        yamlRules.push(`RULE-SET,${providerKey},${target}${r.no_resolve ? ",no-resolve" : ""}`);
      }
    } else if (r.rule_type === "GEOIP") {
      yamlRules.push(`GEOIP,${r.payload},${target}${r.no_resolve ? ",no-resolve" : ""}`);
    } else {
      yamlRules.push(`${r.rule_type},${r.payload},${target}${r.no_resolve ? ",no-resolve" : ""}`);
    }
  }

  if (!sortedRules.some((r) => r.rule_type === "FINAL")) {
    const defaultFallback =
      effectiveGroups.find((g) => g.type === "select")?.name || effectiveGroups[0]?.name || "DIRECT";
    if (sortedRules.length === 0) {
      yamlRules.push("GEOIP,CN,DIRECT");
    }
    yamlRules.push(`MATCH,${defaultFallback}`);
  }

  return stringifyYaml({
    "mixed-port": 7890,
    "allow-lan": true,
    mode: "rule",
    "log-level": "info",
    dns: {
      enable: true,
      "enhanced-mode": "fake-ip",
      nameserver: ["223.5.5.5", "119.29.29.29"],
    },
    proxies,
    "proxy-groups": proxyGroups,
    ...(Object.keys(ruleProviders).length > 0 ? { "rule-providers": ruleProviders } : {}),
    rules: yamlRules,
  });
}
