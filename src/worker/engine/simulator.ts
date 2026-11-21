import { matchNodesForGroup } from "../../shared/groupMatcher";
import type { PolicyGroup, ProxyNode, RoutingRule, SimulationResult } from "../../shared/types";

const BUILTIN_RULESET_SAMPLES: Record<string, string[]> = {
  "ai-suite": [
    "openai.com",
    "chatgpt.com",
    "anthropic.com",
    "claude.ai",
    "gemini.google.com",
    "generativelanguage.googleapis.com",
    "perplexity.ai",
    "cursor.sh",
    "cursor.com",
  ],
  streaming: [
    "netflix.com",
    "nflxvideo.net",
    "youtube.com",
    "googlevideo.com",
    "spotify.com",
    "disneyplus.com",
    "twitch.tv",
  ],
  "telegram-cidr": ["t.me", "telegram.org", "91.108.", "149.154."],
  "apple-cn": [
    "apple.com",
    "icloud.com",
    "mzstatic.com",
    "cdn-apple.com",
    "bilibili.com",
    "qq.com",
    "taobao.com",
    "jd.com",
    "zhihu.com",
  ],
  "reject-telemetry": [
    "doubleclick.net",
    "googlesyndication.com",
    "adservice.google.com",
    "app-measurement.com",
  ],
};

function extractHostOrTarget(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) return "openai.com";
  try {
    if (trimmed.includes("://")) {
      return new URL(trimmed).hostname.toLowerCase();
    }
  } catch {
    // ignore
  }
  return trimmed.split("/")[0].split(":")[0].toLowerCase();
}

function resolveBestNodeForPolicy(
  policyName: string,
  groups: PolicyGroup[],
  nodes: ProxyNode[],
  visited = new Set<string>()
): { nodeName: string; latency: number | null } {
  if (policyName === "DIRECT") return { nodeName: "DIRECT (本地直连)", latency: null };
  if (policyName.startsWith("REJECT")) return { nodeName: "REJECT-DROP (直接丢弃)", latency: null };
  if (visited.has(policyName)) return { nodeName: policyName, latency: null };
  visited.add(policyName);

  const group = groups.find((g) => g.name === policyName);
  if (!group) return { nodeName: policyName, latency: null };

  if (group.fallback_groups.length > 0) {
    const res = resolveBestNodeForPolicy(group.fallback_groups[0], groups, nodes, visited);
    return {
      nodeName: `${group.fallback_groups[0]} → ${res.nodeName}`,
      latency: res.latency,
    };
  }

  const matched = matchNodesForGroup(group, nodes);
  if (matched.length > 0) {
    matched.sort((a, b) => (a.latency_ms ?? 9999) - (b.latency_ms ?? 9999));
    return { nodeName: matched[0].normalized_name, latency: matched[0].latency_ms };
  }

  const active = nodes.filter((n) => n.status === "active");
  if (active.length > 0) {
    return { nodeName: active[0].normalized_name, latency: active[0].latency_ms };
  }
  return { nodeName: "DIRECT", latency: null };
}

export function simulateRoute(
  rawInput: string,
  rules: RoutingRule[],
  groups: PolicyGroup[],
  nodes: ProxyNode[]
): SimulationResult {
  const host = extractHostOrTarget(rawInput);
  const sorted = [...rules]
    .filter((r) => r.enabled)
    .sort((a, b) => {
      if (a.rule_type === "FINAL") return 1;
      if (b.rule_type === "FINAL") return -1;
      return a.priority - b.priority;
    });

  for (let i = 0; i < sorted.length; i++) {
    const r = sorted[i];
    const p = r.payload.toLowerCase().trim();

    if (r.rule_type === "DOMAIN" && host === p) {
      const resolved = resolveBestNodeForPolicy(r.target_policy, groups, nodes);
      return {
        target: rawInput,
        host,
        elapsed_ms: 0.3,
        matched_rule_title: r.title,
        matched_expression: `DOMAIN, ${r.payload}`,
        matched_kind: r.kind,
        target_policy: r.target_policy,
        resolved_node: resolved.nodeName,
        resolved_latency_ms: resolved.latency,
      };
    }

    if (r.rule_type === "DOMAIN-SUFFIX" && (host === p || host.endsWith(`.${p}`))) {
      const resolved = resolveBestNodeForPolicy(r.target_policy, groups, nodes);
      return {
        target: rawInput,
        host,
        elapsed_ms: 0.4,
        matched_rule_title: r.title,
        matched_expression: `DOMAIN-SUFFIX, ${r.payload}`,
        matched_kind: r.kind,
        target_policy: r.target_policy,
        resolved_node: resolved.nodeName,
        resolved_latency_ms: resolved.latency,
      };
    }

    if (r.rule_type === "DOMAIN-KEYWORD" && host.includes(p)) {
      const resolved = resolveBestNodeForPolicy(r.target_policy, groups, nodes);
      return {
        target: rawInput,
        host,
        elapsed_ms: 0.4,
        matched_rule_title: r.title,
        matched_expression: `DOMAIN-KEYWORD, ${r.payload}`,
        matched_kind: r.kind,
        target_policy: r.target_policy,
        resolved_node: resolved.nodeName,
        resolved_latency_ms: resolved.latency,
      };
    }

    if (r.rule_type === "PROCESS-NAME" && rawInput.toLowerCase().includes(p)) {
      const resolved = resolveBestNodeForPolicy(r.target_policy, groups, nodes);
      return {
        target: rawInput,
        host,
        elapsed_ms: 0.3,
        matched_rule_title: r.title,
        matched_expression: `PROCESS-NAME, ${r.payload}`,
        matched_kind: r.kind,
        target_policy: r.target_policy,
        resolved_node: resolved.nodeName,
        resolved_latency_ms: resolved.latency,
      };
    }

    if (r.rule_type === "RULE-SET" || r.rule_type === "GEOIP") {
      for (const [key, domains] of Object.entries(BUILTIN_RULESET_SAMPLES)) {
        if (p.includes(key) || (r.rule_type === "GEOIP" && key === "apple-cn")) {
          const hit = domains.find((d) => host === d || host.endsWith(`.${d}`) || host.startsWith(d));
          if (hit) {
            const resolved = resolveBestNodeForPolicy(r.target_policy, groups, nodes);
            return {
              target: rawInput,
              host,
              elapsed_ms: 0.5,
              matched_rule_title: r.title,
              matched_expression: `${r.rule_type}, ${r.payload}`,
              matched_kind: "ruleset",
              target_policy: r.target_policy,
              resolved_node: resolved.nodeName,
              resolved_latency_ms: resolved.latency,
            };
          }
        }
      }
      if (r.rule_type === "GEOIP" && p === "cn" && host.endsWith(".cn")) {
        const resolved = resolveBestNodeForPolicy(r.target_policy, groups, nodes);
        return {
          target: rawInput,
          host,
          elapsed_ms: 0.5,
          matched_rule_title: r.title,
          matched_expression: `GEOIP, CN`,
          matched_kind: "ruleset",
          target_policy: r.target_policy,
          resolved_node: resolved.nodeName,
          resolved_latency_ms: resolved.latency,
        };
      }
    }
  }

  const finalRule = sorted.find((r) => r.rule_type === "FINAL");
  const fallbackPolicy = finalRule?.target_policy || groups.find((g) => g.type === "select")?.name || "DIRECT";
  const resolved = resolveBestNodeForPolicy(fallbackPolicy, groups, nodes);

  return {
    target: rawInput,
    host,
    elapsed_ms: 0.6,
    matched_rule_title: finalRule?.title || "全局兜底路由策略",
    matched_expression: `FINAL, ${fallbackPolicy}`,
    matched_kind: "fallback",
    target_policy: fallbackPolicy,
    resolved_node: resolved.nodeName,
    resolved_latency_ms: resolved.latency,
  };
}
