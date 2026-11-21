import type { PolicyGroup, ProxyNode, RoutingRule } from "./types";

export function compileGroupRegex(pattern: string): RegExp | null {
  const trimmed = (pattern || "").trim();
  if (!trimmed) return null;
  try {
    const slashMatch = trimmed.match(/^\/(.+)\/([gimsuy]*)$/);
    const body = (slashMatch ? slashMatch[1] : trimmed).replace(/^\(\?i\)/i, "");
    const rawFlags = slashMatch ? slashMatch[2] : "i";
    const flags = rawFlags.includes("i") ? rawFlags : `${rawFlags}i`;
    return new RegExp(body, flags);
  } catch {
    return null;
  }
}

/**
 * Matches active nodes belonging directly to a PolicyGroup via its `filter_regex`.
 * If `filter_regex` is empty ("") — e.g. a pure sub-group selector like `ChatGPT -> [US, JP]` —
 * returns `[]` so pure selector groups don't erroneously pull in every raw node.
 */
export function matchNodesForGroup(group: Pick<PolicyGroup, "filter_regex">, nodes: ProxyNode[]): ProxyNode[] {
  const active = nodes.filter((n) => n.status === "active");
  const expr = (group.filter_regex || "").trim();
  if (!expr) return [];
  if (expr === ".*") return active;

  const re = compileGroupRegex(expr);
  if (!re) return [];

  return active.filter(
    (n) => re.test(n.normalized_name) || re.test(n.raw_name) || re.test(n.region) || re.test(n.line_tag)
  );
}

/**
 * Computes upstream & downstream topology links for a PolicyGroup:
 * - linkedRules: RoutingRules whose target_policy === group.name
 * - parentGroups: PolicyGroups whose fallback_groups include group.name
 * - matchedNodes: Active ProxyNodes matched by group.filter_regex
 */
export function getGroupTopology(
  group: PolicyGroup,
  allGroups: PolicyGroup[],
  allRules: RoutingRule[],
  allNodes: ProxyNode[]
) {
  const linkedRules = allRules.filter((r) => r.target_policy === group.name);
  const parentGroups = allGroups.filter(
    (g) => g.id !== group.id && g.fallback_groups.includes(group.name)
  );
  const matchedNodes = matchNodesForGroup(group, allNodes);

  return {
    linkedRules,
    parentGroups,
    matchedNodes,
  };
}

/**
 * Builds a clean region filter regex like `/^(HK|JP)\b/` from selected region codes.
 */
export function buildRegionRegex(regions: string[]): string {
  const clean = Array.from(new Set(regions.map((r) => r.trim().toUpperCase()).filter(Boolean)));
  if (clean.length === 0) return "";
  if (clean.length === 1) return `/^${clean[0]}\\b/`;
  return `/^(${clean.join("|")})\\b/`;
}

/**
 * Extracts selected region codes if the regex is a simple region regex like `/^HK\b/` or `/^(HK|JP)\b/`.
 */
export function parseSimpleRegionRegex(regexStr: string): string[] | null {
  const trimmed = (regexStr || "").trim();
  if (!trimmed) return [];
  const single = trimmed.match(/^\/?\^([A-Z]{2,6})\\b\/?i?$/);
  if (single) return [single[1].toUpperCase()];
  const multi = trimmed.match(/^\/?\^\(([A-Z|]+)\)\\b\/?i?$/);
  if (multi) return multi[1].split("|").filter(Boolean);
  return null;
}
