import type { PipelineStats, ProxyNode, TowerSettings } from "../../shared/types";
import type { RawParsedNode } from "./parser";

export interface RawSourceBatch {
  sub_id: string;
  sub_name: string;
  nodes: RawParsedNode[];
}

function compileUserRegex(pattern: string): RegExp | null {
  const trimmed = pattern.trim();
  if (!trimmed) return null;
  try {
    const slashMatch = trimmed.match(/^\/(.+)\/([gimsuy]*)$/);
    if (slashMatch) {
      return new RegExp(slashMatch[1], slashMatch[2] || "i");
    }
    return new RegExp(trimmed, "i");
  } catch {
    return null;
  }
}

export function formatNormalizedName(
  template: string,
  vars: {
    REGION: string;
    LINE_TAG: string;
    PROTOCOL: string;
    SOURCE: string;
    INDEX: number;
  }
): string {
  return template
    .replace(/\{REGION\}/g, vars.REGION)
    .replace(/\{LINE_TAG\}/g, vars.LINE_TAG)
    .replace(/\{PROTOCOL\}/g, vars.PROTOCOL)
    .replace(/\{SOURCE\}/g, vars.SOURCE)
    .replace(/\{INDEX:02\}/g, String(vars.INDEX).padStart(2, "0"))
    .replace(/\{INDEX\}/g, String(vars.INDEX));
}

export function runIntegrationPipeline(
  batches: RawSourceBatch[],
  settings: TowerSettings,
  previousLatencies = new Map<string, number>()
): { nodes: ProxyNode[]; subValidCounts: Record<string, { raw: number; valid: number; regions: string[] }> } {
  const now = Date.now();
  const excludeRegex = compileUserRegex(settings.exclude_regex);
  const subValidCounts: Record<string, { raw: number; valid: number; regions: Set<string> }> = {};

  interface Candidate {
    id: string;
    sub_id: string;
    sub_name: string;
    raw: RawParsedNode;
    fingerprint: string;
    status: ProxyNode["status"];
    filter_reason: string;
    merged_count: number;
  }

  const candidates: Candidate[] = [];
  let seq = 1;

  for (const batch of batches) {
    subValidCounts[batch.sub_id] = { raw: batch.nodes.length, valid: 0, regions: new Set() };
    for (const raw of batch.nodes) {
      const id = `nd_${batch.sub_id}_${seq++}`;
      const fingerprint = `${raw.protocol.toLowerCase()}:${raw.server.toLowerCase()}:${raw.port}`;
      let status: ProxyNode["status"] = "active";
      let filter_reason = "";

      if (excludeRegex && excludeRegex.test(raw.raw_name)) {
        status = "filtered_regex";
        filter_reason = `命中黑名单正则 ${settings.exclude_regex}`;
      } else if (raw.multiplier > settings.max_multiplier) {
        status = "filtered_multiplier";
        filter_reason = `倍率 ${raw.multiplier}x > 上限 ${settings.max_multiplier.toFixed(1)}x`;
      }

      candidates.push({
        id,
        sub_id: batch.sub_id,
        sub_name: batch.sub_name,
        raw,
        fingerprint,
        status,
        filter_reason,
        merged_count: 0,
      });
    }
  }

  if (settings.dedup_enabled) {
    const seenByFp = new Map<string, Candidate>();
    for (const item of candidates) {
      if (item.status !== "active") continue;
      const existing = seenByFp.get(item.fingerprint);
      if (!existing) {
        seenByFp.set(item.fingerprint, item);
      } else if (item.raw.multiplier < existing.raw.multiplier) {
        existing.status = "filtered_dedup";
        existing.filter_reason = `同入口 ${item.raw.server}:${item.raw.port} 已保留更低倍率源`;
        item.merged_count = existing.merged_count + 1;
        seenByFp.set(item.fingerprint, item);
      } else {
        item.status = "filtered_dedup";
        item.filter_reason = `与「${existing.sub_name}」同入口合并去重`;
        existing.merged_count += 1;
      }
    }
  }

  const groupCounters = new Map<string, number>();
  const usedNames = new Set<string>();

  const output: ProxyNode[] = candidates.map((c) => {
    let normalized_name = c.raw.raw_name;
    if (c.status === "active") {
      const key = `${c.raw.region}:${c.raw.line_tag}`;
      const nextIdx = (groupCounters.get(key) || 0) + 1;
      groupCounters.set(key, nextIdx);
      let candidateName = formatNormalizedName(settings.rename_template, {
        REGION: c.raw.region,
        LINE_TAG: c.raw.line_tag,
        PROTOCOL: c.raw.protocol,
        SOURCE: c.sub_name.split("·")[0].trim(),
        INDEX: nextIdx,
      }).trim();
      if (!candidateName) candidateName = c.raw.raw_name;
      if (usedNames.has(candidateName)) {
        let suffix = 2;
        while (usedNames.has(`${candidateName} (${suffix})`)) suffix++;
        candidateName = `${candidateName} (${suffix})`;
      }
      usedNames.add(candidateName);
      normalized_name = candidateName;

      const stats = subValidCounts[c.sub_id];
      if (stats) {
        stats.valid += 1;
        if (c.raw.region !== "GLOBAL") stats.regions.add(c.raw.region);
      }
    }

    const preservedLatency = previousLatencies.get(c.fingerprint) ?? null;
    const latency_ms = c.status === "active" ? c.raw.latency_ms ?? preservedLatency : null;

    return {
      id: c.id,
      sub_id: c.sub_id,
      sub_name: c.sub_name,
      raw_name: c.raw.raw_name,
      normalized_name,
      region: c.raw.region,
      line_tag: c.raw.line_tag,
      protocol: c.raw.protocol,
      server: c.raw.server,
      port: c.raw.port,
      cipher_or_param: c.raw.cipher_or_param,
      raw_config: c.raw.raw_config,
      multiplier: c.raw.multiplier,
      latency_ms,
      fingerprint: c.fingerprint,
      merged_count: c.merged_count,
      status: c.status,
      filter_reason: c.filter_reason,
      updated_at: now,
    };
  });

  const regionOrder: Record<string, number> = {
    HK: 1,
    TW: 2,
    JP: 3,
    SG: 4,
    KR: 5,
    US: 6,
    DE: 7,
    UK: 8,
    GLOBAL: 50,
  };
  output.sort((a, b) => {
    const aAct = a.status === "active" ? 0 : 1;
    const bAct = b.status === "active" ? 0 : 1;
    if (aAct !== bAct) return aAct - bAct;
    const rDiff = (regionOrder[a.region] || 25) - (regionOrder[b.region] || 25);
    if (rDiff !== 0) return rDiff;
    return a.normalized_name.localeCompare(b.normalized_name);
  });

  const formattedSubCounts: Record<string, { raw: number; valid: number; regions: string[] }> = {};
  for (const [k, v] of Object.entries(subValidCounts)) {
    formattedSubCounts[k] = {
      raw: v.raw,
      valid: v.valid,
      regions: Array.from(v.regions).slice(0, 5),
    };
  }

  return { nodes: output, subValidCounts: formattedSubCounts };
}

export function computePipelineStats(nodes: ProxyNode[]): PipelineStats {
  let filtered_regex_or_rate = 0;
  let filtered_dedup = 0;
  let active_total = 0;
  let latencySum = 0;
  let probed_count = 0;
  const region_counts: Record<string, number> = {};

  for (const n of nodes) {
    if (n.status === "active") {
      active_total += 1;
      region_counts[n.region] = (region_counts[n.region] || 0) + 1;
      if (typeof n.latency_ms === "number" && n.latency_ms > 0) {
        latencySum += n.latency_ms;
        probed_count += 1;
      }
    } else if (n.status === "filtered_dedup") {
      filtered_dedup += 1;
    } else {
      filtered_regex_or_rate += 1;
    }
  }

  return {
    raw_total: nodes.length,
    filtered_regex_or_rate,
    filtered_dedup,
    active_total,
    avg_latency_ms: probed_count > 0 ? Math.round(latencySum / probed_count) : null,
    probed_count,
    region_counts,
  };
}
