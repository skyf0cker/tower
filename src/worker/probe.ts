import { connect } from "cloudflare:sockets";
import type { ProxyNode } from "../shared/types";

export interface NodeProbeEntry {
  id: string;
  normalized_name: string;
  region: string;
  protocol: string;
  server: string;
  port: number;
  latency_ms: number | null;
}

export interface ProbeNodesSummary {
  probed_count: number;
  reachable_count: number;
  unreachable_count: number;
  avg_latency_ms: number | null;
  results: NodeProbeEntry[];
}

export async function probeTcpConnectMs(
  hostname: string,
  port: number,
  timeoutMs = 2500
): Promise<number | null> {
  const t0 = Date.now();
  let socket: ReturnType<typeof connect> | null = null;
  try {
    socket = connect({ hostname, port });
    await Promise.race([
      socket.opened,
      new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), timeoutMs)),
    ]);
    const rtt = Math.max(1, Date.now() - t0);
    await socket.close().catch(() => {});
    return rtt;
  } catch {
    if (socket) {
      await socket.close().catch(() => {});
    }
    return null;
  }
}

export async function probeNodes(
  db: D1Database,
  nodes: ProxyNode[],
  options?: { timeoutMs?: number; concurrency?: number }
): Promise<ProbeNodesSummary> {
  const rawTimeout = typeof options?.timeoutMs === "number" ? options.timeoutMs : 2500;
  const timeoutMs = Math.max(500, Math.min(8000, Math.round(rawTimeout)));
  const rawConc = typeof options?.concurrency === "number" ? options.concurrency : 10;
  const concurrency = Math.max(1, Math.min(20, Math.round(rawConc)));

  const results: NodeProbeEntry[] = [];
  let latencySum = 0;
  let reachableCount = 0;

  for (let i = 0; i < nodes.length; i += concurrency) {
    const chunk = nodes.slice(i, i + concurrency);
    const chunkResults = await Promise.all(
      chunk.map(async (n) => {
        const ms = await probeTcpConnectMs(n.server, n.port, timeoutMs);
        await db.prepare(`UPDATE nodes SET latency_ms = ? WHERE id = ?`).bind(ms, n.id).run();
        return {
          id: n.id,
          normalized_name: n.normalized_name,
          region: n.region,
          protocol: n.protocol,
          server: n.server,
          port: n.port,
          latency_ms: ms,
        };
      })
    );
    for (const item of chunkResults) {
      results.push(item);
      if (item.latency_ms !== null) {
        reachableCount += 1;
        latencySum += item.latency_ms;
      }
    }
  }

  return {
    probed_count: results.length,
    reachable_count: reachableCount,
    unreachable_count: results.length - reachableCount,
    avg_latency_ms: reachableCount > 0 ? Math.round(latencySum / reachableCount) : null,
    results,
  };
}
