import { useState } from "react";
import type { DashboardSnapshot } from "../../shared/types";
import { PulseIcon, SearchIcon } from "../icons";

interface Props {
  data: DashboardSnapshot;
  busy: boolean;
  onOpenAddSub: () => void;
  onSavePipeline: (payload: {
    rename_template: string;
    exclude_regex: string;
    max_multiplier: number;
    dedup_enabled: boolean;
  }) => Promise<void>;
  onProbeLatency: () => Promise<void>;
}

export function NodePoolView({ data, busy, onOpenAddSub, onSavePipeline, onProbeLatency }: Props) {
  const [regionFilter, setRegionFilter] = useState<string>("ALL");
  const [query, setQuery] = useState("");
  const [renameTemplate, setRenameTemplate] = useState(data.settings.rename_template);
  const [excludeRegex, setExcludeRegex] = useState(data.settings.exclude_regex);
  const [maxMultiplier, setMaxMultiplier] = useState(data.settings.max_multiplier);
  const [dedupEnabled, setDedupEnabled] = useState(data.settings.dedup_enabled);
  const [showMobileRules, setShowMobileRules] = useState(false);

  const filteredTotal = data.pipeline.filtered_regex_or_rate + data.pipeline.filtered_dedup;
  const regions = Object.entries(data.pipeline.region_counts).sort((a, b) => b[1] - a[1]);

  const visibleNodes = data.nodes.filter((n) => {
    if (regionFilter === "FILTERED") {
      if (n.status === "active") return false;
    } else if (regionFilter !== "ALL") {
      if (n.status !== "active" || n.region !== regionFilter) return false;
    }
    if (query.trim()) {
      const q = query.toLowerCase();
      return (
        n.normalized_name.toLowerCase().includes(q) ||
        n.raw_name.toLowerCase().includes(q) ||
        n.protocol.toLowerCase().includes(q) ||
        n.sub_name.toLowerCase().includes(q) ||
        n.server.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const sampleNode = data.nodes.find((n) => n.status === "active") || data.nodes[0];
  const sampleRawLabel = sampleNode ? sampleNode.raw_name : "示例原始节点名";
  const previewSample = renameTemplate
    .replace(/\{REGION\}/g, sampleNode?.region || "HK")
    .replace(/\{LINE_TAG\}/g, sampleNode?.line_tag || "IEPL")
    .replace(/\{PROTOCOL\}/g, sampleNode?.protocol || "Trojan")
    .replace(/\{SOURCE\}/g, sampleNode ? sampleNode.sub_name.split("·")[0].trim() : "Sub")
    .replace(/\{INDEX:02\}/g, "01")
    .replace(/\{INDEX\}/g, "1");

  const handleApply = () =>
    onSavePipeline({
      rename_template: renameTemplate,
      exclude_regex: excludeRegex,
      max_multiplier: maxMultiplier,
      dedup_enabled: dedupEnabled,
    });

  return (
    <>
      <div className="top-bar">
        <div style={{ minWidth: 220 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <h1 className="page-title">节点整合池与清洗引擎</h1>
            <span className="badge badge-primary">PIPELINE ACTIVE</span>
          </div>
          <p className="page-subtitle">
            对多订阅源原始节点执行正则过滤、高倍率剔除、指纹去重与标准化重命名
          </p>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          {data.pipeline.active_total > 0 && (
            <button type="button" className="btn" disabled={busy} onClick={onProbeLatency}>
              <PulseIcon />
              <span>{busy ? "探测中…" : "TCP 握手测速"}</span>
            </button>
          )}
          <button
            type="button"
            className="btn mobile-only"
            onClick={() => setShowMobileRules((v) => !v)}
          >
            {showMobileRules ? "收起规则" : "清洗规则"}
          </button>
          <button type="button" className="btn btn-primary" disabled={busy} onClick={handleApply}>
            应用并重新编译节点池
          </button>
        </div>
      </div>

      {/* 4-Stage Pipeline Funnel */}
      <div className="view-scroll-body">
      <div className="kpi-strip">
        <div className="kpi-cell">
          <div className="kpi-label">01 · RAW INGEST</div>
          <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
            <span className="kpi-value">{data.pipeline.raw_total}</span>
            <span style={{ fontSize: 12, color: "var(--color-muted)", whiteSpace: "nowrap" }}>原始解析节点</span>
          </div>
          <div className="kpi-caption mono">保留完整协议参数 (TLS / WS / Reality / OBFS)</div>
        </div>

        <div className="kpi-cell">
          <div className="kpi-label">02 · REGEX &amp; RATE FILTER</div>
          <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
            <span className="kpi-value" style={{ color: "var(--color-warning)" }}>
              -{data.pipeline.filtered_regex_or_rate}
            </span>
            <span style={{ fontSize: 12, color: "var(--color-muted)", whiteSpace: "nowrap" }}>条件拦截剔除</span>
          </div>
          <div className="kpi-caption mono">阈值 &gt; {data.settings.max_multiplier.toFixed(1)}x 与黑名单正则</div>
        </div>

        <div className="kpi-cell">
          <div className="kpi-label">03 · FINGERPRINT DEDUP</div>
          <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
            <span className="kpi-value">-{data.pipeline.filtered_dedup}</span>
            <span style={{ fontSize: 12, color: "var(--color-muted)", whiteSpace: "nowrap" }}>重复入口合并</span>
          </div>
          <div className="kpi-caption mono">按 Server:Port 指纹保留低倍率源</div>
        </div>

        <div className="kpi-cell" style={{ background: "var(--color-primary-soft)" }}>
          <div className="kpi-label" style={{ color: "var(--color-primary)", fontWeight: 600 }}>
            04 · NORMALIZED OUTPUT
          </div>
          <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
            <span className="kpi-value" style={{ color: "var(--color-primary)" }}>
              {data.pipeline.active_total}
            </span>
            <span style={{ fontSize: 12, fontWeight: 500, whiteSpace: "nowrap" }}>最终下发可用</span>
          </div>
          <div className="kpi-caption mono" style={{ color: "var(--color-success)" }}>
            {data.pipeline.avg_latency_ms !== null
              ? `已探测 ${data.pipeline.probed_count} 节点 · 均值 ${data.pipeline.avg_latency_ms}ms`
              : "点击右上角「TCP 握手测速」探测连通性"}
          </div>
        </div>
      </div>

      <div className="workspace-split">
        <div className="primary-column" style={{ gap: 18 }}>
          {data.nodes.length === 0 ? (
            <div
              style={{
                padding: "44px 24px",
                borderRadius: 12,
                border: "1px dashed var(--color-border)",
                background: "var(--color-surface)",
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                textAlign: "center",
                gap: 12,
              }}
            >
              <div style={{ fontSize: 15, fontWeight: 600 }}>节点池为空</div>
              <div style={{ fontSize: 13, color: "var(--color-muted)", maxWidth: 420 }}>
                导入真实订阅源或本地配置文件后，将在此展示每一个节点的标准化重命名结果、原始名称对比、协议与倍率拦截详情。
              </div>
              <button type="button" className="btn btn-primary" onClick={onOpenAddSub}>
                + 导入订阅源 / 本地配置
              </button>
            </div>
          ) : (
            <>
              {/* Region Filter & Search Bar */}
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: 12,
                  flexWrap: "wrap",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                  <button
                    type="button"
                    className={`filter-chip ${regionFilter === "ALL" ? "active" : ""}`}
                    onClick={() => setRegionFilter("ALL")}
                  >
                    全部 {data.pipeline.raw_total}
                  </button>
                  {regions.map(([rg, cnt]) => (
                    <button
                      key={rg}
                      type="button"
                      className={`filter-chip mono ${regionFilter === rg ? "active" : ""}`}
                      onClick={() => setRegionFilter(rg)}
                    >
                      {rg} {cnt}
                    </button>
                  ))}
                  {filteredTotal > 0 && (
                    <button
                      type="button"
                      className={`filter-chip mono ${regionFilter === "FILTERED" ? "active" : ""}`}
                      style={
                        regionFilter !== "FILTERED"
                          ? {
                              background: "var(--color-warning-soft)",
                              borderColor: "var(--color-warning-border)",
                              color: "var(--color-warning)",
                            }
                          : undefined
                      }
                      onClick={() => setRegionFilter("FILTERED")}
                    >
                      已剔除 {filteredTotal}
                    </button>
                  )}
                </div>

                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                    padding: "6px 12px",
                    borderRadius: 7,
                    background: "var(--color-surface)",
                    border: "1px solid var(--color-border)",
                    minWidth: 200,
                  }}
                >
                  <SearchIcon />
                  <input
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    placeholder="筛选节点名 / 域名 / 协议..."
                    style={{
                      border: "none",
                      background: "transparent",
                      outline: "none",
                      fontSize: 12,
                      width: "100%",
                      color: "var(--color-ink)",
                    }}
                  />
                </div>
              </div>

              {/* Node Table */}
              <div className="hairline-list">
                <div className="table-header-row desktop-only">
                  <div style={{ flex: 1, minWidth: 180 }}>NORMALIZED NODE · 标准名与原始对照</div>
                  <div className="col-opt-lg" style={{ width: 96, flexShrink: 0 }}>
                    SOURCE
                  </div>
                  <div className="col-opt-md" style={{ width: 96, flexShrink: 0 }}>
                    PROTOCOL
                  </div>
                  <div className="col-opt-md" style={{ width: 64, flexShrink: 0, textAlign: "right" }}>
                    RATE
                  </div>
                  <div style={{ width: 84, flexShrink: 0, textAlign: "right" }}>TCP RTT</div>
                </div>

                {visibleNodes.map((n) => {
                  const isActive = n.status === "active";
                  const badgeClass = !isActive
                    ? n.status === "filtered_regex"
                      ? "badge badge-danger"
                      : "badge badge-warning"
                    : n.region === "HK"
                      ? "badge badge-primary"
                      : "badge";
                  const badgeText = !isActive ? "RM" : n.region === "GLOBAL" ? "GL" : n.region.slice(0, 2);

                  return (
                    <div key={n.id} className="hairline-row" style={{ opacity: isActive ? 1 : 0.7 }}>
                      <div className="row-main-slot">
                        <div style={{ width: 34, flexShrink: 0 }}>
                          <span className={badgeClass} style={{ width: "100%" }}>
                            {badgeText}
                          </span>
                        </div>
                        <div style={{ display: "flex", flexDirection: "column", gap: 2, minWidth: 0, flex: 1 }}>
                          <div
                            className="row-title"
                            style={{
                              fontWeight: isActive ? 600 : 500,
                              color: isActive ? "var(--color-ink)" : "var(--color-muted)",
                              textDecoration: isActive ? "none" : "line-through",
                            }}
                          >
                            {isActive ? n.normalized_name : n.raw_name}
                          </div>
                          <div
                            className="row-subtitle"
                            style={{
                              color: isActive
                                ? "var(--color-muted)"
                                : n.status === "filtered_regex"
                                  ? "var(--color-danger)"
                                  : "var(--color-warning)",
                            }}
                          >
                            {isActive
                              ? `原名: ${n.raw_name}${n.merged_count > 0 ? ` (合并 ${n.merged_count} 重复)` : ""}`
                              : n.filter_reason}
                          </div>
                        </div>
                      </div>

                      <div
                        className="desktop-only col-opt-lg truncate"
                        style={{ width: 96, flexShrink: 0, fontSize: 12, color: "var(--color-muted)" }}
                      >
                        {n.sub_name}
                      </div>

                      <div
                        className="mono desktop-only col-opt-md"
                        style={{ width: 96, flexShrink: 0, fontSize: 12, whiteSpace: "nowrap" }}
                      >
                        {n.protocol}
                      </div>

                      <div
                        className="mono desktop-only col-opt-md"
                        style={{
                          width: 64,
                          flexShrink: 0,
                          textAlign: "right",
                          fontSize: 12,
                          whiteSpace: "nowrap",
                          fontWeight: !isActive && n.multiplier > data.settings.max_multiplier ? 600 : 400,
                          color:
                            !isActive && n.multiplier > data.settings.max_multiplier
                              ? "var(--color-warning)"
                              : "var(--color-muted)",
                        }}
                      >
                        {n.multiplier.toFixed(1)}x
                      </div>

                      <div
                        className="mono"
                        style={{
                          width: 84,
                          flexShrink: 0,
                          textAlign: "right",
                          fontSize: 12,
                          fontWeight: 600,
                          whiteSpace: "nowrap",
                          color: !isActive
                            ? n.status === "filtered_regex"
                              ? "var(--color-danger)"
                              : "var(--color-warning)"
                            : n.latency_ms === null
                              ? "var(--color-subtle)"
                              : n.latency_ms > 150
                                ? "var(--color-primary)"
                                : "var(--color-success)",
                        }}
                      >
                        {!isActive
                          ? n.status === "filtered_regex"
                            ? "已过滤"
                            : "已拦截"
                          : n.latency_ms !== null
                            ? `${n.latency_ms} ms`
                            : "未测速"}
                      </div>
                    </div>
                  );
                })}
              </div>
            </>
          )}
        </div>

        {/* Right Cleaning Inspector Rail */}
        <aside className={`secondary-rail ${showMobileRules ? "" : "desktop-only"}`} style={{ gap: 22 }}>
          <div style={{ display: "flex", flexDirection: "column", gap: 10, minWidth: 0 }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
              <span style={{ fontSize: 14, fontWeight: 600, whiteSpace: "nowrap" }}>统一重命名模板</span>
              <span className="mono" style={{ fontSize: 11, color: "var(--color-primary)", whiteSpace: "nowrap" }}>
                实时映射预览
              </span>
            </div>
            <div className="surface-card">
              <div className="mono" style={{ fontSize: 11, color: "var(--color-subtle)" }}>
                支持变量: &#123;REGION&#125; &#123;LINE_TAG&#125; &#123;PROTOCOL&#125; &#123;SOURCE&#125; &#123;INDEX:02&#125;
              </div>
              <input
                className="input mono"
                value={renameTemplate}
                onChange={(e) => setRenameTemplate(e.target.value)}
              />
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, paddingTop: 4 }}>
                <span className="mono truncate" style={{ fontSize: 11, color: "var(--color-muted)" }}>
                  {sampleRawLabel}
                </span>
                <span className="mono" style={{ fontSize: 11, fontWeight: 600, color: "var(--color-primary)", whiteSpace: "nowrap" }}>
                  → {previewSample}
                </span>
              </div>
            </div>

            <div className="surface-card" style={{ gap: 8, marginTop: 4 }}>
              <div style={{ fontSize: 13, fontWeight: 600 }}>客户端协议兼容转换</div>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 8, fontSize: 12 }}>
                <span style={{ color: "var(--color-muted)" }}>VLESS → Surge 6</span>
                <span className="mono" style={{ fontSize: 11, color: "var(--color-success)", whiteSpace: "nowrap" }}>
                  原生支持 (REALITY / WS / gRPC / XHTTP)
                </span>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 8, fontSize: 12 }}>
                <span style={{ color: "var(--color-muted)" }}>VLESS / SSR → Surge 5</span>
                <span className="mono" style={{ fontSize: 11, color: "var(--color-warning)", whiteSpace: "nowrap" }}>
                  自动跳过不支持协议
                </span>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 8, fontSize: 12 }}>
                <span style={{ color: "var(--color-muted)" }}>Snell v4+ → Stash / Clash</span>
                <span className="mono" style={{ fontSize: 11, color: "var(--color-warning)", whiteSpace: "nowrap" }}>
                  自动跳过不支持协议
                </span>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 8, fontSize: 12 }}>
                <span style={{ color: "var(--color-muted)" }}>Clash YAML ↔ Surge</span>
                <span className="mono" style={{ fontSize: 11, color: "var(--color-success)", whiteSpace: "nowrap" }}>
                  双向保留完整参数
                </span>
              </div>
            </div>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 10, minWidth: 0 }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
              <span style={{ fontSize: 14, fontWeight: 600, whiteSpace: "nowrap" }}>剔除与倍率守卫</span>
              <span className="mono" style={{ fontSize: 11, color: "var(--color-warning)", whiteSpace: "nowrap" }}>
                已拦截 {filteredTotal} 节点
              </span>
            </div>

            <div className="surface-card" style={{ gap: 12 }}>
              <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                <span className="mono" style={{ fontSize: 11, color: "var(--color-subtle)" }}>
                  EXCLUDE REGEX · 黑名单正则
                </span>
                <input
                  className="input mono"
                  style={{ fontSize: 11 }}
                  value={excludeRegex}
                  onChange={(e) => setExcludeRegex(e.target.value)}
                />
              </div>

              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: 8,
                  paddingTop: 10,
                  borderTop: "1px solid var(--color-border)",
                }}
              >
                <span style={{ fontSize: 13, whiteSpace: "nowrap" }}>最高允许倍率</span>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <input
                    type="range"
                    min="0.5"
                    max="10"
                    step="0.5"
                    value={maxMultiplier}
                    onChange={(e) => setMaxMultiplier(Number(e.target.value))}
                    style={{ width: 84 }}
                  />
                  <span className="badge mono">&lt;= {maxMultiplier.toFixed(1)}x</span>
                </div>
              </div>

              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: 8,
                  paddingTop: 10,
                  borderTop: "1px solid var(--color-border)",
                }}
              >
                <span style={{ fontSize: 13 }}>跨源同入口自动去重</span>
                <button
                  type="button"
                  className={`switch ${dedupEnabled ? "on" : ""}`}
                  onClick={() => setDedupEnabled((v) => !v)}
                >
                  <span className="switch-thumb" />
                </button>
              </div>

              <button type="button" className="btn btn-ink btn-sm" disabled={busy} onClick={handleApply}>
                保存清洗参数并重算
              </button>
            </div>
          </div>
        </aside>
      </div>
      </div>
    </>
  );
}
