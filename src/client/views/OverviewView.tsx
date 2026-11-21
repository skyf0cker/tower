import { useState } from "react";
import type { DashboardSnapshot } from "../../shared/types";
import { CopyIcon, formatRelativeTime } from "../icons";

interface Props {
  data: DashboardSnapshot;
  busy: boolean;
  onSync: () => void;
  onOpenAddSub: () => void;
  onToggleSub: (id: string, enabled: boolean) => void;
  onDeleteSub: (id: string) => void;
  onNavigate: (tab: "overview" | "subscriptions" | "nodes" | "rules" | "logs") => void;
  onNotify: (msg: string) => void;
}

export function OverviewView({
  data,
  busy,
  onSync,
  onOpenAddSub,
  onToggleSub,
  onDeleteSub,
  onNavigate,
  onNotify,
}: Props) {
  const [formatTab, setFormatTab] = useState<"surge6" | "surge" | "stash" | "clash">("surge6");
  const origin = typeof window !== "undefined" ? window.location.origin : "http://127.0.0.1:8787";
  const baseSubUrl = `${origin}/sub/${data.settings.sub_token}`;
  const fullSubUrl = `${baseSubUrl}?target=${formatTab}`;

  const surge6DeepLink = `surge:///install-config?url=${encodeURIComponent(`${baseSubUrl}?target=surge6`)}`;
  const surgeDeepLink = `surge:///install-config?url=${encodeURIComponent(`${baseSubUrl}?target=surge`)}`;
  const stashDeepLink = `stash://install-config?url=${encodeURIComponent(`${baseSubUrl}?target=stash`)}&name=Tower`;
  const activeVlessCount = data.nodes.filter(
    (n) => n.status === "active" && n.protocol.toUpperCase() === "VLESS"
  ).length;

  const copyText = async (text: string, label: string) => {
    await navigator.clipboard.writeText(text);
    onNotify(`已复制 ${label}`);
  };

  const enabledSubs = data.subscriptions.filter((s) => s.enabled);
  const okSubs = enabledSubs.filter(
    (s) => s.last_status === "200 OK" || s.last_status === "本地导入"
  );
  const syncSuccessRatio =
    enabledSubs.length > 0 ? `${Math.round((okSubs.length / enabledSubs.length) * 100)}%` : "—";

  const totalRuleEntries = data.rules
    .filter((r) => r.enabled)
    .reduce((acc, r) => acc + r.rule_count, 0);
  const blockedCount = data.access_logs.filter((l) => l.status_code >= 400).length;
  const activeClients = Array.from(
    new Set(data.access_logs.filter((l) => l.status_code === 200).map((l) => l.device_ua))
  );
  const seenClientTags = Array.from(
    new Set(data.access_logs.filter((l) => l.status_code === 200).map((l) => l.client_tag))
  );

  return (
    <>
      {/* Desktop Top Header */}
      <div className="top-bar desktop-only">
        <div style={{ minWidth: 220 }}>
          <h1 className="page-title">订阅与路由总控</h1>
          <p className="page-subtitle">统一整合多源节点与分流规则，向桌面与移动终端自适应下发配置</p>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "nowrap", maxWidth: "100%", minWidth: 0 }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              padding: "5px 6px 5px 12px",
              borderRadius: 8,
              background: "var(--color-surface)",
              border: "1px solid var(--color-border)",
              flex: "1 1 auto",
              minWidth: 0,
            }}
          >
            <span
              className="mono truncate"
              style={{ fontSize: 12, color: "var(--color-muted)", maxWidth: 200, minWidth: 80 }}
            >
              {baseSubUrl}
            </span>
            <div style={{ display: "flex", gap: 4, flexShrink: 0 }}>
              {(
                [
                  { id: "surge6", label: "Surge 6" },
                  { id: "surge", label: "Surge 5" },
                  { id: "stash", label: "Stash" },
                  { id: "clash", label: "Clash.Meta" },
                ] as const
              ).map((t) => (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => setFormatTab(t.id)}
                  className="mono"
                  style={{
                    padding: "3px 8px",
                    borderRadius: 5,
                    border: formatTab === t.id ? "1px solid var(--color-border)" : "1px solid transparent",
                    background: formatTab === t.id ? "var(--color-card)" : "transparent",
                    color: formatTab === t.id ? "var(--color-ink)" : "var(--color-muted)",
                    fontSize: 11,
                    fontWeight: formatTab === t.id ? 600 : 500,
                    cursor: "pointer",
                    whiteSpace: "nowrap",
                  }}
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>

          <button
            type="button"
            className="btn btn-primary"
            onClick={() => copyText(fullSubUrl, `${formatTab.toUpperCase()} 统一订阅链接`)}
          >
            <CopyIcon />
            <span>复制统一订阅</span>
          </button>
        </div>
      </div>

      {/* Mobile Hero Unified Subscription Card (<= 768px) */}
      <div className="view-scroll-body">
      <div className="mobile-only" style={{ padding: "16px 18px 4px", flexDirection: "column" }}>
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 14,
            padding: 16,
            borderRadius: 12,
            background: "var(--color-surface)",
            border: "1px solid var(--color-border)",
          }}
        >
          <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
            <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
              <span className="mono" style={{ fontSize: 11, letterSpacing: "0.04em", color: "var(--color-muted)" }}>
                UNIFIED SUBSCRIPTION
              </span>
              <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
                <span style={{ fontSize: 26, fontWeight: 600, letterSpacing: "-0.03em", lineHeight: "30px" }}>
                  {data.pipeline.active_total}
                </span>
                <span style={{ fontSize: 13, fontWeight: 500 }}>整合可用节点</span>
              </div>
            </div>
            <span
              className="mono"
              style={{
                padding: "3px 8px",
                borderRadius: 6,
                background: "var(--color-card)",
                border: "1px solid var(--color-border)",
                fontSize: 11,
                fontWeight: 500,
              }}
            >
              UA 自适应
            </span>
          </div>

          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 8,
              padding: "8px 10px",
              borderRadius: 7,
              background: "var(--color-card)",
              border: "1px solid var(--color-border)",
            }}
          >
            <span className="mono truncate" style={{ fontSize: 11, color: "var(--color-muted)" }}>
              {baseSubUrl}
            </span>
            <button
              type="button"
              onClick={() => copyText(baseSubUrl, "统一订阅地址")}
              className="link-btn mono"
              style={{ fontSize: 11 }}
            >
              复制
            </button>
          </div>

          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <a href={surge6DeepLink} className="btn btn-primary" style={{ flex: "1 1 110px", fontWeight: 600 }}>
              导入 Surge 6
            </a>
            <a href={surgeDeepLink} className="btn" style={{ flex: "1 1 90px", fontWeight: 600 }}>
              Surge 5
            </a>
            <a href={stashDeepLink} className="btn" style={{ flex: "1 1 90px", fontWeight: 600 }}>
              Stash
            </a>
          </div>
        </div>
      </div>

      {/* 4-Column Architectural KPI Strip (100% Real Data) */}
      <div className="kpi-strip">
        <div className="kpi-cell">
          <div className="kpi-label">ACTIVE NODES · 整合可用节点</div>
          <div style={{ display: "flex", alignItems: "baseline", gap: 10 }}>
            <span className="kpi-value">{data.pipeline.active_total}</span>
            {data.pipeline.raw_total > 0 && (
              <span className="mono" style={{ fontSize: 12, color: "var(--color-success)", whiteSpace: "nowrap" }}>
                共 {data.pipeline.raw_total} 原始
              </span>
            )}
          </div>
          <div className="kpi-caption">
            {enabledSubs.length > 0
              ? `源自 ${enabledSubs.length} 个启用源 · 过滤去重 ${data.pipeline.filtered_regex_or_rate + data.pipeline.filtered_dedup} 节点`
              : "尚未导入订阅源"}
          </div>
        </div>

        <div className="kpi-cell">
          <div className="kpi-label">ROUTING RULES · 策略与规则</div>
          <div style={{ display: "flex", alignItems: "baseline", gap: 10 }}>
            <span className="kpi-value">{data.policy_groups.length} 组</span>
            <span className="mono" style={{ fontSize: 12, color: "var(--color-muted)", whiteSpace: "nowrap" }}>
              {totalRuleEntries.toLocaleString()} 条
            </span>
          </div>
          <div className="kpi-caption">
            {data.rules.length > 0
              ? `含 ${data.rules.filter((r) => r.kind === "override").length} 条私有覆盖与 ${data.rules.filter((r) => r.kind === "ruleset").length} 条规则集`
              : "未配置时默认下发 CN 直连 + Proxy 兜底"}
          </div>
        </div>

        <div className="kpi-cell">
          <div className="kpi-label">SYNC HEALTH · 同步与延迟</div>
          <div style={{ display: "flex", alignItems: "baseline", gap: 10 }}>
            <span className="kpi-value">{syncSuccessRatio}</span>
            <span className="mono" style={{ fontSize: 12, color: "var(--color-primary)", whiteSpace: "nowrap" }}>
              {data.pipeline.avg_latency_ms !== null
                ? `${data.pipeline.avg_latency_ms}ms 均值`
                : "未测速"}
            </span>
          </div>
          <div className="kpi-caption">
            {data.settings.last_full_sync_at
              ? `上次更新 ${formatRelativeTime(data.settings.last_full_sync_at)} · 版本 v${data.settings.revision}`
              : `当前配置版本 v${data.settings.revision}`}
          </div>
        </div>

        <div className="kpi-cell">
          <div className="kpi-label">ENDPOINTS · 累计拉取终端</div>
          <div style={{ display: "flex", alignItems: "baseline", gap: 10 }}>
            <span className="kpi-value">{activeClients.length} 台</span>
            {blockedCount > 0 && (
              <span className="mono" style={{ fontSize: 12, color: "var(--color-warning)", whiteSpace: "nowrap" }}>
                {blockedCount} 次拦截
              </span>
            )}
          </div>
          <div className="kpi-caption">
            {seenClientTags.length > 0
              ? `已接入类型: ${seenClientTags.join(" · ")}`
              : "等待终端首次拉取统一订阅"}
          </div>
        </div>
      </div>

      {/* Main Split Body */}
      <div className="workspace-split">
        <div className="primary-column">
          {/* Section 1: Upstream Subscriptions */}
          <section style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            <div className="section-header">
              <div style={{ display: "flex", alignItems: "baseline", gap: 10 }}>
                <h2 className="section-title">上游订阅源管理</h2>
                <span className="mono col-opt-md" style={{ fontSize: 12, color: "var(--color-muted)", whiteSpace: "nowrap" }}>
                  {data.subscriptions.length} SOURCES
                </span>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                {data.subscriptions.length > 0 && (
                  <button type="button" className="btn btn-sm" disabled={busy} onClick={onSync}>
                    {busy ? "同步中…" : "立即全量更新"}
                  </button>
                )}
                <button type="button" className="btn btn-sm" onClick={() => onNavigate("subscriptions")}>
                  订阅管理详情 →
                </button>
                <button type="button" className="btn btn-sm btn-ink" onClick={onOpenAddSub}>
                  + 新增订阅
                </button>
              </div>
            </div>

            {data.subscriptions.length === 0 ? (
              <div
                style={{
                  padding: "36px 24px",
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
                <div style={{ fontSize: 15, fontWeight: 600 }}>尚未接入任何订阅源</div>
                <div style={{ fontSize: 13, color: "var(--color-muted)", maxWidth: 440 }}>
                  点击下方按钮粘贴你的机场订阅链接，或直接上传本地 Surge <code className="mono">.conf</code> / Stash &amp; Clash <code className="mono">.yaml</code> 配置文件查看真实节点清洗与整合效果。
                </div>
                <button type="button" className="btn btn-primary" onClick={onOpenAddSub}>
                  + 导入首个真实订阅源 / 配置文件
                </button>
              </div>
            ) : (
              <div className="hairline-list">
                <div className="table-header-row desktop-only">
                  <div style={{ flex: 1, minWidth: 160 }}>PROVIDER · 订阅源与协议</div>
                  <div className="col-opt-lg" style={{ width: 132, flexShrink: 0 }}>
                    REGIONS · 区域
                  </div>
                  <div className="col-opt-md" style={{ width: 78, flexShrink: 0, textAlign: "right" }}>
                    NODES · 有效
                  </div>
                  <div style={{ width: 124, flexShrink: 0 }}>QUOTA · 流量余量</div>
                  <div className="col-opt-md" style={{ width: 88, flexShrink: 0, textAlign: "right" }}>
                    STATUS
                  </div>
                  <div className="col-opt-md" style={{ width: 22, flexShrink: 0 }} />
                </div>

                {data.subscriptions.map((sub) => {
                  const hasQuota = !sub.is_unlimited && sub.total_gb > 0;
                  const ratio = hasQuota
                    ? Math.min(100, Math.round((sub.used_gb / Math.max(0.1, sub.total_gb)) * 100))
                    : 0;
                  const isWarn = hasQuota && ratio >= 85;
                  return (
                    <div key={sub.id} className="hairline-row" style={{ opacity: sub.enabled ? 1 : 0.58 }}>
                      <div className="row-main-slot">
                        <button
                          type="button"
                          title={sub.enabled ? "点击暂停该订阅源" : "点击启用该订阅源"}
                          onClick={() => onToggleSub(sub.id, !sub.enabled)}
                          style={{
                            width: 16,
                            height: 16,
                            border: "none",
                            background: "transparent",
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            cursor: "pointer",
                            padding: 0,
                            flexShrink: 0,
                          }}
                        >
                          <span
                            style={{
                              width: 8,
                              height: 8,
                              borderRadius: 999,
                              background: !sub.enabled
                                ? "var(--color-subtle)"
                                : sub.last_status.includes("失败") || sub.last_status.startsWith("HTTP 4") || sub.last_status.startsWith("HTTP 5")
                                  ? "var(--color-danger)"
                                  : "var(--color-success)",
                            }}
                          />
                        </button>
                        <div style={{ display: "flex", flexDirection: "column", gap: 2, minWidth: 0, flex: 1 }}>
                          <div className="row-title">{sub.name}</div>
                          <div className="row-subtitle">{sub.protocol_hint || sub.url}</div>
                        </div>
                      </div>

                      <div
                        className="desktop-only col-opt-lg"
                        style={{ display: "flex", gap: 4, width: 132, flexShrink: 0 }}
                      >
                        {(sub.regions.length > 0 ? sub.regions : ["—"]).slice(0, 4).map((rg) => (
                          <span key={rg} className="badge">
                            {rg}
                          </span>
                        ))}
                      </div>

                      <div
                        className="mono desktop-only col-opt-md"
                        style={{ width: 78, flexShrink: 0, fontSize: 13, fontWeight: 500, whiteSpace: "nowrap", textAlign: "right" }}
                      >
                        {sub.valid_node_count} / {sub.raw_node_count}
                      </div>

                      <div style={{ display: "flex", flexDirection: "column", gap: 5, width: 124, flexShrink: 0 }}>
                        <div
                          className="mono truncate"
                          style={{
                            fontSize: 11,
                            color: isWarn ? "var(--color-warning)" : "var(--color-muted)",
                          }}
                        >
                          {hasQuota ? `${sub.used_gb} / ${sub.total_gb} GB` : "未返回配额 / 不限"}
                        </div>
                        <div className="progress-track">
                          <div
                            className="progress-fill"
                            style={{
                              width: `${hasQuota ? ratio : 100}%`,
                              opacity: hasQuota ? 1 : 0.25,
                              background: isWarn ? "var(--color-warning)" : "var(--color-ink)",
                            }}
                          />
                        </div>
                      </div>

                      <div
                        className="mono desktop-only col-opt-md"
                        style={{
                          width: 88,
                          flexShrink: 0,
                          textAlign: "right",
                          fontSize: 11,
                          whiteSpace: "nowrap",
                          color: sub.last_status === "200 OK" || sub.last_status === "本地导入"
                            ? "var(--color-success)"
                            : "var(--color-muted)",
                        }}
                      >
                        {sub.enabled ? sub.last_status : "已暂停"}
                      </div>

                      <div className="desktop-only col-opt-md" style={{ width: 22, flexShrink: 0, display: "flex", justifyContent: "flex-end" }}>
                        <button
                          type="button"
                          className="btn btn-ghost-danger mono"
                          style={{ fontSize: 11, padding: "2px 5px" }}
                          onClick={() => onDeleteSub(sub.id)}
                          title="移除订阅源"
                        >
                          ×
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </section>

          {/* Section 2: Routing Rules Summary */}
          <section style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            <div className="section-header">
              <div style={{ display: "flex", alignItems: "baseline", gap: 10 }}>
                <h2 className="section-title">路由规则与策略矩阵</h2>
                <span className="mono col-opt-md" style={{ fontSize: 12, color: "var(--color-muted)", whiteSpace: "nowrap" }}>
                  PRIORITY PIPELINE
                </span>
              </div>
              <button type="button" className="link-btn" onClick={() => onNavigate("rules")}>
                进入规则编排器 →
              </button>
            </div>

            {data.rules.length === 0 ? (
              <div
                style={{
                  padding: "22px 20px",
                  borderRadius: 10,
                  border: "1px solid var(--color-border)",
                  background: "var(--color-surface)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: 12,
                  flexWrap: "wrap",
                }}
              >
                <div style={{ fontSize: 13, color: "var(--color-muted)" }}>
                  暂未配置自定义分流规则（导入节点后可在「路由规则编排」中按地区一键生成策略组与规则集）。
                </div>
                <button type="button" className="btn btn-sm" onClick={() => onNavigate("rules")}>
                  前往配置规则 →
                </button>
              </div>
            ) : (
              <div className="hairline-list">
                {data.rules.slice(0, 6).map((rule, idx) => {
                  const isFinal = rule.rule_type === "FINAL";
                  const badgeClass =
                    rule.target_policy === "DIRECT"
                      ? "badge badge-success"
                      : rule.target_policy.startsWith("REJECT")
                        ? "badge badge-danger"
                        : idx === 0
                          ? "badge badge-primary"
                          : "badge";
                  return (
                    <div key={rule.id} className="hairline-row">
                      <div
                        className="mono"
                        style={{
                          width: 32,
                          flexShrink: 0,
                          fontSize: 12,
                          fontWeight: 600,
                          color: idx === 0 ? "var(--color-primary)" : "var(--color-muted)",
                        }}
                      >
                        {isFinal ? "#FF" : `#${String(idx + 1).padStart(2, "0")}`}
                      </div>

                      <div style={{ display: "flex", flexDirection: "column", gap: 2, flex: "1 1 160px", minWidth: 0 }}>
                        <div className="row-title">{rule.title}</div>
                        <div className="row-subtitle">
                          {rule.rule_type}, {rule.payload}
                        </div>
                      </div>

                      <div style={{ flexShrink: 0, display: "flex", justifyContent: "flex-end" }}>
                        <span className={badgeClass}>→ {rule.target_policy}</span>
                      </div>

                      <div
                        className="mono desktop-only col-opt-lg"
                        style={{
                          width: 96,
                          flexShrink: 0,
                          textAlign: "right",
                          fontSize: 11,
                          whiteSpace: "nowrap",
                          color: "var(--color-muted)",
                        }}
                      >
                        {rule.sync_meta}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </section>
        </div>

        {/* Right Secondary Rail */}
        <aside className="secondary-rail">
          <div style={{ display: "flex", flexDirection: "column", gap: 12, minWidth: 0 }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
              <span style={{ fontSize: 15, fontWeight: 600, whiteSpace: "nowrap" }}>终端自适应下发</span>
              <span className="mono" style={{ fontSize: 11, color: "var(--color-success)", whiteSpace: "nowrap" }}>
                TOKEN 鉴权开启
              </span>
            </div>

            <div className="surface-card">
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span className="badge badge-primary">SURGE 6</span>
                  <span style={{ fontSize: 13, fontWeight: 600, whiteSpace: "nowrap" }}>Managed Config</span>
                </div>
                <div style={{ display: "flex", gap: 10, flexShrink: 0 }}>
                  <a
                    href={`${baseSubUrl}?target=surge6`}
                    target="_blank"
                    rel="noreferrer"
                    style={{ fontSize: 12, color: "var(--color-muted)", textDecoration: "none", whiteSpace: "nowrap" }}
                  >
                    预览
                  </a>
                  <a
                    href={surge6DeepLink}
                    style={{ fontSize: 12, color: "var(--color-muted)", textDecoration: "none", whiteSpace: "nowrap" }}
                  >
                    导入
                  </a>
                  <button
                    type="button"
                    className="link-btn"
                    onClick={() => copyText(`${baseSubUrl}?target=surge6`, "Surge 6 (含 VLESS) 托管配置地址")}
                  >
                    复制链接
                  </button>
                </div>
              </div>
              <div className="row-subtitle">
                #!MANAGED-CONFIG · 原生支持 VLESS / REALITY / XHTTP
                {activeVlessCount > 0 ? ` · 含 ${activeVlessCount} 个 VLESS 节点` : ""}
              </div>
            </div>

            <div className="surface-card">
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span className="badge">SURGE 5</span>
                  <span style={{ fontSize: 13, fontWeight: 600, whiteSpace: "nowrap" }}>Managed Config</span>
                </div>
                <div style={{ display: "flex", gap: 10, flexShrink: 0 }}>
                  <a
                    href={`${baseSubUrl}?target=surge`}
                    target="_blank"
                    rel="noreferrer"
                    style={{ fontSize: 12, color: "var(--color-muted)", textDecoration: "none", whiteSpace: "nowrap" }}
                  >
                    预览
                  </a>
                  <button
                    type="button"
                    className="link-btn"
                    onClick={() => copyText(`${baseSubUrl}?target=surge`, "Surge 托管配置地址")}
                  >
                    复制链接
                  </button>
                </div>
              </div>
              <div className="row-subtitle">#!MANAGED-CONFIG interval=43200 · 自动跳过 VLESS</div>
            </div>

            <div className="surface-card">
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span className="badge">STASH / CLASH</span>
                  <span style={{ fontSize: 13, fontWeight: 600, whiteSpace: "nowrap" }}>YAML Profile</span>
                </div>
                <div style={{ display: "flex", gap: 10, flexShrink: 0 }}>
                  <a
                    href={`${baseSubUrl}?target=stash`}
                    target="_blank"
                    rel="noreferrer"
                    style={{ fontSize: 12, color: "var(--color-muted)", textDecoration: "none", whiteSpace: "nowrap" }}
                  >
                    预览
                  </a>
                  <button
                    type="button"
                    className="link-btn"
                    onClick={() => copyText(`${baseSubUrl}?target=stash`, "Stash YAML 订阅地址")}
                  >
                    复制链接
                  </button>
                </div>
              </div>
              <div className="row-subtitle">完整保留原始协议参数与 Rule-Provider</div>
            </div>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 12, minWidth: 0 }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
              <span style={{ fontSize: 15, fontWeight: 600, whiteSpace: "nowrap" }}>实时访问与拉取记录</span>
              <button type="button" className="link-btn" onClick={() => onNavigate("logs")}>
                全部审计
              </button>
            </div>

            {data.access_logs.length === 0 ? (
              <div
                style={{
                  padding: "20px 14px",
                  borderRadius: 10,
                  border: "1px dashed var(--color-border)",
                  color: "var(--color-muted)",
                  fontSize: 12,
                  textAlign: "center",
                }}
              >
                暂无终端拉取记录 · 点击上方「预览」或在客户端拉取后实时记录
              </div>
            ) : (
              <div className="hairline-list">
                {data.access_logs.slice(0, 5).map((log) => {
                  const isBlock = log.status_code >= 400;
                  const tagClass =
                    log.client_tag === "SURGE"
                      ? "badge badge-primary"
                      : isBlock
                        ? "badge badge-danger"
                        : "badge";
                  return (
                    <div
                      key={log.id}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 10,
                        padding: "11px 0",
                        borderBottom: "1px solid var(--color-border)",
                        minWidth: 0,
                      }}
                    >
                      <div style={{ width: 58, flexShrink: 0 }}>
                        <span className={tagClass} style={{ width: "100%", fontSize: 10 }}>
                          {log.client_tag}
                        </span>
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", gap: 2, flex: 1, minWidth: 0 }}>
                        <div className="row-title" style={{ fontWeight: 500, fontSize: 13 }}>
                          {log.device_ua}
                        </div>
                        <div className="row-subtitle">
                          {log.ip} · {log.isp_geo}
                        </div>
                      </div>
                      <div
                        style={{
                          display: "flex",
                          flexDirection: "column",
                          alignItems: "flex-end",
                          gap: 2,
                          width: 68,
                          flexShrink: 0,
                        }}
                      >
                        <span
                          className="mono"
                          style={{
                            fontSize: 11,
                            fontWeight: 600,
                            whiteSpace: "nowrap",
                            color: isBlock ? "var(--color-danger)" : "var(--color-success)",
                          }}
                        >
                          {log.status_label}
                        </span>
                        <span className="mono" style={{ fontSize: 11, color: "var(--color-subtle)", whiteSpace: "nowrap" }}>
                          {formatRelativeTime(log.created_at)}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </aside>
      </div>
      </div>
    </>
  );
}
