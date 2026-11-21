import { useCallback, useEffect, useRef, useState } from "react";
import type { DashboardSnapshot, SimulationResult } from "../shared/types";
import {
  GlobeIcon,
  GridIcon,
  MonitorIcon,
  MoonIcon,
  PulseIcon,
  RulesIcon,
  StackIcon,
  SunIcon,
  TowerLogo,
} from "./icons";
import { AccessLogsView } from "./views/AccessLogsView";
import { NodePoolView } from "./views/NodePoolView";
import { OverviewView } from "./views/OverviewView";
import { RuleStudioView } from "./views/RuleStudioView";
import { SubscriptionsView } from "./views/SubscriptionsView";

type NavTab = "overview" | "subscriptions" | "nodes" | "rules" | "logs";
type ThemeMode = "light" | "dark" | "system";

export function App() {
  const [tab, setTab] = useState<NavTab>("overview");
  const [themeMode, setThemeMode] = useState<ThemeMode>(() => {
    if (typeof window === "undefined") return "system";
    const saved = localStorage.getItem("tower-theme");
    return saved === "light" || saved === "dark" || saved === "system" ? saved : "system";
  });
  const [data, setData] = useState<DashboardSnapshot | null>(null);
  const [authBlock, setAuthBlock] = useState<{ code: string; message: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [toast, setToast] = useState<string | null>(null);

  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const apply = () => {
      const isDark = themeMode === "dark" || (themeMode === "system" && media.matches);
      document.documentElement.dataset.theme = isDark ? "dark" : "light";
      const metaTheme = document.querySelector('meta[name="theme-color"]');
      if (metaTheme) metaTheme.setAttribute("content", isDark ? "#0b0f17" : "#ffffff");
    };
    apply();
    localStorage.setItem("tower-theme", themeMode);
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, [themeMode]);

  // Real Data Import Modal (only opened via explicit "+ 新增订阅源 / 导入" button!)
  const [showAddSub, setShowAddSub] = useState(false);
  const [subName, setSubName] = useState("");
  const [subUrl, setSubUrl] = useState("");
  const [fetchUa, setFetchUa] = useState("auto");
  const [subProxy, setSubProxy] = useState("");
  const [showAddAdvanced, setShowAddAdvanced] = useState(false);
  const [subHint, setSubHint] = useState("");
  const [subContent, setSubContent] = useState("");
  const [importRules, setImportRules] = useState(true);
  const [importError, setImportError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const notify = useCallback((msg: string) => {
    setToast(msg);
    setTimeout(() => {
      setToast((curr) => (curr === msg ? null : curr));
    }, 2800);
  }, []);

  const fetchBootstrap = useCallback(async () => {
    const res = await fetch("/api/bootstrap");
    if (res.ok) {
      setAuthBlock(null);
      setData(await res.json<DashboardSnapshot>());
    } else if (res.status === 401 || res.status === 403) {
      const errBody = await res.json<{ error?: string; message?: string }>().catch(() => null);
      setAuthBlock({
        code: errBody?.error || "UNAUTHORIZED",
        message: errBody?.message || "管理后台受 Cloudflare Access 零信任网关保护，请先完成身份验证。",
      });
    }
  }, []);

  useEffect(() => {
    fetchBootstrap();
  }, [fetchBootstrap]);

  const runAction = async (url: string, init: RequestInit, successMsg?: string): Promise<boolean> => {
    setBusy(true);
    try {
      const res = await fetch(url, {
        ...init,
        headers: { "content-type": "application/json", ...(init.headers || {}) },
      });
      const payload = await res
        .json<DashboardSnapshot & { error?: string; message?: string }>()
        .catch(() => null);
      if (res.ok && payload && payload.settings) {
        setData(payload);
        if (successMsg) notify(successMsg);
        return true;
      } else {
        const errMsg = payload?.message || payload?.error || `请求失败 (${res.status})`;
        notify(errMsg);
        return false;
      }
    } finally {
      setBusy(false);
    }
  };

  const handleLocalFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    setSubContent(text);
    setImportError(null);
    if (!subName.trim()) {
      setSubName(file.name.replace(/\.(conf|yaml|yml|txt|list)$/i, ""));
    }
    const hasRulesOrGroups =
      text.includes("[Proxy Group]") ||
      text.includes("[Rule]") ||
      text.includes("proxy-groups:") ||
      text.includes("rules:");
    setImportRules(hasRulesOrGroups);
    e.target.value = "";
  };

  if (authBlock) {
    return (
      <div
        style={{
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          padding: 24,
          background: "var(--color-bg)",
        }}
      >
        <div className="modal-panel" style={{ maxWidth: 480 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div className="brand-mark">
              <TowerLogo />
            </div>
            <div>
              <div style={{ fontSize: 16, fontWeight: 600 }}>TOWER · 控制面安全保护</div>
              <div className="mono" style={{ fontSize: 11, color: "var(--color-danger)" }}>
                {authBlock.code}
              </div>
            </div>
          </div>

          <p style={{ margin: 0, fontSize: 13, color: "var(--color-muted)", lineHeight: "20px" }}>
            {authBlock.message}
          </p>

          {authBlock.code === "UNCONFIGURED_CF_ACCESS" && (
            <pre className="code-preview" style={{ fontSize: 11 }}>
              {[
                "# 部署后请注入 Cloudflare Access 团队域名与应用 AUD：",
                "npx wrangler secret put CF_ACCESS_TEAM_DOMAIN",
                "npx wrangler secret put CF_ACCESS_AUD",
              ].join("\n")}
            </pre>
          )}

          <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
            <button type="button" className="btn btn-primary" onClick={() => window.location.reload()}>
              重新验证并刷新
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (!data) {
    return (
      <div
        style={{
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          gap: 10,
          color: "var(--color-muted)",
          fontFamily: "var(--font-mono)",
          fontSize: 13,
        }}
      >
        <div className="brand-mark">
          <TowerLogo />
        </div>
        <span>TOWER · Loading Workspace…</span>
      </div>
    );
  }

  const hasSynced = Boolean(data.settings.last_full_sync_at);
  const minutesSinceSync = hasSynced
    ? Math.max(0, Math.floor((Date.now() - (data.settings.last_full_sync_at || 0)) / 60000))
    : 0;
  const nextSyncIn = hasSynced
    ? Math.max(1, data.settings.cron_interval_min - (minutesSinceSync % data.settings.cron_interval_min))
    : data.settings.cron_interval_min;
  const cronProgress = hasSynced
    ? Math.min(
        96,
        Math.max(10, Math.round(((data.settings.cron_interval_min - nextSyncIn) / data.settings.cron_interval_min) * 100))
      )
    : 0;

  return (
    <div className="app-shell">
      {/* Desktop Left Sidebar */}
      <aside className="sidebar">
        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
          <div className="brand-header">
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <div className="brand-mark">
                <TowerLogo />
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 1 }}>
                <span style={{ fontSize: 15, fontWeight: 600, letterSpacing: "-0.02em", lineHeight: "18px" }}>
                  TOWER
                </span>
                <span
                  className="mono"
                  style={{ fontSize: 11, color: "var(--color-muted)", lineHeight: "14px", whiteSpace: "nowrap" }}
                >
                  EDGE · v{data.settings.revision}
                </span>
              </div>
            </div>
            <span className="live-pill">LIVE</span>
          </div>

          <nav style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <div className="nav-section-label" style={{ paddingTop: 4 }}>
              CONTROL PLANE
            </div>

            <button
              type="button"
              className={`nav-item ${tab === "overview" ? "active" : ""}`}
              onClick={() => setTab("overview")}
            >
              <span className="nav-icon-slot">
                <GridIcon active={tab === "overview"} />
              </span>
              <span className="nav-label">总览控制台</span>
              <span className="nav-count-slot">01</span>
            </button>

            <button
              type="button"
              className={`nav-item ${tab === "subscriptions" ? "active" : ""}`}
              onClick={() => setTab("subscriptions")}
            >
              <span className="nav-icon-slot">
                <StackIcon active={tab === "subscriptions"} />
              </span>
              <span className="nav-label">订阅源管理</span>
              <span className="nav-count-slot">{data.subscriptions.length}</span>
            </button>

            <button
              type="button"
              className={`nav-item ${tab === "nodes" ? "active" : ""}`}
              onClick={() => setTab("nodes")}
            >
              <span className="nav-icon-slot">
                <GlobeIcon active={tab === "nodes"} />
              </span>
              <span className="nav-label">节点整合池</span>
              <span className="nav-count-slot">{data.pipeline.active_total}</span>
            </button>

            <button
              type="button"
              className={`nav-item ${tab === "rules" ? "active" : ""}`}
              onClick={() => setTab("rules")}
            >
              <span className="nav-icon-slot">
                <RulesIcon active={tab === "rules"} />
              </span>
              <span className="nav-label">策略与规则管理</span>
              <span className="nav-count-slot">{data.policy_groups.length}</span>
            </button>

            <button
              type="button"
              className={`nav-item ${tab === "logs" ? "active" : ""}`}
              onClick={() => setTab("logs")}
            >
              <span className="nav-icon-slot">
                <PulseIcon active={tab === "logs"} />
              </span>
              <span className="nav-label">访问与拉取记录</span>
              <span className="nav-count-slot">{data.access_logs.length}</span>
            </button>

            <div className="nav-section-label">DELIVERY</div>
            <a
              href={`/sub/${data.settings.sub_token}?target=surge6`}
              target="_blank"
              rel="noreferrer"
              className="nav-item"
              style={{ textDecoration: "none" }}
            >
              <span className="nav-icon-slot">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                  <rect x="3" y="2.5" width="10" height="11" rx="2" stroke="var(--color-muted)" strokeWidth="1.4" />
                  <path d="M6 6H10M6 9H8.5" stroke="var(--color-muted)" strokeWidth="1.4" strokeLinecap="round" />
                </svg>
              </span>
              <span className="nav-label">Surge 6 配置产物</span>
              <span className="nav-count-slot">v{data.settings.revision}</span>
            </a>
          </nav>
        </div>

        {/* Theme Switcher & Cron Scheduler Footer */}
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <div className="theme-switcher" role="group" aria-label="外观模式切换">
            <button
              type="button"
              className={`theme-switcher-btn ${themeMode === "light" ? "active" : ""}`}
              onClick={() => setThemeMode("light")}
              title="浅色模式"
            >
              <SunIcon />
              <span>浅色</span>
            </button>
            <button
              type="button"
              className={`theme-switcher-btn ${themeMode === "dark" ? "active" : ""}`}
              onClick={() => setThemeMode("dark")}
              title="深色模式"
            >
              <MoonIcon />
              <span>深色</span>
            </button>
            <button
              type="button"
              className={`theme-switcher-btn ${themeMode === "system" ? "active" : ""}`}
              onClick={() => setThemeMode("system")}
              title="跟随系统外观"
            >
              <MonitorIcon />
              <span>自动</span>
            </button>
          </div>

          <div className="scheduler-card">
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span
                style={{
                  width: 7,
                  height: 7,
                  borderRadius: 999,
                  background: data.subscriptions.length > 0 ? "var(--color-success)" : "var(--color-subtle)",
                }}
              />
              <span style={{ fontSize: 12, fontWeight: 600 }}>Worker Cron 引擎</span>
            </div>
            <span className="mono" style={{ fontSize: 11, color: "var(--color-muted)" }}>
              */{data.settings.cron_interval_min}m
            </span>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            <span style={{ fontSize: 12, color: "var(--color-muted)" }}>
              {data.subscriptions.length > 0
                ? `下次自动拉取：${nextSyncIn} 分钟后`
                : "等待接入首个订阅源"}
            </span>
            <div className="progress-track">
              <div
                className="progress-fill"
                style={{ width: `${cronProgress}%`, background: "var(--color-primary)" }}
              />
            </div>
          </div>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="main-area">
        {/* Mobile Top Sticky Header */}
        <header className="mobile-top-header">
          <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
            <div className="brand-mark" style={{ width: 26, height: 26 }}>
              <TowerLogo size={14} />
            </div>
            <span style={{ fontSize: 16, fontWeight: 600, letterSpacing: "-0.02em" }}>TOWER</span>
            <span className="live-pill">LIVE</span>
          </div>
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <button
              type="button"
              className="btn btn-sm"
              style={{ padding: "5px 8px" }}
              onClick={() =>
                setThemeMode((prev) => (prev === "light" ? "dark" : prev === "dark" ? "system" : "light"))
              }
              title={`当前外观：${themeMode === "light" ? "浅色" : themeMode === "dark" ? "深色" : "跟随系统"}`}
            >
              {themeMode === "light" ? <SunIcon /> : themeMode === "dark" ? <MoonIcon /> : <MonitorIcon />}
            </button>
            <button
              type="button"
              className="btn btn-sm btn-ink"
              onClick={() => {
                setImportError(null);
                setShowAddSub(true);
              }}
            >
              + 新增订阅
            </button>
            {data.subscriptions.length > 0 && (
              <button
                type="button"
                className="btn btn-sm"
                disabled={busy}
                onClick={() => runAction("/api/sync", { method: "POST" }, "已完成全量远程同步")}
              >
                {busy ? "同步中" : "同步"}
              </button>
            )}
          </div>
        </header>

        {tab === "overview" && (
          <OverviewView
            data={data}
            busy={busy}
            onSync={() => runAction("/api/sync", { method: "POST" }, "已完成上游订阅全量更新")}
            onOpenAddSub={() => {
              setImportError(null);
              setShowAddSub(true);
            }}
            onToggleSub={(id, enabled) => {
              runAction(
                `/api/subscriptions/${id}`,
                { method: "PATCH", body: JSON.stringify({ enabled }) },
                enabled ? "已启用订阅源并重算节点池" : "已暂停该订阅源"
              );
            }}
            onDeleteSub={(id) => {
              runAction(`/api/subscriptions/${id}`, { method: "DELETE" }, "已移除订阅源");
            }}
            onNavigate={setTab}
            onNotify={notify}
          />
        )}

        {tab === "subscriptions" && (
          <SubscriptionsView
            data={data}
            busy={busy}
            onOpenAddSub={() => {
              setImportError(null);
              setShowAddSub(true);
            }}
            onSyncAll={() => runAction("/api/sync", { method: "POST" }, "已完成全部订阅源拉取与节点重算")}
            onSyncSingle={async (id) => {
              await runAction(`/api/subscriptions/${id}/sync`, { method: "POST" }, "已完成该订阅源单独拉取更新");
            }}
            onSyncGroupsFromSub={async (id, replaceGroups, syncRules) => {
              await runAction(
                `/api/subscriptions/${id}/sync-groups`,
                {
                  method: "POST",
                  body: JSON.stringify({ replace_groups: replaceGroups, sync_rules: syncRules }),
                },
                replaceGroups ? "已使用该订阅源重建策略组关联" : "已从该订阅源同步更新策略组关联"
              );
            }}
            onUpdateSub={async (id, payload) => {
              await runAction(
                `/api/subscriptions/${id}`,
                { method: "PATCH", body: JSON.stringify(payload) },
                "已保存订阅源配置并重新整合节点池"
              );
            }}
            onToggleSub={(id, enabled) => {
              runAction(
                `/api/subscriptions/${id}`,
                { method: "PATCH", body: JSON.stringify({ enabled }) },
                enabled ? "已启用订阅源" : "已暂停订阅源"
              );
            }}
            onDeleteSub={(id) => {
              runAction(`/api/subscriptions/${id}`, { method: "DELETE" }, "已删除订阅源");
            }}
          />
        )}

        {tab === "nodes" && (
          <NodePoolView
            data={data}
            busy={busy}
            onOpenAddSub={() => {
              setImportError(null);
              setShowAddSub(true);
            }}
            onSavePipeline={async (payload) => {
              await runAction(
                "/api/settings",
                { method: "PUT", body: JSON.stringify(payload) },
                "已更新清洗与重命名规则，节点池已重新编译"
              );
            }}
            onProbeLatency={async () => {
              await runAction("/api/nodes/probe", { method: "POST" }, "已完成节点 TCP 握手延迟探测");
            }}
          />
        )}

        {tab === "rules" && (
          <RuleStudioView
            data={data}
            busy={busy}
            onSimulate={async (target): Promise<SimulationResult> => {
              const res = await fetch("/api/simulate", {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({ target }),
              });
              return res.json<SimulationResult>();
            }}
            onScaffoldRules={async () => {
              await runAction(
                "/api/rules/scaffold",
                { method: "POST" },
                "已根据当前可用节点地区生成策略组与标准分流规则"
              );
            }}
            onAddPolicyGroup={async (payload) => {
              await runAction(
                "/api/policy-groups",
                { method: "POST", body: JSON.stringify(payload) },
                "已新建策略组"
              );
            }}
            onUpdatePolicyGroup={async (id, payload) => {
              await runAction(
                `/api/policy-groups/${id}`,
                { method: "PUT", body: JSON.stringify(payload) },
                "已保存策略组配置并同步关联引用"
              );
            }}
            onDeletePolicyGroup={async (id) => {
              await runAction(`/api/policy-groups/${id}`, { method: "DELETE" }, "已移除策略组");
            }}
            onAddRule={async (payload) => {
              await runAction("/api/rules", { method: "POST", body: JSON.stringify(payload) }, "已新增分流规则");
            }}
            onUpdateRule={async (id, payload) => {
              await runAction(`/api/rules/${id}`, { method: "PUT", body: JSON.stringify(payload) }, "已更新分流规则");
            }}
            onPatchRule={async (id, payload) => {
              await runAction(
                `/api/rules/${id}`,
                { method: "PATCH", body: JSON.stringify(payload) },
                payload.target_policy ? `已将规则流向切换至「${payload.target_policy}」` : undefined
              );
            }}
            onDeleteRule={async (id) => {
              await runAction(`/api/rules/${id}`, { method: "DELETE" }, "已删除规则");
            }}
            onPublish={async () => {
              await runAction(
                "/api/publish",
                { method: "POST" },
                `已发布新修订版本 v${data.settings.revision + 1}`
              );
            }}
          />
        )}

        {tab === "logs" && (
          <AccessLogsView
            data={data}
            busy={busy}
            onRotateToken={async () => {
              await runAction(
                "/api/settings/rotate-token",
                { method: "POST" },
                "已随机轮换高熵订阅 Token，旧订阅与旧规则集签名同步失效"
              );
            }}
            onUpdateSubToken={async (subToken) => {
              await runAction(
                "/api/settings/sub-token",
                { method: "PUT", body: JSON.stringify({ sub_token: subToken }) },
                "已更新自定义订阅 Token，规则集 HMAC 签名已同步重算"
              );
            }}
            onRotateMcpToken={async () => {
              await runAction(
                "/api/settings/rotate-mcp-token",
                { method: "POST" },
                "已随机轮换高熵 MCP Token，旧 Bearer 凭证立即失效"
              );
            }}
            onUpdateMcpToken={async (mcpToken) => {
              await runAction(
                "/api/settings/mcp-token",
                { method: "PUT", body: JSON.stringify({ mcp_token: mcpToken }) },
                "已更新自定义 MCP Token"
              );
            }}
            onToggleUaGuard={async (enabled) => {
              await runAction(
                "/api/settings",
                { method: "PUT", body: JSON.stringify({ ua_guard_enabled: enabled }) },
                enabled ? "已开启爬虫与聊天预览 UA 拦截" : "已关闭爬虫与聊天预览 UA 拦截"
              );
            }}
            onToggleStrictUa={async (enabled) => {
              await runAction(
                "/api/settings",
                { method: "PUT", body: JSON.stringify({ strict_client_ua: enabled }) },
                enabled ? "已开启严格代理客户端 UA 白名单" : "已关闭严格客户端 UA 白名单"
              );
            }}
            onResetAll={async () => {
              await runAction("/api/reset", { method: "POST" }, "已清空全部本地数据并重置 Token");
            }}
            onRefresh={fetchBootstrap}
            onNotify={notify}
          />
        )}
      </main>

      {/* Mobile Sticky Bottom Tab Bar (5 Tabs including Subscriptions!) */}
      <nav className="mobile-tab-bar">
        <button
          type="button"
          className={`mobile-tab-item ${tab === "overview" ? "active" : ""}`}
          onClick={() => setTab("overview")}
        >
          <GridIcon active={tab === "overview"} />
          <span>总览</span>
        </button>
        <button
          type="button"
          className={`mobile-tab-item ${tab === "subscriptions" ? "active" : ""}`}
          onClick={() => setTab("subscriptions")}
        >
          <StackIcon active={tab === "subscriptions"} />
          <span>订阅</span>
        </button>
        <button
          type="button"
          className={`mobile-tab-item ${tab === "nodes" ? "active" : ""}`}
          onClick={() => setTab("nodes")}
        >
          <GlobeIcon active={tab === "nodes"} />
          <span>节点</span>
        </button>
        <button
          type="button"
          className={`mobile-tab-item ${tab === "rules" ? "active" : ""}`}
          onClick={() => setTab("rules")}
        >
          <RulesIcon active={tab === "rules"} />
          <span>策略</span>
        </button>
        <button
          type="button"
          className={`mobile-tab-item ${tab === "logs" ? "active" : ""}`}
          onClick={() => setTab("logs")}
        >
          <PulseIcon active={tab === "logs"} />
          <span>记录</span>
        </button>
      </nav>

      {/* Real Data Import Modal */}
      {showAddSub && (
        <div className="modal-backdrop" onClick={() => setShowAddSub(false)}>
          <div className="modal-panel" style={{ maxWidth: 560 }} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
              <div>
                <h3 style={{ margin: 0, fontSize: 17, fontWeight: 600 }}>新增订阅源 / 导入本地配置</h3>
                <p style={{ margin: "3px 0 0", fontSize: 12, color: "var(--color-muted)" }}>
                  支持远程订阅 URL、本地 Surge .conf / Stash &amp; Clash .yaml 文件或节点链接粘贴
                </p>
              </div>
              <input
                ref={fileInputRef}
                type="file"
                accept=".conf,.yaml,.yml,.txt,.list"
                style={{ display: "none" }}
                onChange={handleLocalFileSelect}
              />
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => fileInputRef.current?.click()}
              >
                选择本地文件…
              </button>
            </div>

            {importError && (
              <div
                style={{
                  padding: "9px 12px",
                  borderRadius: 8,
                  background: "var(--color-danger-soft)",
                  color: "var(--color-danger)",
                  fontSize: 12,
                  lineHeight: "17px",
                }}
              >
                {importError}
              </div>
            )}

            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <div style={{ display: "flex", gap: 8 }}>
                <input
                  className="input"
                  style={{ flex: 1 }}
                  placeholder="订阅源名称（必填，如 主力机场 / 本地 Surge 配置）"
                  value={subName}
                  onChange={(e) => setSubName(e.target.value)}
                />
                <select
                  className="select mono"
                  style={{ width: 170 }}
                  value={fetchUa}
                  onChange={(e) => setFetchUa(e.target.value)}
                  title="远程 URL 拉取时使用的客户端 User-Agent"
                >
                  <option value="auto">UA: 自动探测</option>
                  <option value="clash">UA: Clash.Meta</option>
                  <option value="stash">UA: Stash iOS</option>
                  <option value="surge6">UA: Surge 6 (macOS)</option>
                  <option value="surge">UA: Surge macOS</option>
                  <option value="v2ray">UA: V2Ray Base64</option>
                </select>
              </div>

              <input
                className="input mono"
                placeholder="方式 1：填写远程订阅链接 https://... （若直接上传/粘贴本地内容可留空）"
                value={subUrl}
                onChange={(e) => setSubUrl(e.target.value)}
              />

              {/* Advanced Options: SOCKS5 / HTTP Upstream Proxy */}
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <button
                    type="button"
                    className="link-btn"
                    style={{ fontSize: 12 }}
                    onClick={() => setShowAddAdvanced((v) => !v)}
                  >
                    {showAddAdvanced || subProxy
                      ? "▾ 收起高级配置（前置代理请求）"
                      : "▸ 高级配置（使用 SOCKS5 / HTTP 代理请求订阅）"}
                  </button>
                  {subProxy && (
                    <span className="badge badge-primary">已启用前置代理</span>
                  )}
                </div>

                {(showAddAdvanced || Boolean(subProxy)) && (
                  <div
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: 8,
                      padding: "10px 12px",
                      borderRadius: 8,
                      background: "var(--color-surface)",
                      border: "1px solid var(--color-border)",
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, flexWrap: "wrap" }}>
                      <span className="mono" style={{ fontSize: 11, color: "var(--color-muted)" }}>
                        前置 SOCKS5 / HTTP 代理（绕过机场对 CF Worker 机房 IP 的 403 拦截）
                      </span>
                      <div style={{ display: "flex", gap: 8 }}>
                        {data.subscriptions.find((s) => s.fetch_proxy) && (
                          <button
                            type="button"
                            className="link-btn"
                            style={{ fontSize: 11 }}
                            onClick={() => {
                              const existing = data.subscriptions.find((s) => s.fetch_proxy);
                              if (existing) setSubProxy(existing.fetch_proxy);
                            }}
                          >
                            复用已有代理
                          </button>
                        )}
                        {(() => {
                          const poolProxy = data.nodes.find(
                            (n) =>
                              n.status === "active" &&
                              (n.protocol === "SOCKS5" ||
                                (n.protocol === "HTTPS" &&
                                  (n.raw_config?.surge_rhs || "").trim().toLowerCase().startsWith("http,")))
                          );
                          if (!poolProxy) return null;
                          return (
                            <button
                              type="button"
                              className="link-btn"
                              style={{ fontSize: 11 }}
                              onClick={() => {
                                const rhs = poolProxy.raw_config?.surge_rhs || "";
                                const kv: Record<string, string> = {};
                                for (const seg of rhs.split(",").slice(3)) {
                                  const i = seg.indexOf("=");
                                  if (i !== -1) kv[seg.slice(0, i).trim().toLowerCase()] = seg.slice(i + 1).trim();
                                }
                                const scheme = poolProxy.protocol === "SOCKS5" ? "socks5" : "http";
                                const auth = kv.username
                                  ? `${encodeURIComponent(kv.username)}:${encodeURIComponent(kv.password || "")}@`
                                  : "";
                                setSubProxy(`${scheme}://${auth}${poolProxy.server}:${poolProxy.port}`);
                              }}
                            >
                              填入池内节点 ({poolProxy.normalized_name})
                            </button>
                          );
                        })()}
                      </div>
                    </div>

                    <input
                      className="input mono"
                      style={{ background: "var(--color-card)", fontSize: 12 }}
                      placeholder="socks5://user:pass@host:port 或 host:port:user:pass"
                      value={subProxy}
                      onChange={(e) => setSubProxy(e.target.value)}
                    />
                  </div>
                )}
              </div>

              <textarea
                className="textarea mono"
                style={{ fontSize: 12 }}
                rows={7}
                placeholder={
                  "方式 2：点击右上角「选择本地文件…」或在此直接粘贴：\n• Clash / Stash 完整 YAML 或 proxies 列表\n• Surge 完整 .conf 或 [Proxy] 节点行\n• Base64 订阅串 或 ss:// vmess:// vless:// trojan:// hy2:// tuic:// 链接"
                }
                value={subContent}
                onChange={(e) => setSubContent(e.target.value)}
              />

              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
                <label
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                    fontSize: 12,
                    color: "var(--color-ink)",
                    cursor: "pointer",
                  }}
                >
                  <input
                    type="checkbox"
                    checked={importRules}
                    onChange={(e) => setImportRules(e.target.checked)}
                  />
                  <span>若包含 [Proxy Group] / [Rule] 或 proxy-groups / rules，一并导入策略组与规则</span>
                </label>
              </div>
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
              <button type="button" className="btn" onClick={() => setShowAddSub(false)}>
                取消
              </button>
              <button
                type="button"
                className="btn btn-primary"
                disabled={busy || !subName.trim() || (!subUrl.trim() && !subContent.trim())}
                onClick={async () => {
                  setImportError(null);
                  setBusy(true);
                  try {
                    const res = await fetch("/api/subscriptions", {
                      method: "POST",
                      headers: { "content-type": "application/json" },
                      body: JSON.stringify({
                        name: subName,
                        url: subUrl,
                        fetch_ua: fetchUa,
                        fetch_proxy: subProxy,
                        protocol_hint: subHint,
                        inline_content: subContent,
                        import_rules_and_groups: importRules,
                      }),
                    });
                    const payload = await res.json<DashboardSnapshot & { error?: string }>();
                    if (!res.ok) {
                      const errText = payload?.error || "导入失败，请检查订阅地址或配置格式";
                      setImportError(errText);
                      if (errText.includes("403")) {
                        setShowAddAdvanced(true);
                      }
                      return;
                    }
                    setData(payload);
                    notify(`已成功导入「${subName}」`);
                    setSubName("");
                    setSubUrl("");
                    setSubProxy("");
                    setShowAddAdvanced(false);
                    setSubHint("");
                    setSubContent("");
                    setShowAddSub(false);
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                {busy ? "正在拉取解析…" : "确认导入并整合"}
              </button>
            </div>
          </div>
        </div>
      )}

      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}
