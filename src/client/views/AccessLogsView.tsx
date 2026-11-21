import { useEffect, useState } from "react";
import { deriveRuleSetSignature } from "../../shared/hmac";
import type { DashboardSnapshot } from "../../shared/types";
import { formatRelativeTime } from "../icons";

interface Props {
  data: DashboardSnapshot;
  busy: boolean;
  onRotateToken: () => Promise<void>;
  onUpdateSubToken: (subToken: string) => Promise<void>;
  onRotateMcpToken: () => Promise<void>;
  onUpdateMcpToken: (mcpToken: string) => Promise<void>;
  onToggleUaGuard: (enabled: boolean) => Promise<void>;
  onToggleStrictUa: (enabled: boolean) => Promise<void>;
  onResetAll: () => Promise<void>;
  onRefresh: () => Promise<void>;
  onNotify: (msg: string) => void;
}

export function AccessLogsView({
  data,
  busy,
  onRotateToken,
  onUpdateSubToken,
  onRotateMcpToken,
  onUpdateMcpToken,
  onToggleUaGuard,
  onToggleStrictUa,
  onResetAll,
  onNotify,
}: Props) {
  const [filter, setFilter] = useState<"ALL" | "SURGE" | "STASH" | "CLASH" | "BROWSER" | "BLOCK">("ALL");
  const [tokenInput, setTokenInput] = useState(data.settings.sub_token);
  const [showToken, setShowToken] = useState(false);
  const [mcpTokenInput, setMcpTokenInput] = useState(data.settings.mcp_token);
  const [showMcpToken, setShowMcpToken] = useState(false);
  const [showCfGuide, setShowCfGuide] = useState(false);

  useEffect(() => {
    setTokenInput(data.settings.sub_token);
  }, [data.settings.sub_token]);

  useEffect(() => {
    setMcpTokenInput(data.settings.mcp_token);
  }, [data.settings.mcp_token]);

  const filteredLogs = data.access_logs.filter((l) => {
    if (filter === "ALL") return true;
    if (filter === "BLOCK") return l.status_code >= 400;
    return l.client_tag === filter;
  });

  const isTokenDirty = tokenInput.trim() !== data.settings.sub_token;
  const isTokenValid =
    tokenInput.trim().length >= 12 &&
    tokenInput.trim().length <= 128 &&
    /^[A-Za-z0-9_-]+$/.test(tokenInput.trim());

  const isMcpTokenDirty = mcpTokenInput.trim() !== data.settings.mcp_token;
  const isMcpTokenValid =
    mcpTokenInput.trim().length >= 12 &&
    mcpTokenInput.trim().length <= 128 &&
    /^[A-Za-z0-9_-]+$/.test(mcpTokenInput.trim());

  const origin = typeof window !== "undefined" ? window.location.origin : "http://127.0.0.1:8787";
  const mcpEndpointUrl = `${origin}/mcp`;
  const mcpConfigJson = JSON.stringify(
    {
      mcpServers: {
        tower: {
          url: mcpEndpointUrl,
          headers: {
            Authorization: `Bearer ${data.settings.mcp_token}`,
          },
        },
      },
    },
    null,
    2
  );
  const sampleSig = deriveRuleSetSignature(data.settings.sub_token, "ai-suite.list");
  const sampleSignedRuleUrl = `${origin}/r/ai-suite.list?sig=${sampleSig}`;

  const copyText = async (text: string, label: string) => {
    await navigator.clipboard.writeText(text);
    onNotify(`已复制 ${label}`);
  };

  return (
    <>
      <div className="top-bar">
        <div style={{ minWidth: 220 }}>
          <h1 className="page-title">访问记录与边缘鉴权保护</h1>
          <p className="page-subtitle">
            Cloudflare Access 零信任控制面鉴权、可轮转订阅 Token 与 /r/* 规则集 HMAC 派生签名审计
          </p>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <button
            type="button"
            className="btn btn-primary"
            disabled={busy}
            onClick={() => {
              if (window.confirm("确定立即随机轮换订阅 Token 吗？旧订阅链接与旧规则签名将同步失效。")) {
                onRotateToken();
              }
            }}
          >
            随机轮换订阅 Token
          </button>
        </div>
      </div>

      <div className="view-scroll-body">
        <div className="workspace-split">
          <div className="primary-column" style={{ gap: 18 }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {(["ALL", "SURGE", "STASH", "CLASH", "BROWSER", "BLOCK"] as const).map((tab) => (
                  <button
                    key={tab}
                    type="button"
                    className={`filter-chip mono ${filter === tab ? "active" : ""}`}
                    onClick={() => setFilter(tab)}
                  >
                    {tab === "ALL" ? `全部记录 ${data.access_logs.length}` : tab}
                  </button>
                ))}
              </div>
              <span className="mono" style={{ fontSize: 11, color: "var(--color-muted)", whiteSpace: "nowrap" }}>
                未授权请求统一伪装返回 404 · 防缓存头已开启
              </span>
            </div>

            {filteredLogs.length === 0 ? (
              <div
                style={{
                  padding: "40px 24px",
                  borderRadius: 12,
                  border: "1px dashed var(--color-border)",
                  background: "var(--color-surface)",
                  textAlign: "center",
                  color: "var(--color-muted)",
                  fontSize: 13,
                }}
              >
                暂无匹配的真实拉取记录。当你在 Surge、Stash 或浏览器访问统一订阅或规则集链接时，请求会自动审计在此处。
              </div>
            ) : (
              <div className="hairline-list">
                <div className="table-header-row desktop-only">
                  <div style={{ width: 68, flexShrink: 0 }}>CLIENT</div>
                  <div style={{ flex: 1, minWidth: 160 }}>USER-AGENT / 终端标识</div>
                  <div className="col-opt-lg" style={{ width: 210, flexShrink: 0 }}>
                    来源 IP &amp; 审计结果
                  </div>
                  <div className="col-opt-md" style={{ width: 72, flexShrink: 0, textAlign: "right" }}>
                    耗时
                  </div>
                  <div style={{ width: 96, flexShrink: 0, textAlign: "right" }}>状态 / 时间</div>
                </div>

                {filteredLogs.map((log) => {
                  const isBlock = log.status_code >= 400;
                  const badgeClass =
                    log.client_tag === "SURGE"
                      ? "badge badge-primary"
                      : isBlock
                        ? "badge badge-danger"
                        : "badge";
                  const badgeText =
                    log.client_tag === "SURGE" && log.target_format === "surge6" ? "SURGE 6" : log.client_tag;
                  return (
                    <div key={log.id} className="hairline-row">
                      <div style={{ width: 68, flexShrink: 0 }}>
                        <span className={badgeClass} style={{ width: "100%" }}>
                          {badgeText}
                        </span>
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", gap: 2, flex: "1 1 160px", minWidth: 0 }}>
                        <span className="row-title" style={{ fontSize: 13 }}>
                          {log.device_ua}
                        </span>
                        <span className="row-subtitle mobile-only">
                          {log.ip} · {log.isp_geo}
                        </span>
                      </div>
                      <div
                        className="mono desktop-only col-opt-lg truncate"
                        style={{ width: 210, flexShrink: 0, fontSize: 12, color: "var(--color-muted)" }}
                        title={`${log.ip} · ${log.isp_geo}`}
                      >
                        {log.ip} · {log.isp_geo}
                      </div>
                      <div
                        className="mono desktop-only col-opt-md"
                        style={{ width: 72, flexShrink: 0, textAlign: "right", fontSize: 12, color: "var(--color-muted)", whiteSpace: "nowrap" }}
                      >
                        {log.latency_ms} ms
                      </div>
                      <div
                        style={{
                          width: 96,
                          flexShrink: 0,
                          display: "flex",
                          flexDirection: "column",
                          alignItems: "flex-end",
                          gap: 2,
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

          <aside className="secondary-rail" style={{ gap: 22 }}>
            {/* Card 1: Cloudflare Access Control Plane Status */}
            <div style={{ display: "flex", flexDirection: "column", gap: 10, minWidth: 0 }}>
              <span style={{ fontSize: 15, fontWeight: 600 }}>控制面鉴权 (Cloudflare Access)</span>
              <div className="surface-card" style={{ gap: 10 }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                  <span style={{ fontSize: 13, fontWeight: 600 }}>
                    {data.auth?.mode === "cf_access" ? "Zero Trust JWT 验签已生效" : "本地开发模式 (Localhost)"}
                  </span>
                  <span className={`badge ${data.auth?.mode === "cf_access" ? "badge-success" : "badge-primary"}`}>
                    {data.auth?.mode === "cf_access" ? "PROTECTED" : "LOCAL DEV"}
                  </span>
                </div>

                {data.auth?.mode === "cf_access" ? (
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, fontSize: 12 }}>
                    <span className="mono truncate" style={{ color: "var(--color-muted)" }}>
                      登录身份：{data.auth.email}
                    </span>
                    {data.auth.logout_url && (
                      <a href={data.auth.logout_url} className="link-btn" style={{ textDecoration: "none" }}>
                        退出登录
                      </a>
                    )}
                  </div>
                ) : (
                  <div style={{ fontSize: 12, color: "var(--color-muted)", lineHeight: "18px" }}>
                    本地 127.0.0.1 自动免密放行；部署公网域名后若未配置 CF_ACCESS_AUD，后端 /api/* 会默认安全锁定拒绝未授权访问。
                  </div>
                )}

                <div>
                  <button type="button" className="link-btn" onClick={() => setShowCfGuide((v) => !v)}>
                    {showCfGuide ? "收起部署配置步骤" : "查看 Cloudflare Access 部署配置清单"}
                  </button>
                  {showCfGuide && (
                    <div
                      style={{
                        marginTop: 8,
                        padding: "10px 12px",
                        borderRadius: 8,
                        background: "var(--color-surface)",
                        border: "1px solid var(--color-border)",
                        fontSize: 11.5,
                        color: "var(--color-muted)",
                        display: "flex",
                        flexDirection: "column",
                        gap: 6,
                        lineHeight: "17px",
                      }}
                    >
                      <div>
                        <strong>1. Zero Trust 建应用</strong>：保护 <span className="mono">你的域名/*</span>，Policy 设为 Allow 你的邮箱或 GitHub；
                      </div>
                      <div>
                        <strong>2. 添加 Bypass 放行订阅与 MCP</strong>：新建子路径策略，将 <span className="mono">/sub/*</span>、<span className="mono">/r/*</span> 与 <span className="mono">/mcp</span> Action 设为 Bypass（Everyone），分别交由 Worker 内部校验订阅 Token、HMAC 签名与 MCP Bearer Token；
                      </div>
                      <div>
                        <strong>3. 注入 Worker 验签密钥</strong>：执行 <span className="mono">npx wrangler secret put CF_ACCESS_TEAM_DOMAIN</span> 与 <span className="mono">npx wrangler secret put CF_ACCESS_AUD</span>。
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Card 2: Rotatable & Editable Subscription Token */}
            <div style={{ display: "flex", flexDirection: "column", gap: 10, minWidth: 0 }}>
              <span style={{ fontSize: 15, fontWeight: 600 }}>可轮转订阅 Token 管理</span>
              <div className="surface-card" style={{ gap: 10 }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                  <span className="mono" style={{ fontSize: 11, color: "var(--color-subtle)" }}>
                    SUBSCRIPTION TOKEN (12~128 位)
                  </span>
                  <div style={{ display: "flex", gap: 10 }}>
                    <button
                      type="button"
                      className="link-btn"
                      style={{ fontSize: 11 }}
                      onClick={() => setShowToken((v) => !v)}
                    >
                      {showToken ? "隐藏" : "显示"}
                    </button>
                    <button
                      type="button"
                      className="link-btn"
                      style={{ fontSize: 11 }}
                      onClick={() => copyText(data.settings.sub_token, "订阅 Token")}
                    >
                      复制
                    </button>
                  </div>
                </div>

                <input
                  type={showToken ? "text" : "password"}
                  className="input mono"
                  style={{ fontSize: 12 }}
                  placeholder="输入 12 位以上自定义字母/数字/连字符"
                  value={tokenInput}
                  onChange={(e) => setTokenInput(e.target.value)}
                />

                {isTokenDirty && !isTokenValid && (
                  <span style={{ fontSize: 11.5, color: "var(--color-danger)" }}>
                    需为 12~128 位大小写字母、数字、下划线或连字符（不含空格与斜杠）
                  </span>
                )}

                <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                  <button
                    type="button"
                    className="btn btn-primary btn-sm"
                    style={{ flex: 1 }}
                    disabled={busy || !isTokenDirty || !isTokenValid}
                    onClick={() => onUpdateSubToken(tokenInput.trim())}
                  >
                    保存自定义 Token
                  </button>
                  <button
                    type="button"
                    className="btn btn-sm"
                    disabled={busy}
                    onClick={() => onRotateToken()}
                  >
                    随机生成高熵 Token
                  </button>
                </div>

                <span style={{ fontSize: 11.5, color: "var(--color-subtle)", lineHeight: "16px" }}>
                  修改或轮换后，旧 /sub/:token 链接与下方 /r/* 规则集 HMAC 派生签名会自动同步失效。
                </span>
              </div>
            </div>

            {/* Card 2.5: Rotatable & Editable Remote MCP Token */}
            <div style={{ display: "flex", flexDirection: "column", gap: 10, minWidth: 0 }}>
              <span style={{ fontSize: 15, fontWeight: 600 }}>远程 MCP Server 鉴权 Token</span>
              <div className="surface-card" style={{ gap: 10 }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                  <span className="mono" style={{ fontSize: 11, color: "var(--color-subtle)" }}>
                    MCP BEARER TOKEN (12~128 位)
                  </span>
                  <div style={{ display: "flex", gap: 10 }}>
                    <button
                      type="button"
                      className="link-btn"
                      style={{ fontSize: 11 }}
                      onClick={() => setShowMcpToken((v) => !v)}
                    >
                      {showMcpToken ? "隐藏" : "显示"}
                    </button>
                    <button
                      type="button"
                      className="link-btn"
                      style={{ fontSize: 11 }}
                      onClick={() => copyText(data.settings.mcp_token, "MCP Token")}
                    >
                      复制
                    </button>
                  </div>
                </div>

                <input
                  type={showMcpToken ? "text" : "password"}
                  className="input mono"
                  style={{ fontSize: 12 }}
                  placeholder="输入 12 位以上自定义字母/数字/连字符"
                  value={mcpTokenInput}
                  onChange={(e) => setMcpTokenInput(e.target.value)}
                />

                {isMcpTokenDirty && !isMcpTokenValid && (
                  <span style={{ fontSize: 11.5, color: "var(--color-danger)" }}>
                    需为 12~128 位大小写字母、数字、下划线或连字符（不含空格与斜杠）
                  </span>
                )}

                <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                  <button
                    type="button"
                    className="btn btn-primary btn-sm"
                    style={{ flex: 1 }}
                    disabled={busy || !isMcpTokenDirty || !isMcpTokenValid}
                    onClick={() => onUpdateMcpToken(mcpTokenInput.trim())}
                  >
                    保存自定义 Token
                  </button>
                  <button
                    type="button"
                    className="btn btn-sm"
                    disabled={busy}
                    onClick={() => {
                      if (window.confirm("确定立即随机轮换 MCP Token 吗？旧客户端 Bearer 凭证将立即失效。")) {
                        onRotateMcpToken();
                      }
                    }}
                  >
                    随机生成高熵 Token
                  </button>
                </div>

                <div
                  style={{
                    paddingTop: 10,
                    borderTop: "1px solid var(--color-border)",
                    display: "flex",
                    flexDirection: "column",
                    gap: 6,
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                    <span className="mono" style={{ fontSize: 11, color: "var(--color-subtle)" }}>
                      STREAMABLE HTTP ENDPOINT
                    </span>
                    <div style={{ display: "flex", gap: 10 }}>
                      <button
                        type="button"
                        className="link-btn"
                        style={{ fontSize: 11 }}
                        onClick={() => copyText(mcpEndpointUrl, "MCP 端点地址")}
                      >
                        复制 URL
                      </button>
                      <button
                        type="button"
                        className="link-btn"
                        style={{ fontSize: 11 }}
                        onClick={() => copyText(mcpConfigJson, "MCP 客户端配置 JSON")}
                      >
                        复制客户端 JSON
                      </button>
                    </div>
                  </div>
                  <div
                    className="mono truncate"
                    style={{
                      fontSize: 11.5,
                      padding: "7px 9px",
                      borderRadius: 6,
                      background: "var(--color-surface)",
                      border: "1px solid var(--color-border)",
                      color: "var(--color-muted)",
                    }}
                    title={mcpEndpointUrl}
                  >
                    {mcpEndpointUrl}
                  </div>
                  <span style={{ fontSize: 11.5, color: "var(--color-subtle)", lineHeight: "16px" }}>
                    在 AI 客户端使用 Authorization: Bearer &lt;MCP Token&gt; 接入，支持策略编排、路由模拟与 Surge / Stash 实时编译。
                  </span>
                </div>
              </div>
            </div>

            {/* Card 3: Subscription & Rule-Set Edge Guards */}
            <div style={{ display: "flex", flexDirection: "column", gap: 10, minWidth: 0 }}>
              <span style={{ fontSize: 15, fontWeight: 600 }}>订阅与规则集边缘安全策略</span>
              <div className="surface-card" style={{ gap: 12 }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
                  <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                    <span style={{ fontSize: 13, fontWeight: 600 }}>爬虫与链接预览机器人拦截</span>
                    <span style={{ fontSize: 12, color: "var(--color-muted)" }}>
                      阻断扫描器及 Telegram / 微信等聊天预览爬虫
                    </span>
                  </div>
                  <button
                    type="button"
                    className={`switch ${data.settings.ua_guard_enabled ? "on" : ""}`}
                    onClick={() => onToggleUaGuard(!data.settings.ua_guard_enabled)}
                  >
                    <span className="switch-thumb" />
                  </button>
                </div>

                <div
                  style={{
                    paddingTop: 10,
                    borderTop: "1px solid var(--color-border)",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 10,
                  }}
                >
                  <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                    <span style={{ fontSize: 13, fontWeight: 600 }}>严格代理客户端 UA 白名单</span>
                    <span style={{ fontSize: 12, color: "var(--color-muted)" }}>
                      仅允许 Surge / Stash / Clash 等客户端拉取，拦截普通浏览器直接打开订阅链接
                    </span>
                  </div>
                  <button
                    type="button"
                    className={`switch ${data.settings.strict_client_ua ? "on" : ""}`}
                    onClick={() => onToggleStrictUa(!data.settings.strict_client_ua)}
                  >
                    <span className="switch-thumb" />
                  </button>
                </div>

                <div
                  style={{
                    paddingTop: 10,
                    borderTop: "1px solid var(--color-border)",
                    display: "flex",
                    flexDirection: "column",
                    gap: 6,
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                    <span style={{ fontSize: 13, fontWeight: 600 }}>规则集 /r/* HMAC 派生签名</span>
                    <span className="badge badge-success">HMAC-SHA256</span>
                  </div>
                  <span style={{ fontSize: 12, color: "var(--color-muted)", lineHeight: "17px" }}>
                    编译产物中的托管 RULE-SET 自动附带单向不可逆签名，无签名或签名失配直接返回 404：
                  </span>
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      gap: 8,
                      padding: "6px 9px",
                      borderRadius: 6,
                      background: "var(--color-surface)",
                      border: "1px solid var(--color-border)",
                    }}
                  >
                    <span className="mono truncate" style={{ fontSize: 11, color: "var(--color-muted)" }}>
                      /r/ai-suite.list?sig={sampleSig.slice(0, 14)}…
                    </span>
                    <button
                      type="button"
                      className="link-btn"
                      style={{ fontSize: 11 }}
                      onClick={() => copyText(sampleSignedRuleUrl, "带签名规则集示例地址")}
                    >
                      复制验证
                    </button>
                  </div>
                </div>

                <div
                  style={{
                    paddingTop: 10,
                    borderTop: "1px solid var(--color-border)",
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    gap: 8,
                  }}
                >
                  <span style={{ fontSize: 12, color: "var(--color-muted)" }}>清空本地数据库全部记录</span>
                  <button
                    type="button"
                    className="btn btn-sm"
                    style={{ color: "var(--color-danger)", borderColor: "var(--color-danger-border)" }}
                    disabled={busy}
                    onClick={() => {
                      if (window.confirm("确定清空本地所有已导入的订阅、节点、规则与日志吗？")) {
                        onResetAll();
                      }
                    }}
                  >
                    清空重置
                  </button>
                </div>
              </div>
            </div>
          </aside>
        </div>
      </div>
    </>
  );
}
