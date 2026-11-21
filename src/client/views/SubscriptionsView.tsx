import { useEffect, useRef, useState } from "react";
import type { DashboardSnapshot, SubscriptionItem } from "../../shared/types";
import { formatRelativeTime } from "../icons";

interface Props {
  data: DashboardSnapshot;
  busy: boolean;
  onOpenAddSub: () => void;
  onSyncAll: () => void;
  onSyncSingle: (id: string) => Promise<void>;
  onSyncGroupsFromSub: (id: string, replaceGroups: boolean, syncRules: boolean) => Promise<void>;
  onUpdateSub: (
    id: string,
    payload: {
      name: string;
      url: string;
      fetch_ua: string;
      fetch_proxy: string;
      note: string;
      inline_content?: string;
      enabled?: boolean;
    }
  ) => Promise<void>;
  onToggleSub: (id: string, enabled: boolean) => void;
  onDeleteSub: (id: string) => void;
}

export function SubscriptionsView({
  data,
  busy,
  onOpenAddSub,
  onSyncAll,
  onSyncSingle,
  onSyncGroupsFromSub,
  onUpdateSub,
  onToggleSub,
  onDeleteSub,
}: Props) {
  const [selectedId, setSelectedId] = useState<string>(data.subscriptions[0]?.id || "");
  const selectedSub: SubscriptionItem | undefined =
    data.subscriptions.find((s) => s.id === selectedId) || data.subscriptions[0];

  const [editName, setEditName] = useState("");
  const [editUrl, setEditUrl] = useState("");
  const [showUrl, setShowUrl] = useState(false);
  const [editUa, setEditUa] = useState("auto");
  const [editProxy, setEditProxy] = useState("");
  const [showProxy, setShowProxy] = useState(false);
  const [showEditAdvanced, setShowEditAdvanced] = useState(false);
  const [editNote, setEditNote] = useState("");
  const [showRawEditor, setShowRawEditor] = useState(false);
  const [editRawContent, setEditRawContent] = useState("");
  const detailRailRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (selectedSub) {
      setSelectedId(selectedSub.id);
      setEditName(selectedSub.name);
      setEditUrl(selectedSub.url.startsWith("local://") ? "" : selectedSub.url);
      setShowUrl(false);
      setEditUa(selectedSub.fetch_ua || "auto");
      setEditProxy(selectedSub.fetch_proxy || "");
      setShowProxy(false);
      setShowEditAdvanced(Boolean(selectedSub.fetch_proxy));
      setEditNote(selectedSub.note || "");
      setEditRawContent(selectedSub.inline_content || "");
      setShowRawEditor(false);
      detailRailRef.current?.scrollTo({ top: 0 });
    }
  }, [selectedSub?.id]);

  const sourceNodes = selectedSub ? data.nodes.filter((n) => n.sub_id === selectedSub.id) : [];
  const activeSourceNodes = sourceNodes.filter((n) => n.status === "active");
  const filteredSourceNodes = sourceNodes.filter((n) => n.status !== "active");

  const hasEmbeddedGroupsOrRules = selectedSub
    ? selectedSub.inline_content.includes("[Proxy Group]") ||
      selectedSub.inline_content.includes("proxy-groups:") ||
      selectedSub.inline_content.includes("[Rule]") ||
      selectedSub.inline_content.includes("rules:")
    : false;

  return (
    <>
      <div className="top-bar">
        <div style={{ minWidth: 220 }}>
          <h1 className="page-title">订阅源管理</h1>
          <p className="page-subtitle">
            管理远程机场订阅链接与本地导入配置，支持单源独立更新、UA 策略调整与源节点透视
          </p>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          {data.subscriptions.length > 0 && (
            <button type="button" className="btn" disabled={busy} onClick={onSyncAll}>
              {busy ? "正在同步…" : "全量更新全部订阅"}
            </button>
          )}
          <button type="button" className="btn btn-primary" onClick={onOpenAddSub}>
            + 新增订阅源 / 导入文件
          </button>
        </div>
      </div>

      {data.subscriptions.length === 0 ? (
        <div className="view-scroll-body" style={{ padding: 32 }}>
          <div
            style={{
              padding: "48px 24px",
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
            <div style={{ fontSize: 16, fontWeight: 600 }}>尚未添加任何订阅源</div>
            <div style={{ fontSize: 13, color: "var(--color-muted)", maxWidth: 460 }}>
              支持接入远程机场订阅链接（自动识别 Clash.Meta / Surge / Base64 协议与流量响应头），或上传本地配置文件。
            </div>
            <button type="button" className="btn btn-primary" onClick={onOpenAddSub}>
              + 新增首个订阅源
            </button>
          </div>
        </div>
      ) : (
        <div className="sub-studio-split">
          {/* Left Master List: All Subscriptions */}
          <div className="primary-column" style={{ gap: 16 }}>
            <div className="section-header">
              <span className="section-title" style={{ fontSize: 15 }}>
                已接入订阅列表 ({data.subscriptions.length})
              </span>
              <span className="mono" style={{ fontSize: 11, color: "var(--color-muted)" }}>
                点击任意行在右侧查看节点与编辑参数
              </span>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {data.subscriptions.map((sub) => {
                const isSelected = selectedSub?.id === sub.id;
                const hasQuota = !sub.is_unlimited && sub.total_gb > 0;
                const ratio = hasQuota
                  ? Math.min(100, Math.round((sub.used_gb / Math.max(0.1, sub.total_gb)) * 100))
                  : 0;
                const isLocal = sub.url.startsWith("local://");

                return (
                  <div
                    key={sub.id}
                    onClick={() => setSelectedId(sub.id)}
                    style={{
                      padding: "16px 18px",
                      borderRadius: 11,
                      cursor: "pointer",
                      background: isSelected ? "var(--color-primary-soft)" : "var(--color-card)",
                      border: isSelected ? "1px solid var(--color-primary-border)" : "1px solid var(--color-border)",
                      opacity: sub.enabled ? 1 : 0.65,
                      display: "flex",
                      flexDirection: "column",
                      gap: 10,
                      transition: "border-color 0.14s ease, background-color 0.14s ease",
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0 }}>
                        <span
                          style={{
                            width: 8,
                            height: 8,
                            borderRadius: 999,
                            flexShrink: 0,
                            background: !sub.enabled
                              ? "var(--color-subtle)"
                              : sub.last_status.includes("失败") || sub.last_status.startsWith("HTTP 4")
                                ? "var(--color-danger)"
                                : "var(--color-success)",
                          }}
                        />
                        <span className="row-title" style={{ fontSize: 15 }}>
                          {sub.name}
                        </span>
                        <span className="badge">{isLocal ? "本地配置" : `UA: ${sub.fetch_ua}`}</span>
                        {sub.fetch_proxy && <span className="badge badge-primary">SOCKS/HTTP 代理</span>}
                      </div>

                      <div
                        style={{ display: "flex", alignItems: "center", gap: 10, flexShrink: 0 }}
                        onClick={(e) => e.stopPropagation()}
                      >
                        <span className="mono" style={{ fontSize: 12, color: "var(--color-muted)" }}>
                          {sub.enabled ? sub.last_status : "已暂停"}
                        </span>
                        <button
                          type="button"
                          className={`switch ${sub.enabled ? "on" : ""}`}
                          onClick={() => onToggleSub(sub.id, !sub.enabled)}
                          title={sub.enabled ? "暂停此订阅源" : "启用此订阅源"}
                        >
                          <span className="switch-thumb" />
                        </button>
                      </div>
                    </div>

                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        gap: 14,
                        flexWrap: "wrap",
                      }}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
                        <span className="mono" style={{ fontSize: 12, fontWeight: 600, color: "var(--color-ink)" }}>
                          有效 {sub.valid_node_count} / 原始 {sub.raw_node_count} 节点
                        </span>
                        <span style={{ color: "var(--color-border)" }}>|</span>
                        <span className="row-subtitle">{sub.protocol_hint || "自动协议识别"}</span>
                      </div>

                      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                        {sub.regions.slice(0, 5).map((rg) => (
                          <span key={rg} className="badge" style={{ background: "var(--color-card)" }}>
                            {rg}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 16 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 10, flex: 1, maxWidth: 260 }}>
                        <div className="progress-track" style={{ flex: 1 }}>
                          <div
                            className="progress-fill"
                            style={{
                              width: `${hasQuota ? ratio : 100}%`,
                              opacity: hasQuota ? 1 : 0.25,
                              background: ratio >= 85 ? "var(--color-warning)" : "var(--color-primary)",
                            }}
                          />
                        </div>
                        <span className="mono" style={{ fontSize: 11, color: "var(--color-muted)", whiteSpace: "nowrap" }}>
                          {hasQuota ? `${sub.used_gb} / ${sub.total_gb} GB` : "不限配额"}
                        </span>
                      </div>

                      <span className="mono" style={{ fontSize: 11, color: "var(--color-subtle)", whiteSpace: "nowrap" }}>
                        {sub.expire_at
                          ? `到期 ${new Date(sub.expire_at).toISOString().slice(0, 10)} · `
                          : ""}
                        更新于 {formatRelativeTime(sub.last_sync_at)}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right Detail & Editor Inspector */}
          {selectedSub && (
            <aside ref={detailRailRef} className="sub-detail-rail">
              <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                  <span style={{ fontSize: 15, fontWeight: 600, whiteSpace: "nowrap" }}>编辑订阅源配置</span>
                  <div style={{ display: "flex", gap: 6 }}>
                    {!selectedSub.url.startsWith("local://") && (
                      <button
                        type="button"
                        className="btn btn-sm"
                        disabled={busy}
                        onClick={() => onSyncSingle(selectedSub.id)}
                      >
                        单独拉取更新
                      </button>
                    )}
                    <button
                      type="button"
                      className="btn btn-sm"
                      style={{ color: "var(--color-danger)", borderColor: "var(--color-danger-border)" }}
                      disabled={busy}
                      onClick={() => {
                        if (window.confirm(`确定移除订阅源「${selectedSub.name}」及其节点吗？`)) {
                          onDeleteSub(selectedSub.id);
                        }
                      }}
                    >
                      删除
                    </button>
                  </div>
                </div>

                <div className="surface-card" style={{ gap: 10 }}>
                  <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                    <span className="mono" style={{ fontSize: 11, color: "var(--color-subtle)" }}>
                      订阅名称
                    </span>
                    <input
                      className="input"
                      value={editName}
                      onChange={(e) => setEditName(e.target.value)}
                    />
                  </div>

                  <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                      <span className="mono" style={{ fontSize: 11, color: "var(--color-subtle)" }}>
                        远程订阅地址 URL（本地导入可留空或绑定新 URL）
                      </span>
                      {editUrl && (
                        <button
                          type="button"
                          className="link-btn"
                          style={{ fontSize: 11 }}
                          onClick={() => setShowUrl((v) => !v)}
                        >
                          {showUrl ? "隐藏" : "显示"}
                        </button>
                      )}
                    </div>
                    <input
                      type={showUrl ? "text" : "password"}
                      className="input mono"
                      style={{ fontSize: 12 }}
                      placeholder="https://..."
                      value={editUrl}
                      onChange={(e) => setEditUrl(e.target.value)}
                    />
                  </div>

                  <div style={{ display: "flex", gap: 8 }}>
                    <div style={{ display: "flex", flexDirection: "column", gap: 4, width: 165 }}>
                      <span className="mono" style={{ fontSize: 11, color: "var(--color-subtle)" }}>
                        拉取 User-Agent
                      </span>
                      <select
                        className="select mono"
                        value={editUa}
                        onChange={(e) => setEditUa(e.target.value)}
                      >
                        <option value="auto">自动探测</option>
                        <option value="clash">Clash.Meta</option>
                        <option value="stash">Stash iOS</option>
                        <option value="surge6">Surge 6 macOS</option>
                        <option value="surge">Surge macOS</option>
                        <option value="v2ray">V2Ray Base64</option>
                      </select>
                    </div>

                    <div style={{ display: "flex", flexDirection: "column", gap: 4, flex: 1 }}>
                      <span className="mono" style={{ fontSize: 11, color: "var(--color-subtle)" }}>
                        备注说明
                      </span>
                      <input
                        className="input"
                        placeholder="如 主力专线 / 备用包"
                        value={editNote}
                        onChange={(e) => setEditNote(e.target.value)}
                      />
                    </div>
                  </div>

                  <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                      <button
                        type="button"
                        className="link-btn"
                        onClick={() => setShowEditAdvanced((v) => !v)}
                      >
                        {showEditAdvanced
                          ? "▾ 收起高级配置（前置代理）"
                          : "▸ 高级配置（前置 SOCKS5 / HTTP 代理拉取）"}
                      </button>
                      {editProxy && showEditAdvanced && (
                        <button
                          type="button"
                          className="link-btn"
                          style={{ fontSize: 11 }}
                          onClick={() => setShowProxy((v) => !v)}
                        >
                          {showProxy ? "隐藏代理" : "显示代理"}
                        </button>
                      )}
                    </div>
                    {showEditAdvanced && (
                      <input
                        type={showProxy || !selectedSub.fetch_proxy ? "text" : "password"}
                        className="input mono"
                        style={{ fontSize: 12 }}
                        placeholder="socks5://user:pass@host:port 或 host:port:user:pass（留空则直连）"
                        value={editProxy}
                        onChange={(e) => setEditProxy(e.target.value)}
                      />
                    )}
                  </div>

                  <div>
                    <button
                      type="button"
                      className="link-btn"
                      onClick={() => setShowRawEditor((v) => !v)}
                    >
                      {showRawEditor
                        ? "收起原始配置内容"
                        : `查看 / 编辑缓存原始配置 (${(selectedSub.inline_content.length / 1024).toFixed(1)} KB)`}
                    </button>
                    {showRawEditor && (
                      <textarea
                        className="textarea mono"
                        style={{ marginTop: 8, fontSize: 11 }}
                        rows={7}
                        value={editRawContent}
                        onChange={(e) => setEditRawContent(e.target.value)}
                      />
                    )}
                  </div>

                  <button
                    type="button"
                    className="btn btn-primary btn-sm"
                    disabled={busy || !editName.trim()}
                    onClick={() =>
                      onUpdateSub(selectedSub.id, {
                        name: editName,
                        url: editUrl.trim() || "local://imported-file",
                        fetch_ua: editUa,
                        fetch_proxy: editProxy.trim(),
                        note: editNote,
                        ...(showRawEditor ? { inline_content: editRawContent } : {}),
                      })
                    }
                  >
                    保存订阅源修改并重算节点
                  </button>
                </div>

                {hasEmbeddedGroupsOrRules && (
                  <div className="surface-card" style={{ gap: 8, background: "var(--color-primary-soft)", borderColor: "var(--color-primary-border)" }}>
                    <div style={{ fontSize: 13, fontWeight: 600, color: "var(--color-primary)" }}>
                      检测到该配置内含策略组与分流规则
                    </div>
                    <div style={{ fontSize: 12, color: "var(--color-muted)" }}>
                      可从该配置重新提取策略组（自动识别子策略嵌套与节点筛选规则）：
                    </div>
                    <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                      <button
                        type="button"
                        className="btn btn-sm"
                        disabled={busy}
                        onClick={() => onSyncGroupsFromSub(selectedSub.id, false, false)}
                      >
                        合并更新策略组
                      </button>
                      <button
                        type="button"
                        className="btn btn-sm btn-primary"
                        disabled={busy}
                        onClick={() => {
                          if (window.confirm(`确定以「${selectedSub.name}」中的策略组覆盖替换现有策略组列表吗？（现有规则将保留）`)) {
                            onSyncGroupsFromSub(selectedSub.id, true, false);
                          }
                        }}
                      >
                        以此源覆盖重建策略组
                      </button>
                    </div>
                  </div>
                )}
              </div>

              {/* Source Nodes Breakdown */}
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <span style={{ fontSize: 14, fontWeight: 600 }}>
                    该订阅源解析节点 ({sourceNodes.length})
                  </span>
                  <span className="mono" style={{ fontSize: 11, color: "var(--color-muted)" }}>
                    可用 {activeSourceNodes.length} · 剔除/合并 {filteredSourceNodes.length}
                  </span>
                </div>

                <div
                  className="surface-card"
                  style={{ maxHeight: 320, overflowY: "auto", padding: "6px 12px", gap: 0 }}
                >
                  {sourceNodes.length === 0 ? (
                    <div style={{ padding: "16px 0", fontSize: 12, color: "var(--color-muted)", textAlign: "center" }}>
                      {selectedSub.enabled ? "未解析到节点" : "该订阅源当前已暂停"}
                    </div>
                  ) : (
                    sourceNodes.map((n) => {
                      const isAct = n.status === "active";
                      return (
                        <div
                          key={n.id}
                          style={{
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "space-between",
                            gap: 8,
                            padding: "8px 0",
                            borderBottom: "1px solid var(--color-border)",
                            opacity: isAct ? 1 : 0.6,
                          }}
                        >
                          <div style={{ display: "flex", flexDirection: "column", gap: 1, minWidth: 0, flex: 1 }}>
                            <span
                              className="truncate"
                              style={{
                                fontSize: 12.5,
                                fontWeight: 600,
                                textDecoration: isAct ? "none" : "line-through",
                              }}
                            >
                              {isAct ? n.normalized_name : n.raw_name}
                            </span>
                            <span className="row-subtitle" style={{ fontSize: 10.5 }}>
                              {isAct ? `原名: ${n.raw_name}` : n.filter_reason}
                            </span>
                          </div>
                          <span className="badge mono" style={{ fontSize: 10 }}>
                            {n.protocol}
                          </span>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            </aside>
          )}
        </div>
      )}
    </>
  );
}
