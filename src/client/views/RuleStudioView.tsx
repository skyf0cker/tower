import { useEffect, useMemo, useRef, useState } from "react";
import {
  buildRegionRegex,
  getGroupTopology,
  matchNodesForGroup,
  parseSimpleRegionRegex,
} from "../../shared/groupMatcher";
import type { DashboardSnapshot, PolicyGroup, RoutingRule, SimulationResult } from "../../shared/types";
import { SearchIcon } from "../icons";

interface Props {
  data: DashboardSnapshot;
  busy: boolean;
  onSimulate: (target: string) => Promise<SimulationResult>;
  onScaffoldRules: () => Promise<void>;
  onAddPolicyGroup: (payload: {
    name: string;
    type: string;
    filter_regex: string;
    fallback_groups: string[];
  }) => Promise<void>;
  onUpdatePolicyGroup: (
    id: string,
    payload: {
      name: string;
      type: string;
      filter_regex: string;
      fallback_groups: string[];
      interval_sec: number;
      tolerance_ms: number;
    }
  ) => Promise<void>;
  onDeletePolicyGroup: (id: string) => Promise<void>;
  onAddRule: (payload: {
    kind?: "override" | "ruleset";
    rule_type: string;
    title: string;
    payload: string;
    target_policy: string;
    no_resolve?: boolean;
  }) => Promise<void>;
  onUpdateRule: (
    id: string,
    payload: {
      rule_type: string;
      title: string;
      payload: string;
      target_policy: string;
      no_resolve: boolean;
    }
  ) => Promise<void>;
  onPatchRule: (id: string, payload: { enabled?: boolean; target_policy?: string }) => Promise<void>;
  onDeleteRule: (id: string) => Promise<void>;
  onPublish: () => Promise<void>;
}

const RULE_TYPES = [
  "DOMAIN-SUFFIX",
  "DOMAIN-KEYWORD",
  "DOMAIN",
  "IP-CIDR",
  "IP-CIDR6",
  "GEOIP",
  "PROCESS-NAME",
  "RULE-SET",
  "FINAL",
] as const;

export function RuleStudioView({
  data,
  busy,
  onSimulate,
  onScaffoldRules,
  onAddPolicyGroup,
  onUpdatePolicyGroup,
  onDeletePolicyGroup,
  onAddRule,
  onUpdateRule,
  onPatchRule,
  onDeleteRule,
  onPublish,
}: Props) {
  const [studioTab, setStudioTab] = useState<"groups" | "all-rules" | "preview">("groups");

  // Selected group in Master-Detail ("BUILTIN:DIRECT", "BUILTIN:REJECT-DROP", or group.id)
  const [selectedKey, setSelectedKey] = useState<string>(
    data.policy_groups[0]?.id || "BUILTIN:DIRECT"
  );
  const [groupSearch, setGroupSearch] = useState("");

  // Group Editor State
  const selectedGroup: PolicyGroup | undefined = data.policy_groups.find((g) => g.id === selectedKey);
  const selectedBuiltin =
    selectedKey === "BUILTIN:DIRECT"
      ? "DIRECT"
      : selectedKey === "BUILTIN:REJECT-DROP"
        ? "REJECT-DROP"
        : null;

  const [editGName, setEditGName] = useState("");
  const [editGType, setEditGType] = useState<PolicyGroup["type"]>("select");
  const [editGRegex, setEditGRegex] = useState("");
  const [editGSubs, setEditGSubs] = useState<string[]>([]);
  const [editGInterval, setEditGInterval] = useState(300);
  const [editGTolerance, setEditGTolerance] = useState(20);
  const [addSubChoice, setAddSubChoice] = useState("");
  const [showAllMatchedNodes, setShowAllMatchedNodes] = useState(false);

  // Create Group Modal
  const [showCreateGroup, setShowCreateGroup] = useState(false);
  const [createGName, setCreateGName] = useState("");
  const [createGType, setCreateGType] = useState<PolicyGroup["type"]>("select");
  const [createGRegex, setCreateGRegex] = useState("");

  // Rule Add / Inline Edit State
  const [showAddRuleModal, setShowAddRuleModal] = useState(false);
  const [newRType, setNewRType] = useState<string>("DOMAIN-SUFFIX");
  const [newRPayload, setNewRPayload] = useState("");
  const [newRTitle, setNewRTitle] = useState("");
  const [newRTarget, setNewRTarget] = useState(data.policy_groups[0]?.name || "DIRECT");
  const [newRNoResolve, setNewRNoResolve] = useState(false);

  const [editingRuleId, setEditingRuleId] = useState<string | null>(null);
  const [editRType, setEditRType] = useState("");
  const [editRPayload, setEditRPayload] = useState("");
  const [editRTitle, setEditRTitle] = useState("");
  const [editRTarget, setEditRTarget] = useState("");
  const [editRNoResolve, setEditRNoResolve] = useState(false);

  // Search & Pagination for Rules
  const [groupRuleQuery, setGroupRuleQuery] = useState("");
  const [globalRuleQuery, setGlobalRuleQuery] = useState("");
  const [globalRuleTypeFilter, setGlobalRuleTypeFilter] = useState("ALL");
  const [globalVisibleLimit, setGlobalVisibleLimit] = useState(80);

  // Simulator & Preview State
  const [simInput, setSimInput] = useState("openai.com");
  const [simResult, setSimResult] = useState<SimulationResult | null>(null);
  const [previewLang, setPreviewLang] = useState<"surge6" | "surge" | "stash">("surge6");
  const detailScrollRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    detailScrollRef.current?.scrollTo({ top: 0 });
  }, [selectedKey]);

  useEffect(() => {
    if (!selectedBuiltin && !selectedGroup && data.policy_groups.length > 0) {
      setSelectedKey(data.policy_groups[0].id);
    }
  }, [data.policy_groups, selectedBuiltin, selectedGroup]);

  useEffect(() => {
    if (selectedGroup) {
      setEditGName(selectedGroup.name);
      setEditGType(selectedGroup.type);
      setEditGRegex(selectedGroup.filter_regex);
      setEditGSubs(selectedGroup.fallback_groups);
      setEditGInterval(selectedGroup.interval_sec);
      setEditGTolerance(selectedGroup.tolerance_ms);
      setShowAllMatchedNodes(false);
      setGroupRuleQuery("");
    }
  }, [selectedGroup?.id]);

  const policyTargetOptions = useMemo(() => {
    const names = Array.from(new Set(data.policy_groups.map((g) => g.name)));
    return [...names, "DIRECT", "REJECT-DROP"];
  }, [data.policy_groups]);

  const availableRegions = useMemo(() => {
    return Object.entries(data.pipeline.region_counts).sort((a, b) => b[1] - a[1]);
  }, [data.pipeline.region_counts]);

  // Live preview of matched nodes based on current unsaved `editGRegex`!
  const liveMatchedNodes = useMemo(() => {
    if (!selectedGroup) return [];
    return matchNodesForGroup({ filter_regex: editGRegex }, data.nodes);
  }, [selectedGroup, editGRegex, data.nodes]);

  const isGroupDirty =
    selectedGroup &&
    (editGName.trim() !== selectedGroup.name ||
      editGType !== selectedGroup.type ||
      editGRegex !== selectedGroup.filter_regex ||
      editGInterval !== selectedGroup.interval_sec ||
      editGTolerance !== selectedGroup.tolerance_ms ||
      JSON.stringify(editGSubs) !== JSON.stringify(selectedGroup.fallback_groups));

  const parsedRegionPills = parseSimpleRegionRegex(editGRegex);

  const toggleRegionPill = (rg: string) => {
    const current = parsedRegionPills ?? [];
    const next = current.includes(rg) ? current.filter((x) => x !== rg) : [...current, rg];
    setEditGRegex(buildRegionRegex(next));
  };

  // Precompute topologies for left master list badges
  const groupStatsMap = useMemo(() => {
    const map = new Map<string, ReturnType<typeof getGroupTopology>>();
    for (const g of data.policy_groups) {
      map.set(g.id, getGroupTopology(g, data.policy_groups, data.rules, data.nodes));
    }
    return map;
  }, [data.policy_groups, data.rules, data.nodes]);

  const directRules = useMemo(
    () => data.rules.filter((r) => r.target_policy === "DIRECT"),
    [data.rules]
  );
  const rejectRules = useMemo(
    () => data.rules.filter((r) => r.target_policy.startsWith("REJECT")),
    [data.rules]
  );

  const currentTargetName = selectedGroup ? selectedGroup.name : selectedBuiltin || "DIRECT";
  const currentLinkedRules = useMemo(() => {
    const list = selectedGroup
      ? data.rules.filter((r) => r.target_policy === selectedGroup.name)
      : selectedBuiltin === "DIRECT"
        ? directRules
        : rejectRules;
    if (!groupRuleQuery.trim()) return list;
    const q = groupRuleQuery.toLowerCase();
    return list.filter(
      (r) =>
        r.payload.toLowerCase().includes(q) ||
        r.title.toLowerCase().includes(q) ||
        r.rule_type.toLowerCase().includes(q)
    );
  }, [selectedGroup, selectedBuiltin, data.rules, directRules, rejectRules, groupRuleQuery]);

  const currentParentGroups = useMemo(() => {
    if (!selectedGroup) return [];
    return data.policy_groups.filter(
      (g) => g.id !== selectedGroup.id && g.fallback_groups.includes(selectedGroup.name)
    );
  }, [selectedGroup, data.policy_groups]);

  const filteredMasterGroups = data.policy_groups.filter((g) =>
    groupSearch.trim() ? g.name.toLowerCase().includes(groupSearch.toLowerCase()) : true
  );

  const filteredGlobalRules = useMemo(() => {
    return data.rules.filter((r) => {
      if (globalRuleTypeFilter === "OVERRIDE" && r.kind !== "override") return false;
      if (globalRuleTypeFilter === "RULESET" && r.rule_type !== "RULE-SET") return false;
      if (globalRuleTypeFilter === "GEO_FINAL" && r.rule_type !== "GEOIP" && r.rule_type !== "FINAL")
        return false;
      if (globalRuleQuery.trim()) {
        const q = globalRuleQuery.toLowerCase();
        return (
          r.payload.toLowerCase().includes(q) ||
          r.title.toLowerCase().includes(q) ||
          r.target_policy.toLowerCase().includes(q) ||
          r.rule_type.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [data.rules, globalRuleTypeFilter, globalRuleQuery]);

  const startEditingRule = (r: RoutingRule) => {
    setEditingRuleId(r.id);
    setEditRType(r.rule_type);
    setEditRPayload(r.payload);
    setEditRTitle(r.title);
    setEditRTarget(r.target_policy);
    setEditRNoResolve(r.no_resolve);
  };

  const openAddRuleForTarget = (targetPolicy: string) => {
    setNewRType("DOMAIN-SUFFIX");
    setNewRPayload("");
    setNewRTitle("");
    setNewRTarget(targetPolicy);
    setNewRNoResolve(false);
    setShowAddRuleModal(true);
  };

  const renderRuleRow = (r: RoutingRule, idxLabel: string) => {
    const isEditing = editingRuleId === r.id;
    if (isEditing) {
      return (
        <div
          key={r.id}
          className="surface-card"
          style={{ margin: "8px 0", background: "var(--color-surface)", gap: 10 }}
        >
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <select
              className="select mono"
              style={{ width: 156, background: "var(--color-card)" }}
              value={editRType}
              onChange={(e) => setEditRType(e.target.value)}
            >
              {RULE_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
            <input
              className="input mono"
              style={{ flex: 1, minWidth: 180, background: "var(--color-card)" }}
              placeholder={
                editRType === "FINAL"
                  ? "可选参数，留空默认 dns-failed"
                  : "域名 / CIDR / Rule-Set URL"
              }
              value={editRPayload}
              onChange={(e) => setEditRPayload(e.target.value)}
            />
            <select
              className="select mono"
              style={{ width: 165, background: "var(--color-card)" }}
              value={editRTarget}
              onChange={(e) => setEditRTarget(e.target.value)}
            >
              {policyTargetOptions.map((p) => (
                <option key={p} value={p}>
                  → {p}
                </option>
              ))}
            </select>
          </div>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 12, flex: 1, minWidth: 200 }}>
              <input
                className="input"
                style={{ flex: 1, background: "var(--color-card)" }}
                placeholder="规则备注名称"
                value={editRTitle}
                onChange={(e) => setEditRTitle(e.target.value)}
              />
              <label style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 12, whiteSpace: "nowrap" }}>
                <input
                  type="checkbox"
                  checked={editRNoResolve}
                  onChange={(e) => setEditRNoResolve(e.target.checked)}
                />
                <span>no-resolve</span>
              </label>
            </div>
            <div style={{ display: "flex", gap: 6 }}>
              <button type="button" className="btn btn-sm" onClick={() => setEditingRuleId(null)}>
                取消
              </button>
              <button
                type="button"
                className="btn btn-sm btn-primary"
                disabled={busy || (editRType !== "FINAL" && !editRPayload.trim())}
                onClick={async () => {
                  await onUpdateRule(r.id, {
                    rule_type: editRType,
                    payload: editRPayload.trim() || (editRType === "FINAL" ? "dns-failed" : ""),
                    title: editRTitle,
                    target_policy: editRTarget,
                    no_resolve: editRNoResolve,
                  });
                  setEditingRuleId(null);
                }}
              >
                保存规则
              </button>
            </div>
          </div>
        </div>
      );
    }

    return (
      <div key={r.id} className="hairline-row" style={{ padding: "10px 0", opacity: r.enabled ? 1 : 0.52 }}>
        <div className="mono" style={{ width: 38, flexShrink: 0, fontSize: 11, color: "var(--color-muted)" }}>
          {idxLabel}
        </div>

        <div className="col-opt-md" style={{ width: 116, flexShrink: 0 }}>
          <span className="badge mono" style={{ fontSize: 10 }}>
            {r.rule_type}
          </span>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 2, flex: "1 1 160px", minWidth: 0 }}>
          <div className="row-title" style={{ fontSize: 13 }}>
            {r.payload}
            {r.no_resolve && (
              <span className="mono" style={{ marginLeft: 6, fontSize: 10, color: "var(--color-muted)", fontWeight: 400 }}>
                (no-resolve)
              </span>
            )}
          </div>
          {r.title && r.title !== `${r.rule_type} · ${r.payload}` && (
            <div className="row-subtitle">{r.title}</div>
          )}
        </div>

        {/* Inline Target Policy Reassign Selector */}
        <div style={{ width: 152, flexShrink: 0 }}>
          <select
            className="select mono"
            style={{
              padding: "4px 8px",
              fontSize: 11,
              fontWeight: 600,
              background:
                r.target_policy === "DIRECT"
                  ? "var(--color-success-soft)"
                  : r.target_policy.startsWith("REJECT")
                    ? "var(--color-danger-soft)"
                    : "var(--color-primary-soft)",
              color:
                r.target_policy === "DIRECT"
                  ? "var(--color-success)"
                  : r.target_policy.startsWith("REJECT")
                    ? "var(--color-danger)"
                    : "var(--color-primary)",
              borderColor: "transparent",
            }}
            value={
              policyTargetOptions.includes(r.target_policy)
                ? r.target_policy
                : policyTargetOptions[0]
            }
            onChange={(e) => onPatchRule(r.id, { target_policy: e.target.value })}
          >
            {!policyTargetOptions.includes(r.target_policy) && (
              <option value={r.target_policy}>→ {r.target_policy}</option>
            )}
            {policyTargetOptions.map((opt) => (
              <option key={opt} value={opt}>
                → {opt}
              </option>
            ))}
          </select>
        </div>

        <button
          type="button"
          className="link-btn"
          style={{ fontSize: 12 }}
          onClick={() => startEditingRule(r)}
        >
          编辑
        </button>

        <button
          type="button"
          className={`switch ${r.enabled ? "on" : ""}`}
          onClick={() => onPatchRule(r.id, { enabled: !r.enabled })}
        >
          <span className="switch-thumb" />
        </button>

        <button
          type="button"
          className="btn btn-ghost-danger mono"
          onClick={() => onDeleteRule(r.id)}
          title="删除此规则"
        >
          ×
        </button>
      </div>
    );
  };

  return (
    <>
      {/* Top Bar */}
      <div className="top-bar">
        <div style={{ minWidth: 220 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <h1 className="page-title">策略组与分流规则编排</h1>
            <span className="badge badge-success">REVISION v{data.settings.revision}</span>
          </div>
          <p className="page-subtitle">
            清晰管理「分流规则 → 策略组 → 子策略与节点筛选」完整拓扑链路
          </p>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          <button type="button" className="btn btn-sm" onClick={() => setShowCreateGroup(true)}>
            + 新建策略组
          </button>
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => openAddRuleForTarget(currentTargetName)}
          >
            + 新增分流规则
          </button>
          <button type="button" className="btn btn-primary" disabled={busy} onClick={onPublish}>
            发布配置 v{data.settings.revision + 1}
          </button>
        </div>
      </div>

      {/* Sub-Navigation Mode Bar */}
      <div className="sub-mode-bar">
        <div className="segmented-control" style={{ background: "var(--color-card)" }}>
          <button
            type="button"
            className={`segmented-btn ${studioTab === "groups" ? "active" : ""}`}
            style={{ padding: "6px 14px" }}
            onClick={() => setStudioTab("groups")}
          >
            按策略组联动编排 ({data.policy_groups.length})
          </button>
          <button
            type="button"
            className={`segmented-btn ${studioTab === "all-rules" ? "active" : ""}`}
            style={{ padding: "6px 14px" }}
            onClick={() => setStudioTab("all-rules")}
          >
            全局规则优先级总表 ({data.rules.length})
          </button>
          <button
            type="button"
            className={`segmented-btn ${studioTab === "preview" ? "active" : ""}`}
            style={{ padding: "6px 14px" }}
            onClick={() => {
              setStudioTab("preview");
              onSimulate(simInput).then(setSimResult).catch(() => {});
            }}
          >
            命中模拟与编译产物预览
          </button>
        </div>

        {data.pipeline.active_total > 0 && data.policy_groups.length === 0 && (
          <button type="button" className="btn btn-sm" disabled={busy} onClick={onScaffoldRules}>
            按已导入节点地区一键生成基础策略组
          </button>
        )}
      </div>

      {/* ============================================================
          MODE 1: Group-Centric Connected Topology & Editor
          ============================================================ */}
      {studioTab === "groups" && (
        <div className="group-studio-split">
          {/* Left Master List: All Policy Groups + Built-in Targets */}
          <div className="group-master-rail">
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                padding: "6px 10px",
                borderRadius: 7,
                background: "var(--color-card)",
                border: "1px solid var(--color-border)",
                flexShrink: 0,
              }}
            >
              <SearchIcon />
              <input
                value={groupSearch}
                onChange={(e) => setGroupSearch(e.target.value)}
                placeholder="筛选策略组名称..."
                style={{
                  border: "none",
                  background: "transparent",
                  outline: "none",
                  fontSize: 12,
                  width: "100%",
                }}
              />
            </div>

            <div className="group-master-list">
              {filteredMasterGroups.map((g) => {
                const isSelected = selectedKey === g.id;
                const topo = groupStatsMap.get(g.id);
                const ruleCnt = topo?.linkedRules.length ?? 0;
                const parentCnt = topo?.parentGroups.length ?? 0;
                const nodeCnt = topo?.matchedNodes.length ?? 0;
                const subCnt = g.fallback_groups.length;

                return (
                  <div
                    key={g.id}
                    onClick={() => setSelectedKey(g.id)}
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: 7,
                      padding: "11px 12px",
                      borderRadius: 9,
                      cursor: "pointer",
                      background: isSelected ? "var(--color-card)" : "transparent",
                      border: isSelected ? "1.5px solid var(--color-primary)" : "1px solid var(--color-border)",
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 6 }}>
                      <span
                        className="truncate"
                        style={{
                          fontSize: 13.5,
                          fontWeight: 600,
                          color: isSelected ? "var(--color-primary)" : "var(--color-ink)",
                        }}
                      >
                        {g.name}
                      </span>
                      <span className="badge mono" style={{ fontSize: 10 }}>
                        {g.type}
                      </span>
                    </div>

                    <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                      <span
                        className="mono"
                        style={{
                          fontSize: 10.5,
                          color: ruleCnt > 0 ? "var(--color-ink)" : "var(--color-subtle)",
                        }}
                      >
                        {ruleCnt > 0
                          ? `${ruleCnt} 条规则`
                          : parentCnt > 0
                            ? `被 ${parentCnt} 组嵌套`
                            : "0 规则引用"}
                      </span>
                      <span style={{ color: "var(--color-border)" }}>·</span>
                      <span className="mono" style={{ fontSize: 10.5, color: "var(--color-muted)" }}>
                        {subCnt > 0 && nodeCnt > 0
                          ? `${subCnt} 子组 + ${nodeCnt} 节点`
                          : subCnt > 0
                            ? `${subCnt} 个子策略`
                            : `${nodeCnt} 个匹配节点`}
                      </span>
                    </div>
                  </div>
                );
              })}

              <div className="nav-section-label" style={{ paddingLeft: 4 }}>
                内置基础出口
              </div>

              <div
                onClick={() => setSelectedKey("BUILTIN:DIRECT")}
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "10px 12px",
                  borderRadius: 9,
                  cursor: "pointer",
                  background: selectedBuiltin === "DIRECT" ? "var(--color-card)" : "transparent",
                  border:
                    selectedBuiltin === "DIRECT"
                      ? "1.5px solid var(--color-success)"
                      : "1px solid var(--color-border)",
                }}
              >
                <span className="badge badge-success">DIRECT · 本地直连</span>
                <span className="mono" style={{ fontSize: 11, color: "var(--color-muted)" }}>
                  {directRules.length} 条规则
                </span>
              </div>

              <div
                onClick={() => setSelectedKey("BUILTIN:REJECT-DROP")}
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "10px 12px",
                  borderRadius: 9,
                  cursor: "pointer",
                  background: selectedBuiltin === "REJECT-DROP" ? "var(--color-card)" : "transparent",
                  border:
                    selectedBuiltin === "REJECT-DROP"
                      ? "1.5px solid var(--color-danger)"
                      : "1px solid var(--color-border)",
                }}
              >
                <span className="badge badge-danger">REJECT · 阻断拦截</span>
                <span className="mono" style={{ fontSize: 11, color: "var(--color-muted)" }}>
                  {rejectRules.length} 条规则
                </span>
              </div>
            </div>
          </div>

          {/* Right Detail Workspace: Selected Group Full Editor + Linked Rules */}
          <div ref={detailScrollRef} className="primary-column group-detail-pane" style={{ gap: 24 }}>
            {selectedGroup ? (
              <>
                {/* Card 1: Group Basic Settings Editor */}
                <section className="surface-card" style={{ padding: 20, gap: 16 }}>
                  <div className="section-header">
                    <div>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <h2 className="section-title">1. 策略组属性设置</h2>
                        {isGroupDirty && <span className="badge badge-warning">有未保存修改</span>}
                      </div>
                      <span style={{ fontSize: 12, color: "var(--color-muted)" }}>
                        重命名分组时，所有关联规则与上层嵌套分组会自动同步更新
                      </span>
                    </div>

                    <div style={{ display: "flex", gap: 8 }}>
                      <button
                        type="button"
                        className="btn btn-sm"
                        style={{ color: "var(--color-danger)", borderColor: "var(--color-danger-border)" }}
                        disabled={busy}
                        onClick={() => {
                          if (
                            window.confirm(
                              `确定删除策略组「${selectedGroup.name}」吗？指向它的规则将自动回退至首个分组或 DIRECT。`
                            )
                          ) {
                            onDeletePolicyGroup(selectedGroup.id);
                          }
                        }}
                      >
                        删除此分组
                      </button>
                      <button
                        type="button"
                        className="btn btn-sm btn-primary"
                        disabled={busy || !editGName.trim()}
                        onClick={() =>
                          onUpdatePolicyGroup(selectedGroup.id, {
                            name: editGName,
                            type: editGType,
                            filter_regex: editGRegex,
                            fallback_groups: editGSubs,
                            interval_sec: editGInterval,
                            tolerance_ms: editGTolerance,
                          })
                        }
                      >
                        保存策略组配置
                      </button>
                    </div>
                  </div>

                  <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
                    <div style={{ flex: "1 1 200px", display: "flex", flexDirection: "column", gap: 4 }}>
                      <span className="mono" style={{ fontSize: 11, color: "var(--color-subtle)" }}>
                        策略组名称
                      </span>
                      <input
                        className="input"
                        value={editGName}
                        onChange={(e) => setEditGName(e.target.value)}
                      />
                    </div>

                    <div style={{ flex: "1 1 220px", display: "flex", flexDirection: "column", gap: 4 }}>
                      <span className="mono" style={{ fontSize: 11, color: "var(--color-subtle)" }}>
                        选路策略类型
                      </span>
                      <select
                        className="select"
                        value={editGType}
                        onChange={(e) => setEditGType(e.target.value as PolicyGroup["type"])}
                      >
                        <option value="select">select · 手动选择 / 按子策略优先级</option>
                        <option value="url-test">url-test · 自动测速选择最低延迟</option>
                        <option value="smart">smart · Surge 智能优选 (Stash 映射 url-test)</option>
                        <option value="fallback">fallback · 按顺序故障转移</option>
                      </select>
                    </div>

                    {editGType !== "select" && (
                      <>
                        <div style={{ width: 110, display: "flex", flexDirection: "column", gap: 4 }}>
                          <span className="mono" style={{ fontSize: 11, color: "var(--color-subtle)" }}>
                            测速间隔 (秒)
                          </span>
                          <input
                            type="number"
                            className="input mono"
                            value={editGInterval}
                            onChange={(e) => setEditGInterval(Number(e.target.value) || 300)}
                          />
                        </div>
                        <div style={{ width: 110, display: "flex", flexDirection: "column", gap: 4 }}>
                          <span className="mono" style={{ fontSize: 11, color: "var(--color-subtle)" }}>
                            切换容差 (ms)
                          </span>
                          <input
                            type="number"
                            className="input mono"
                            value={editGTolerance}
                            onChange={(e) => setEditGTolerance(Number(e.target.value) || 20)}
                          />
                        </div>
                      </>
                    )}
                  </div>
                </section>

                {/* Card 2: Outbound Sub-Groups & Node Matching Rules */}
                <section className="surface-card" style={{ padding: 20, gap: 16 }}>
                  <div className="section-header">
                    <div>
                      <h2 className="section-title">
                        2. 出口构成与节点规则（该分组包含哪些子策略与节点？）
                      </h2>
                      <span style={{ fontSize: 12, color: "var(--color-muted)" }}>
                        可嵌套其他策略组（适合业务分组如 ChatGPT / YouTube），或按地区与正则直接筛选节点池（适合地区分组）
                      </span>
                    </div>
                  </div>

                  {/* 2A: Sub-Group References */}
                  <div
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: 10,
                      padding: 14,
                      borderRadius: 9,
                      background: "var(--color-surface)",
                      border: "1px solid var(--color-border)",
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}>
                      <span style={{ fontSize: 13, fontWeight: 600 }}>
                        A. 引用子策略组 / 固定出口 ({editGSubs.length})
                      </span>

                      <div style={{ display: "flex", gap: 6 }}>
                        <select
                          className="select mono"
                          style={{ width: 190, background: "var(--color-card)", padding: "4px 8px", fontSize: 12 }}
                          value={addSubChoice}
                          onChange={(e) => {
                            const val = e.target.value;
                            if (val && !editGSubs.includes(val)) {
                              setEditGSubs([...editGSubs, val]);
                            }
                            setAddSubChoice("");
                          }}
                        >
                          <option value="">+ 添加子策略组或内置出口…</option>
                          {policyTargetOptions
                            .filter((name) => name !== selectedGroup.name && !editGSubs.includes(name))
                            .map((name) => (
                              <option key={name} value={name}>
                                {name}
                              </option>
                            ))}
                        </select>
                      </div>
                    </div>

                    {editGSubs.length === 0 ? (
                      <div style={{ fontSize: 12, color: "var(--color-muted)" }}>
                        未引用子策略组（当前直接通过下方节点筛选规则匹配节点池）。
                      </div>
                    ) : (
                      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                        {editGSubs.map((subName, idx) => {
                          const targetGrp = data.policy_groups.find((x) => x.name === subName);
                          return (
                            <div
                              key={subName}
                              style={{
                                display: "inline-flex",
                                alignItems: "center",
                                gap: 6,
                                padding: "5px 9px",
                                borderRadius: 7,
                                background: "var(--color-card)",
                                border: "1px solid var(--color-border)",
                                fontSize: 12,
                              }}
                            >
                              <span className="mono" style={{ fontSize: 10, color: "var(--color-subtle)" }}>
                                {idx + 1}.
                              </span>
                              <span
                                onClick={() => targetGrp && setSelectedKey(targetGrp.id)}
                                style={{
                                  fontWeight: 600,
                                  color: targetGrp ? "var(--color-primary)" : "var(--color-ink)",
                                  cursor: targetGrp ? "pointer" : "default",
                                }}
                                title={targetGrp ? `点击跳转到「${subName}」分组` : undefined}
                              >
                                {subName}
                              </span>
                              {idx > 0 && (
                                <button
                                  type="button"
                                  className="btn-ghost-danger mono"
                                  style={{ border: "none", cursor: "pointer", padding: "0 3px", fontSize: 11 }}
                                  onClick={() => {
                                    const copy = [...editGSubs];
                                    [copy[idx - 1], copy[idx]] = [copy[idx], copy[idx - 1]];
                                    setEditGSubs(copy);
                                  }}
                                  title="前移优先级"
                                >
                                  ←
                                </button>
                              )}
                              <button
                                type="button"
                                className="btn-ghost-danger mono"
                                style={{ border: "none", cursor: "pointer", padding: "0 3px", fontSize: 12 }}
                                onClick={() => setEditGSubs(editGSubs.filter((x) => x !== subName))}
                                title="移除子策略"
                              >
                                ×
                              </button>
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>

                  {/* 2B: Dynamic Node Pool Filter Rule */}
                  <div
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: 10,
                      padding: 14,
                      borderRadius: 9,
                      background: "var(--color-surface)",
                      border: "1px solid var(--color-border)",
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, flexWrap: "wrap" }}>
                      <span style={{ fontSize: 13, fontWeight: 600 }}>
                        B. 节点池自动筛选规则 (命中 {liveMatchedNodes.length} 个可用节点)
                      </span>

                      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                        <button
                          type="button"
                          className={`filter-chip ${editGRegex === "" ? "active" : ""}`}
                          style={{ padding: "3px 9px", fontSize: 11 }}
                          onClick={() => setEditGRegex("")}
                        >
                          不直接筛节点 (仅用子策略)
                        </button>
                        <button
                          type="button"
                          className={`filter-chip ${editGRegex === ".*" ? "active" : ""}`}
                          style={{ padding: "3px 9px", fontSize: 11 }}
                          onClick={() => setEditGRegex(".*")}
                        >
                          包含全部可用节点 (.*)
                        </button>
                      </div>
                    </div>

                    {availableRegions.length > 0 && (
                      <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                        <span className="mono" style={{ fontSize: 11, color: "var(--color-muted)" }}>
                          按地区点选：
                        </span>
                        {availableRegions.map(([rg, cnt]) => {
                          const isChecked = parsedRegionPills?.includes(rg) ?? false;
                          return (
                            <button
                              key={rg}
                              type="button"
                              className={`filter-chip mono ${isChecked ? "active" : ""}`}
                              style={{ padding: "3px 8px", fontSize: 11, background: isChecked ? undefined : "var(--color-card)" }}
                              onClick={() => toggleRegionPill(rg)}
                            >
                              {rg} ({cnt})
                            </button>
                          );
                        })}
                      </div>
                    )}

                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <span className="mono" style={{ fontSize: 11, color: "var(--color-subtle)", whiteSpace: "nowrap" }}>
                        筛选正则：
                      </span>
                      <input
                        className="input mono"
                        style={{ background: "var(--color-card)", fontSize: 12 }}
                        placeholder="留空则不直接匹配节点；输入如 /^HK\b/ 或 香港|IEPL 同时匹配标准名与原始名"
                        value={editGRegex}
                        onChange={(e) => setEditGRegex(e.target.value)}
                      />
                    </div>

                    {/* Live Matched Nodes Preview */}
                    {liveMatchedNodes.length > 0 && (
                      <div
                        style={{
                          paddingTop: 8,
                          borderTop: "1px solid var(--color-border)",
                          display: "flex",
                          flexDirection: "column",
                          gap: 8,
                        }}
                      >
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                          <span className="mono" style={{ fontSize: 11, color: "var(--color-success)", fontWeight: 600 }}>
                            实时匹配到的节点列表 ({liveMatchedNodes.length} 个)：
                          </span>
                          {liveMatchedNodes.length > 16 && (
                            <button
                              type="button"
                              className="link-btn"
                              style={{ fontSize: 11 }}
                              onClick={() => setShowAllMatchedNodes((v) => !v)}
                            >
                              {showAllMatchedNodes ? "收起部分" : `展开全部 ${liveMatchedNodes.length} 个节点`}
                            </button>
                          )}
                        </div>
                        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                          {(showAllMatchedNodes ? liveMatchedNodes : liveMatchedNodes.slice(0, 16)).map((n) => (
                            <span
                              key={n.id}
                              title={`原名: ${n.raw_name} (${n.protocol})`}
                              className="mono"
                              style={{
                                padding: "3px 8px",
                                borderRadius: 5,
                                background: "var(--color-card)",
                                border: "1px solid var(--color-border)",
                                fontSize: 11,
                                color: "var(--color-ink)",
                              }}
                            >
                              {n.normalized_name}
                              {n.latency_ms !== null ? ` · ${n.latency_ms}ms` : ""}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {editGSubs.length === 0 && liveMatchedNodes.length === 0 && (
                      <div style={{ fontSize: 12, color: "var(--color-warning)" }}>
                        提示：当前既未添加子策略组，也未匹配到任何节点，编译下发时将自动回退至 DIRECT。
                      </div>
                    )}

                    {isGroupDirty && (
                      <div style={{ display: "flex", justifyContent: "flex-end" }}>
                        <button
                          type="button"
                          className="btn btn-primary btn-sm"
                          disabled={busy}
                          onClick={() =>
                            onUpdatePolicyGroup(selectedGroup.id, {
                              name: editGName,
                              type: editGType,
                              filter_regex: editGRegex,
                              fallback_groups: editGSubs,
                              interval_sec: editGInterval,
                              tolerance_ms: editGTolerance,
                            })
                          }
                        >
                          保存上述出口与节点规则修改
                        </button>
                      </div>
                    )}
                  </div>
                </section>

                {/* Card 3: Inbound Traffic — Parent Groups & Linked Routing Rules */}
                <section className="surface-card" style={{ padding: 20, gap: 14 }}>
                  {currentParentGroups.length > 0 && (
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 8,
                        flexWrap: "wrap",
                        padding: "10px 12px",
                        borderRadius: 8,
                        background: "var(--color-primary-soft)",
                      }}
                    >
                      <span style={{ fontSize: 12, fontWeight: 600, color: "var(--color-primary)" }}>
                        被上层策略组引用 ({currentParentGroups.length})：
                      </span>
                      {currentParentGroups.map((pg) => (
                        <button
                          key={pg.id}
                          type="button"
                          onClick={() => setSelectedKey(pg.id)}
                          className="badge badge-primary"
                          style={{ background: "var(--color-card)", border: "1px solid var(--color-primary-border)", cursor: "pointer" }}
                        >
                          {pg.name} ↗
                        </button>
                      ))}
                    </div>
                  )}

                  <div className="section-header">
                    <div>
                      <h2 className="section-title">
                        3. 流向「{selectedGroup.name}」的分流规则 ({currentLinkedRules.length} 条)
                      </h2>
                      <span style={{ fontSize: 12, color: "var(--color-muted)" }}>
                        管理命中后直接路由到该策略组的所有域名、IP 与远程 Rule-Set
                      </span>
                    </div>

                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <input
                        className="input"
                        style={{ width: 180, padding: "5px 10px", fontSize: 12 }}
                        placeholder="搜索组内规则..."
                        value={groupRuleQuery}
                        onChange={(e) => setGroupRuleQuery(e.target.value)}
                      />
                      <button
                        type="button"
                        className="btn btn-sm btn-ink"
                        onClick={() => openAddRuleForTarget(selectedGroup.name)}
                      >
                        + 为此分组新增规则
                      </button>
                    </div>
                  </div>

                  {currentLinkedRules.length === 0 ? (
                    <div
                      style={{
                        padding: "24px 16px",
                        borderRadius: 8,
                        border: "1px dashed var(--color-border)",
                        textAlign: "center",
                        fontSize: 12.5,
                        color: "var(--color-muted)",
                      }}
                    >
                      {currentParentGroups.length > 0
                        ? `该分组作为底层节点组被「${currentParentGroups.map((p) => p.name).join("、")}」引用，暂无直接指向它的单条分流规则。`
                        : `暂无分流规则指向「${selectedGroup.name}」，可点击右上角新增规则或在「全局规则总表」中将现有规则改绑至此分组。`}
                    </div>
                  ) : (
                    <div className="hairline-list">
                      {currentLinkedRules.map((r, i) =>
                        renderRuleRow(r, `#${String(i + 1).padStart(2, "0")}`)
                      )}
                    </div>
                  )}
                </section>
              </>
            ) : (
              /* Built-in Target (DIRECT / REJECT-DROP) Linked Rules Inspector */
              <section className="surface-card" style={{ padding: 20, gap: 14 }}>
                <div className="section-header">
                  <div>
                    <h2 className="section-title">
                      流向内置出口「{selectedBuiltin}」的分流规则 ({currentLinkedRules.length} 条)
                    </h2>
                    <span style={{ fontSize: 12, color: "var(--color-muted)" }}>
                      {selectedBuiltin === "DIRECT"
                        ? "命中以下规则的流量将不经过任何代理节点，直接由本地网络发出"
                        : "命中以下规则的请求（如广告、隐私遥测）将在客户端内核直接丢弃阻断"}
                    </span>
                  </div>
                  <button
                    type="button"
                    className="btn btn-sm btn-ink"
                    onClick={() => openAddRuleForTarget(selectedBuiltin || "DIRECT")}
                  >
                    + 新增 {selectedBuiltin} 规则
                  </button>
                </div>

                {currentLinkedRules.length === 0 ? (
                  <div style={{ padding: 24, textAlign: "center", color: "var(--color-muted)", fontSize: 13 }}>
                    暂无指向 {selectedBuiltin} 的分流规则。
                  </div>
                ) : (
                  <div className="hairline-list">
                    {currentLinkedRules.map((r, i) =>
                      renderRuleRow(r, `#${String(i + 1).padStart(2, "0")}`)
                    )}
                  </div>
                )}
              </section>
            )}
          </div>
        </div>
      )}

      {/* ============================================================
          MODE 2: Global Priority Rules Pipeline Table
          ============================================================ */}
      {studioTab === "all-rules" && (
        <div className="view-scroll-body">
          <div className="primary-column" style={{ gap: 18 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              {(
                [
                  { id: "ALL", label: `全部规则 ${data.rules.length}` },
                  { id: "OVERRIDE", label: `单条规则 ${data.rules.filter((r) => r.kind === "override").length}` },
                  { id: "RULESET", label: `远程 Rule-Set ${data.rules.filter((r) => r.rule_type === "RULE-SET").length}` },
                  { id: "GEO_FINAL", label: "GEOIP / 兜底" },
                ] as const
              ).map((t) => (
                <button
                  key={t.id}
                  type="button"
                  className={`filter-chip ${globalRuleTypeFilter === t.id ? "active" : ""}`}
                  onClick={() => setGlobalRuleTypeFilter(t.id)}
                >
                  {t.label}
                </button>
              ))}
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
                minWidth: 260,
              }}
            >
              <SearchIcon />
              <input
                value={globalRuleQuery}
                onChange={(e) => setGlobalRuleQuery(e.target.value)}
                placeholder="搜索域名、CIDR、类型或目标策略组..."
                style={{
                  border: "none",
                  background: "transparent",
                  outline: "none",
                  fontSize: 12,
                  width: "100%",
                }}
              />
            </div>
          </div>

          {filteredGlobalRules.length === 0 ? (
            <div
              style={{
                padding: "40px 20px",
                borderRadius: 12,
                border: "1px dashed var(--color-border)",
                background: "var(--color-surface)",
                textAlign: "center",
                color: "var(--color-muted)",
              }}
            >
              未找到匹配的分流规则。
            </div>
          ) : (
            <div className="hairline-list">
              <div className="table-header-row desktop-only">
                <div style={{ width: 38, flexShrink: 0 }}>ORDER</div>
                <div className="col-opt-md" style={{ width: 116, flexShrink: 0 }}>
                  TYPE
                </div>
                <div style={{ flex: 1 }}>MATCH PAYLOAD / 规则内容</div>
                <div style={{ width: 152, flexShrink: 0 }}>TARGET POLICY (可直接切换)</div>
                <div style={{ width: 106, flexShrink: 0, textAlign: "right" }}>操作</div>
              </div>

              {filteredGlobalRules
                .slice(0, globalVisibleLimit)
                .map((r, idx) =>
                  renderRuleRow(r, r.rule_type === "FINAL" ? "#FF" : `#${String(idx + 1).padStart(2, "0")}`)
                )}

              {filteredGlobalRules.length > globalVisibleLimit && (
                <div style={{ padding: "16px 0", display: "flex", justifyContent: "center" }}>
                  <button
                    type="button"
                    className="btn btn-sm"
                    onClick={() => setGlobalVisibleLimit((n) => n + 100)}
                  >
                    加载更多规则 (剩余 {filteredGlobalRules.length - globalVisibleLimit} 条)
                  </button>
                </div>
              )}
            </div>
          )}
          </div>
        </div>
      )}

      {/* ============================================================
          MODE 3: Route Hit Simulator & Compiled Config Preview
          ============================================================ */}
      {studioTab === "preview" && (
        <div className="view-scroll-body">
          <div className="workspace-split">
          <div className="primary-column" style={{ gap: 16 }}>
            <div className="section-header">
              <h2 className="section-title">多端实时编译产物预览</h2>
              <div className="segmented-control">
                <button
                  type="button"
                  className={`segmented-btn mono ${previewLang === "surge6" ? "active" : ""}`}
                  onClick={() => setPreviewLang("surge6")}
                >
                  Surge 6 (.conf · {data.compiled_preview.surge6_line_count} 行)
                </button>
                <button
                  type="button"
                  className={`segmented-btn mono ${previewLang === "surge" ? "active" : ""}`}
                  onClick={() => setPreviewLang("surge")}
                >
                  Surge 5 (.conf · {data.compiled_preview.surge_line_count} 行)
                </button>
                <button
                  type="button"
                  className={`segmented-btn mono ${previewLang === "stash" ? "active" : ""}`}
                  onClick={() => setPreviewLang("stash")}
                >
                  Stash / Clash (.yaml)
                </button>
              </div>
            </div>

            <pre className="code-preview" style={{ maxHeight: "calc(100vh - 250px)" }}>
              {previewLang === "surge6"
                ? data.compiled_preview.surge6
                : previewLang === "surge"
                  ? data.compiled_preview.surge
                  : data.compiled_preview.stash}
            </pre>
          </div>

          <aside className="secondary-rail" style={{ width: 400 }}>
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <span style={{ fontSize: 15, fontWeight: 600 }}>路由命中全链路模拟器</span>
              <div className="surface-card" style={{ gap: 12 }}>
                <div style={{ display: "flex", gap: 6 }}>
                  <input
                    className="input mono"
                    value={simInput}
                    onChange={(e) => setSimInput(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && onSimulate(simInput).then(setSimResult)}
                    placeholder="输入域名或 URL，如 claude.ai"
                  />
                  <button
                    type="button"
                    className="btn btn-ink btn-sm"
                    onClick={() => onSimulate(simInput).then(setSimResult)}
                  >
                    测试
                  </button>
                </div>

                {simResult && (
                  <div
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: 10,
                      paddingTop: 10,
                      borderTop: "1px solid var(--color-border)",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", gap: 8, fontSize: 12 }}>
                      <span style={{ color: "var(--color-muted)" }}>1. 命中分流规则</span>
                      <span className="mono" style={{ fontWeight: 600 }}>
                        {simResult.matched_expression}
                      </span>
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between", gap: 8, fontSize: 12 }}>
                      <span style={{ color: "var(--color-muted)" }}>2. 进入目标策略组</span>
                      <span className="mono" style={{ fontWeight: 600, color: "var(--color-primary)" }}>
                        {simResult.target_policy}
                      </span>
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between", gap: 8, fontSize: 12 }}>
                      <span style={{ color: "var(--color-muted)" }}>3. 最终选路出口</span>
                      <span className="mono" style={{ fontWeight: 600, color: "var(--color-success)", textAlign: "right" }}>
                        {simResult.resolved_node}
                      </span>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </aside>
          </div>
        </div>
      )}

      {/* Create Policy Group Modal */}
      {showCreateGroup && (
        <div className="modal-backdrop" onClick={() => setShowCreateGroup(false)}>
          <div className="modal-panel" style={{ maxWidth: 460 }} onClick={(e) => e.stopPropagation()}>
            <h3 style={{ margin: 0, fontSize: 17, fontWeight: 600 }}>新建策略组</h3>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <input
                className="input"
                placeholder="策略组名称，如 AI 专线 或 🇭🇰 香港自动"
                value={createGName}
                onChange={(e) => setCreateGName(e.target.value)}
              />
              <select
                className="select"
                value={createGType}
                onChange={(e) => setCreateGType(e.target.value as PolicyGroup["type"])}
              >
                <option value="select">select · 手动选择 / 嵌套子策略组</option>
                <option value="url-test">url-test · 自动测速优选节点</option>
                <option value="smart">smart · Surge 智能优选</option>
                <option value="fallback">fallback · 故障转移</option>
              </select>
              <input
                className="input mono"
                placeholder="可选：节点筛选正则（如 /^HK\b/，留空则创建后再勾选子策略或地区）"
                value={createGRegex}
                onChange={(e) => setCreateGRegex(e.target.value)}
              />
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
              <button type="button" className="btn" onClick={() => setShowCreateGroup(false)}>
                取消
              </button>
              <button
                type="button"
                className="btn btn-primary"
                disabled={busy || !createGName.trim()}
                onClick={async () => {
                  await onAddPolicyGroup({
                    name: createGName,
                    type: createGType,
                    filter_regex: createGRegex,
                    fallback_groups: [],
                  });
                  setCreateGName("");
                  setCreateGRegex("");
                  setShowCreateGroup(false);
                }}
              >
                创建并配置出口规则
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Add Routing Rule Modal */}
      {showAddRuleModal && (
        <div className="modal-backdrop" onClick={() => setShowAddRuleModal(false)}>
          <div className="modal-panel" style={{ maxWidth: 480 }} onClick={(e) => e.stopPropagation()}>
            <h3 style={{ margin: 0, fontSize: 17, fontWeight: 600 }}>新增分流规则</h3>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <div style={{ display: "flex", gap: 8 }}>
                <select
                  className="select mono"
                  style={{ width: 170 }}
                  value={newRType}
                  onChange={(e) => setNewRType(e.target.value)}
                >
                  {RULE_TYPES.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </select>
                <select
                  className="select mono"
                  style={{ flex: 1 }}
                  value={newRTarget}
                  onChange={(e) => setNewRTarget(e.target.value)}
                >
                  {policyTargetOptions.map((opt) => (
                    <option key={opt} value={opt}>
                      目标策略组：→ {opt}
                    </option>
                  ))}
                </select>
              </div>
              <input
                className="input mono"
                placeholder={
                  newRType === "FINAL"
                    ? "可选参数，留空默认 dns-failed"
                    : newRType === "RULE-SET"
                      ? "远程规则集 URL: https://..."
                      : newRType === "IP-CIDR"
                        ? "网段如 91.108.4.0/22"
                        : "匹配内容，如 anthropic.com"
                }
                value={newRPayload}
                onChange={(e) => setNewRPayload(e.target.value)}
              />
              <input
                className="input"
                placeholder="备注说明（可选，如 Claude API 分流）"
                value={newRTitle}
                onChange={(e) => setNewRTitle(e.target.value)}
              />
              <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12 }}>
                <input
                  type="checkbox"
                  checked={newRNoResolve}
                  onChange={(e) => setNewRNoResolve(e.target.checked)}
                />
                <span>附加 no-resolve（跳过本地 DNS 解析，适用于 IP-CIDR / RULE-SET）</span>
              </label>
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
              <button type="button" className="btn" onClick={() => setShowAddRuleModal(false)}>
                取消
              </button>
              <button
                type="button"
                className="btn btn-primary"
                disabled={busy || (newRType !== "FINAL" && !newRPayload.trim())}
                onClick={async () => {
                  await onAddRule({
                    rule_type: newRType,
                    payload: newRPayload.trim() || (newRType === "FINAL" ? "dns-failed" : ""),
                    title: newRTitle,
                    target_policy: newRTarget,
                    no_resolve: newRNoResolve,
                  });
                  setShowAddRuleModal(false);
                }}
              >
                确认添加规则
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
