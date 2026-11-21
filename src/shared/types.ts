export interface TowerSettings {
  sub_token: string;
  mcp_token: string;
  rename_template: string;
  exclude_regex: string;
  max_multiplier: number;
  dedup_enabled: boolean;
  ua_guard_enabled: boolean;
  strict_client_ua: boolean;
  cron_interval_min: number;
  last_full_sync_at: number | null;
  revision: number;
}

export interface AdminAuthInfo {
  mode: "cf_access" | "local_dev";
  configured: boolean;
  email: string | null;
  team_domain: string | null;
  logout_url: string | null;
}

export interface SubscriptionItem {
  id: string;
  name: string;
  url: string;
  fetch_ua: string;
  fetch_proxy: string;
  protocol_hint: string;
  enabled: boolean;
  inline_content: string;
  used_gb: number;
  total_gb: number;
  expire_at: number | null;
  is_unlimited: boolean;
  raw_node_count: number;
  valid_node_count: number;
  regions: string[];
  last_sync_at: number | null;
  last_status: string;
  note: string;
  created_at: number;
}

export interface RawNodeConfig {
  surge_rhs?: string;
  clash_proxy?: Record<string, unknown>;
}

export interface ProxyNode {
  id: string;
  sub_id: string;
  sub_name: string;
  raw_name: string;
  normalized_name: string;
  region: string;
  line_tag: string;
  protocol: string;
  server: string;
  port: number;
  cipher_or_param: string;
  raw_config: RawNodeConfig;
  multiplier: number;
  latency_ms: number | null;
  fingerprint: string;
  merged_count: number;
  status: "active" | "filtered_regex" | "filtered_multiplier" | "filtered_dedup";
  filter_reason: string;
  updated_at: number;
}

export interface PolicyGroup {
  id: string;
  name: string;
  type: "url-test" | "fallback" | "select" | "smart";
  filter_regex: string;
  interval_sec: number;
  tolerance_ms: number;
  fallback_groups: string[];
  sort_order: number;
  matched_count?: number;
}

export interface RoutingRule {
  id: string;
  kind: "override" | "ruleset";
  rule_type:
    | "DOMAIN-SUFFIX"
    | "DOMAIN-KEYWORD"
    | "DOMAIN"
    | "IP-CIDR"
    | "IP-CIDR6"
    | "GEOIP"
    | "PROCESS-NAME"
    | "USER-AGENT"
    | "URL-REGEX"
    | "RULE-SET"
    | "FINAL";
  title: string;
  payload: string;
  target_policy: string;
  rule_count: number;
  no_resolve: boolean;
  sync_meta: string;
  enabled: boolean;
  priority: number;
}

export interface AccessLogItem {
  id: string;
  client_tag: "SURGE" | "STASH" | "CLASH" | "BROWSER" | "BLOCK";
  device_ua: string;
  ip: string;
  isp_geo: string;
  status_code: number;
  status_label: string;
  target_format: string;
  latency_ms: number;
  created_at: number;
}

export interface PipelineStats {
  raw_total: number;
  filtered_regex_or_rate: number;
  filtered_dedup: number;
  active_total: number;
  avg_latency_ms: number | null;
  probed_count: number;
  region_counts: Record<string, number>;
}

export interface SimulationResult {
  target: string;
  host: string;
  elapsed_ms: number;
  matched_rule_title: string;
  matched_expression: string;
  matched_kind: string;
  target_policy: string;
  resolved_node: string;
  resolved_latency_ms: number | null;
}

export interface DashboardSnapshot {
  auth: AdminAuthInfo;
  settings: TowerSettings;
  subscriptions: SubscriptionItem[];
  nodes: ProxyNode[];
  policy_groups: PolicyGroup[];
  rules: RoutingRule[];
  access_logs: AccessLogItem[];
  pipeline: PipelineStats;
  compiled_preview: {
    surge: string;
    surge6: string;
    stash: string;
    surge_line_count: number;
    surge6_line_count: number;
    stash_provider_count: number;
  };
}
