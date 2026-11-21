-- Tower D1 Schema (Cloudflare Workers + D1 SQLite)

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS subscriptions (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  url TEXT NOT NULL,
  fetch_ua TEXT NOT NULL DEFAULT 'auto',
  protocol_hint TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  inline_content TEXT NOT NULL DEFAULT '',
  used_gb REAL NOT NULL DEFAULT 0,
  total_gb REAL NOT NULL DEFAULT 0,
  expire_at INTEGER,
  is_unlimited INTEGER NOT NULL DEFAULT 0,
  raw_node_count INTEGER NOT NULL DEFAULT 0,
  valid_node_count INTEGER NOT NULL DEFAULT 0,
  regions_json TEXT NOT NULL DEFAULT '[]',
  last_sync_at INTEGER,
  last_status TEXT NOT NULL DEFAULT '待同步',
  note TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS nodes (
  id TEXT PRIMARY KEY,
  sub_id TEXT NOT NULL,
  sub_name TEXT NOT NULL,
  raw_name TEXT NOT NULL,
  normalized_name TEXT NOT NULL,
  region TEXT NOT NULL,
  line_tag TEXT NOT NULL,
  protocol TEXT NOT NULL,
  server TEXT NOT NULL,
  port INTEGER NOT NULL,
  cipher_or_param TEXT NOT NULL DEFAULT '',
  raw_config_json TEXT NOT NULL DEFAULT '{}',
  multiplier REAL NOT NULL DEFAULT 1.0,
  latency_ms INTEGER,
  fingerprint TEXT NOT NULL,
  merged_count INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'active',
  filter_reason TEXT NOT NULL DEFAULT '',
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_groups (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  type TEXT NOT NULL DEFAULT 'url-test',
  filter_regex TEXT NOT NULL DEFAULT '.*',
  interval_sec INTEGER NOT NULL DEFAULT 300,
  tolerance_ms INTEGER NOT NULL DEFAULT 20,
  fallback_groups_json TEXT NOT NULL DEFAULT '[]',
  sort_order INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS rules (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL DEFAULT 'override',
  rule_type TEXT NOT NULL,
  title TEXT NOT NULL,
  payload TEXT NOT NULL,
  target_policy TEXT NOT NULL,
  rule_count INTEGER NOT NULL DEFAULT 1,
  no_resolve INTEGER NOT NULL DEFAULT 0,
  sync_meta TEXT NOT NULL DEFAULT 'Local',
  enabled INTEGER NOT NULL DEFAULT 1,
  priority INTEGER NOT NULL DEFAULT 10
);

CREATE TABLE IF NOT EXISTS access_logs (
  id TEXT PRIMARY KEY,
  client_tag TEXT NOT NULL,
  device_ua TEXT NOT NULL,
  ip TEXT NOT NULL,
  isp_geo TEXT NOT NULL,
  status_code INTEGER NOT NULL,
  status_label TEXT NOT NULL,
  target_format TEXT NOT NULL,
  latency_ms INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
