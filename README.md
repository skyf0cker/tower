# Tower

**English** | [简体中文](./README.zh-CN.md)

**Tower** is a cloud-native proxy subscription and routing control plane running on **Cloudflare Workers + D1 + Cron Triggers**. It unifies upstream subscription fetching, 4-stage node normalization, policy-group & routing-rule orchestration, edge security delivery, and remote MCP operations for **Surge 6**, **Surge 5**, **Stash**, and **Clash.Meta**.

## Key Features

- **Single-Worker Full-Stack Control Plane**
  - Runs the React management dashboard alongside the Hono edge API, subscription delivery endpoints, hosted rule-sets, and remote MCP server in a single Cloudflare Worker with zero server maintenance.
  - Includes five dedicated views (**Overview**, **Subscriptions**, **Node Pool**, **Policy & Rules Studio**, and **Access Logs**) with responsive desktop/tablet/mobile layouts and Light/Dark themes (following system preference by default).
- **Flexible Subscription Ingestion & Upstream Proxy Fetching**
  - Supports remote subscription URLs, local config paste/file import, and managed manual nodes (`local://manual-nodes`).
  - Built-in **SOCKS5 / HTTP upstream proxy fetcher** (`socks5://user:pass@host:port` or `host:port:user:pass`) powered by `cloudflare:sockets` and userspace TLS (`@reclaimprotocol/tls`) to bypass upstream blocks on Cloudflare egress IPs.
  - Automatically parses `Subscription-Userinfo` quota/expiration headers and refreshes enabled subscriptions every 30 minutes via Cron Triggers.
- **4-Stage Node Integration Pipeline & Real TCP Latency Probing**
  1. **Multi-Format Parsing**: Parses Clash/Stash YAML, Surge `.conf`, Base64 lists, and share URIs (`VLESS`, `AnyTLS`, `Snell`, `Shadowsocks`, `SSR`, `Trojan`, `VMess`, `Hysteria 2`, `Hysteria`, `TUIC`, `WireGuard`).
  2. **Regex & Multiplier Guard**: Filters out expiration/info dummy entries and nodes exceeding `max_multiplier`.
  3. **Ingress Fingerprint Deduplication**: Merges duplicate `protocol:server:port` endpoints while keeping the lower-multiplier source.
  4. **Template-Based Renaming**: Maps normalized names dynamically using `{REGION}`, `{LINE_TAG}`, `{PROTOCOL}`, `{SOURCE}`, `{INDEX}`, and `{INDEX:02}`.
  - Performs real TCP handshake latency probing via `cloudflare:sockets` and persists `latency_ms` in D1.
- **Policy Group & Routing Rule Orchestrator**
  - Supports `select`, `url-test`, `fallback`, and `smart` groups with nested sub-groups and automatic cascade renaming across linked rules and parent groups.
  - Includes a multi-hop route hit simulator (`simulate_route`) and real-time multi-target compilers for **Surge 6 (native VLESS / REALITY / XHTTP)**, **Surge 5**, and **Stash / Clash.Meta YAML** (supporting explicit `?target=` overrides and `User-Agent` auto-detection).
- **Three-Layer Edge Security & Authentication**
  1. **Zero Trust Control Plane (Cloudflare Access)**: Protects `/api/*` by verifying `Cf-Access-Jwt-Assertion` / `CF_Authorization` RS256 signatures (`iss`, `aud`, `exp`, `nbf`) via Web Crypto; defaults to **Fail-Closed** on public domains when Access variables are unset, allowing passwordless access only on `localhost` / `127.0.0.1`.
  2. **Rotatable High-Entropy Subscription Token**: Automatically provisions a 160-bit random token (`tk_...`) with manual editing and one-click rotation, constant-time comparison, sliding-window IP failure rate limiting (8 failures in 5 minutes triggers a 15-minute lockout), stealth `404` responses, `no-store` headers, crawler/link-preview UA blocking, and an optional strict proxy-client UA allowlist.
  3. **HMAC-Derived Rule-Set Signatures**: `/r/:name?sig=...` derives an irreversible, file-scoped `HMAC-SHA256` signature from `sub_token` so hosted rule-set links never expose the primary token and automatically invalidate upon token rotation.
- **Built-in Stateless Remote MCP Server (`/mcp`)**
  - Exposes a Streamable HTTP (`POST /mcp`) server with 19 operational tools. Sensitive tokens, subscription URLs, proxy credentials, and node secrets are redacted by default unless explicitly requested.

## Architecture Overview

```mermaid
flowchart LR
  Up["Upstream Subscriptions / Local Import / Manual Nodes"] -->|"Direct or SOCKS5/HTTP Proxy"| Pipe["4-Stage Pipeline & TCP Probe"]
  Cron["Cron Triggers (*/30 * * * *)"] --> Pipe
  Pipe <--> D1[("Cloudflare D1")]
  D1 --> Compiler["Surge 6 / Surge 5 / Stash Compiler"]
  Compiler --> Sub["/sub/:token (Token + UA Guard)"]
  D1 --> Ruleset["/r/:name?sig=... (HMAC-SHA256)"]
  D1 <--> Api["/api/* (CF Access JWT)"]
  D1 <--> Mcp["/mcp (Bearer Token / CF Access)"]
```

## Quick Start (Local Development)

```bash
# 1. Install dependencies
npm install

# 2. Copy the template Wrangler config (wrangler.jsonc is gitignored to prevent leaking personal domains or D1 IDs)
cp wrangler.example.jsonc wrangler.jsonc

# 3. Start the local dev server with auto-mounted local D1 (default: http://127.0.0.1:8787)
npm run dev
```

> When accessed via `localhost` or `127.0.0.1` without `CF_ACCESS_*` or `MCP_API_TOKEN` configured, `/api/*` and `/mcp` automatically operate in local development mode without requiring login headers.

### Available Scripts

| Script | Description |
| --- | --- |
| `npm run dev` | Start Vite + `@cloudflare/vite-plugin` full-stack local dev server |
| `npm run typecheck` | Run TypeScript type checking (`tsc --noEmit`) |
| `npm run build` | Build worker & client production bundles into `dist/` |
| `npm run preview` | Build production assets and preview locally with `wrangler dev` |
| `npm run deploy` | Build and deploy to Cloudflare Workers |
| `npm run db:migrate:local` | Apply `migrations/` SQL schema changes to local D1 |
| `npm run db:migrate:remote` | Apply `migrations/` SQL schema changes to remote production D1 |

## Deploying to Cloudflare Workers

### 1. Configure Wrangler & Remote D1

```bash
# 1) Create your local wrangler.jsonc from the template if you haven't already
cp wrangler.example.jsonc wrangler.jsonc

# 2) Create a remote D1 database and copy the generated database_id into wrangler.jsonc
npx wrangler d1 create tower-db

# 3) Apply migrations to remote D1
npm run db:migrate:remote
```

Edit your local `wrangler.jsonc`:
- Replace `d1_databases[0].database_id` with your real D1 UUID;
- Uncomment `routes` and set your custom domain (e.g., `tower.example.com`), keeping `"workers_dev": false` so the default `*.workers.dev` subdomain stays disabled;
- Build and deploy:

```bash
npm run deploy
```

### 2. Enable Cloudflare Access Zero Trust Authentication

On public hostnames without Access configured, `/api/*` fails closed with `403 UNCONFIGURED_CF_ACCESS`. Enable authentication as follows:

1. In **Cloudflare Zero Trust → Access → Applications → Add an application (Self-hosted)**:
   - Set **Application domain** to `tower.example.com` (protects the dashboard UI and `/api/*`), with Policy Action set to **Allow** (e.g., email OTP or GitHub identity).
2. **Add Bypass rules for client subscription endpoints**:
   - Create a separate application (or path-scoped rule) covering `tower.example.com/sub/*` and `tower.example.com/r/*` with Policy Action set to **Bypass** (Include: Everyone) so Surge/Stash clients can fetch updates directly while the Worker validates the subscription token and HMAC signature.
3. **Set Worker secrets for JWT verification**:

```bash
# Your Zero Trust Team domain (e.g., myteam or https://myteam.cloudflareaccess.com)
npx wrangler secret put CF_ACCESS_TEAM_DOMAIN

# Application Audience (AUD) Tag from Step 1
npx wrangler secret put CF_ACCESS_AUD
```

## Subscription & Rule-Set Endpoints

| Endpoint | Behavior / Parameters |
| --- | --- |
| `GET /sub/:token` | Auto-detects `Surge 6`, `Surge 5`, `Stash`, or `Clash` from request `User-Agent` |
| `GET /sub/:token?target=surge6` | Compiles a Surge 6 profile (native VLESS enabled by default) |
| `GET /sub/:token?target=surge` | Compiles a Surge 5 profile (VLESS filtered out by default; alias `?target=surge5`) |
| `GET /sub/:token?target=stash` | Compiles Stash / Clash.Meta YAML (aliases `?target=clash`, `?target=yaml`) |
| `GET /sub/:token?vless=1` / `0` | Explicitly enable or disable VLESS nodes in Surge profiles |
| `GET /r/:name?sig=<hmac>` | Serves HMAC-signed hosted rule-sets (`ai-suite.list`, `streaming.list`, `telegram-cidr.list`, `reject-telemetry.list`) |

## Built-in Remote MCP Server (`/mcp`)

Tower includes a stateless **Streamable HTTP MCP Server** (`POST /mcp`) secured by Bearer token or Cloudflare Access authentication.

### 1. Token Management & Access Configuration

Tower automatically generates and persists a 160-bit **MCP Token** (`mcp_...`), which can be viewed, copied as client JSON, customized, or rotated in the dashboard under **Access Logs → Remote MCP Server Auth Token**. You can also set an optional secret via Wrangler:

```bash
npx wrangler secret put MCP_API_TOKEN
```

If Cloudflare Access protects the domain, allow `/mcp` using either option:
- **Option A (Recommended)**: Add a Cloudflare Access **Bypass** rule for `tower.example.com/mcp`, letting the Worker verify `Authorization: Bearer <MCP_TOKEN>` (or `X-MCP-Token`).
- **Option B**: Use a Cloudflare Access Service Token (`CF-Access-Client-Id` and `CF-Access-Client-Secret` headers).

### 2. MCP Client Configuration Example

```json
{
  "mcpServers": {
    "tower": {
      "url": "https://tower.example.com/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_MCP_API_TOKEN"
      }
    }
  }
}
```

### 3. Available MCP Tools (19 Total)

| Category | Tool Name | Description |
| --- | --- | --- |
| State & Settings | `get_platform_state` | Retrieve global settings, revision, pipeline stats, policy groups, and rules (secrets redacted by default) |
| State & Settings | `update_settings` | Update rename template, exclusion regex, max multiplier, dedup, and UA guards (rebuilds node pool) |
| State & Settings | `publish_revision` | Increment `revision` to publish a new config release (optionally syncing upstream subscriptions first) |
| Subscriptions & Nodes | `list_subscriptions` | List subscriptions, traffic quotas, node counts, and sync status (URLs & proxy passwords redacted by default) |
| Subscriptions & Nodes | `upsert_subscription` | Create or update remote/local subscriptions (with optional upstream proxy) and rebuild the node pool |
| Subscriptions & Nodes | `delete_subscription` | Delete a subscription source and rebuild the node pool |
| Subscriptions & Nodes | `sync_subscriptions` | Immediately sync one or all enabled subscriptions |
| Subscriptions & Nodes | `list_nodes` | Filter nodes by status, region, subscription ID, protocol, or keyword |
| Subscriptions & Nodes | `get_node_detail` | Inspect a single node, matched policy groups, and Surge 5 / Surge 6 / Stash compiled previews |
| Subscriptions & Nodes | `add_manual_node` | Add or replace a self-hosted node in the managed `local://manual-nodes` source |
| Subscriptions & Nodes | `delete_manual_node` | Delete matching nodes from `local://` sources and rebuild the node pool |
| Subscriptions & Nodes | `probe_nodes` | Run real TCP handshake latency probes on target nodes and persist `latency_ms` |
| Policies & Rules | `upsert_policy_group` | Create or update a policy group (renaming cascades to rules and parent groups) |
| Policies & Rules | `delete_policy_group` | Delete a policy group and fall back any referencing rules |
| Policies & Rules | `upsert_rule` | Create or update a routing rule and its priority |
| Policies & Rules | `delete_rule` | Delete a routing rule by ID |
| Policies & Rules | `scaffold_policy_and_rules` | Auto-generate standard regional policy groups and starter rules from active nodes |
| Simulation & Compile | `simulate_route` | Simulate route matching and final resolved node for a domain, URL, IP, or process name |
| Simulation & Compile | `compile_profile` | Compile live `surge`, `surge6`, or `stash` configuration artifacts with summary metadata |

## Tech Stack & Project Structure

- **Tech Stack**: Cloudflare Workers · Cloudflare D1 · Cron Triggers · `cloudflare:sockets` · Hono · `@reclaimprotocol/tls` · `yaml` · React 19 · TypeScript · Vite 6
- **Project Structure**:
  - `wrangler.example.jsonc` — Open-source Wrangler template (copy to gitignored `wrangler.jsonc` before running or deploying)
  - `migrations/` — D1 SQLite schema migrations (`0001_init.sql`, `0002_add_fetch_proxy.sql`)
  - `src/client/` — React 19 dashboard (`views/` contains the five main control-plane views)
  - `src/shared/` — Shared types, policy group regex matcher, and pure TypeScript `SHA-256` / `HMAC-SHA256` implementation
  - `src/worker/` — Hono routes, Cloudflare Access & MCP auth, D1 persistence, TCP probing, `proxyFetch` upstream proxy client, MCP server, and `engine/` (parser, pipeline, simulator, compiler)

## Security Notes

- `wrangler.jsonc`, `.dev.vars`, `.dev.vars.*`, `.env`, `.env.*`, `.wrangler/`, and `dist/` are excluded via `.gitignore`. Never commit personal custom domains, D1 `database_id` values, or real tokens.
- Always configure Cloudflare Access and rotate default tokens before exposing a deployment publicly.

## License

Released under the [MIT License](./LICENSE).
