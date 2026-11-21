# Tower

**Tower** 是运行在 **Cloudflare Workers + D1 + Cron Triggers** 上的云端网络订阅与路由规则控制平面，统一管理 **Surge 6**、**Surge 5**、**Stash** 与 **Clash.Meta** 的上游订阅拉取、节点清洗整合、策略组与分流规则编排，以及边缘安全下发与远程 MCP 运维。

## 核心特性

- **单 Worker 全栈控制面板**
  - 前端控制台与 Hono 边缘 API、订阅下发端点、托管规则集与远程 MCP 服务运行在同一个 Cloudflare Worker 实例，零服务器运维。
  - 提供 **总览控制台**、**订阅源管理**、**节点整合池**、**策略与规则管理**、**访问与拉取记录** 五大视图，适配桌面、窄屏与移动端，支持浅色 / 深色模式（默认跟随系统）。
- **灵活订阅接入与前置代理拉取**
  - 支持远程订阅 URL、本地配置粘贴/上传导入及自建单节点托管（`local://manual-nodes`）。
  - 内置基于 `cloudflare:sockets` + 用户态 TLS（`@reclaimprotocol/tls`）的 **SOCKS5 / HTTP 前置代理拉取**（`socks5://user:pass@host:port` 或 `host:port:user:pass`），解决部分上游订阅屏蔽 Cloudflare 出口 IP 的问题。
  - 自动解析 `Subscription-Userinfo` 流量配额与到期时间，并通过 Cron Triggers 每 30 分钟自动同步更新。
- **四阶节点清洗流水线与真实 TCP 测速**
  1. **多格式解析**：自动解析 Clash / Stash YAML、Surge `.conf`、Base64 及分享链接（支持 `VLESS`、`AnyTLS`、`Snell`、`Shadowsocks`、`SSR`、`Trojan`、`VMess`、`Hysteria 2`、`Hysteria`、`TUIC`、`WireGuard`）。
  2. **正则与高倍率守卫**：剔除到期/官网等伪节点及超出 `max_multiplier` 阈值的节点。
  3. **入口指纹去重**：按 `protocol:server:port` 合并重复入口并保留低倍率源。
  4. **统一模板重命名**：支持 `{REGION}`、`{LINE_TAG}`、`{PROTOCOL}`、`{SOURCE}`、`{INDEX}`、`{INDEX:02}` 实时映射。
  - 支持通过 `cloudflare:sockets` 对节点执行真实 TCP 握手延迟探测并持久化 `latency_ms`。
- **策略组与分流规则联动编排器**
  - 支持 `select`、`url-test`、`fallback`、`smart` 策略组与嵌套子策略组，修改组名时自动级联更新关联规则与父策略组引用。
  - 内置多跳路由命中模拟器（`simulate_route`）与多端实时编译器，支持 **Surge 6（原生 VLESS / REALITY / XHTTP）**、**Surge 5** 与 **Stash / Clash.Meta YAML**（含 `?target=` 显式指定及客户端 `User-Agent` 自适应）。
- **三层边缘安全与鉴权体系**
  1. **控制面零信任保护（Cloudflare Access）**：`/api/*` 通过 Web Crypto 校验 `Cf-Access-Jwt-Assertion` / `CF_Authorization` 的 RS256 签名（`iss` / `aud` / `exp` / `nbf`）；公网域名未配置 Access 时默认 **Fail-Closed** 锁定，仅对 `localhost` / `127.0.0.1` 自动免密放行。
  2. **可轮转高熵订阅 Token**：默认生成 160-bit 随机 Token（`tk_...`），支持自定义或一键轮转，配合常量时间比对、IP 滑动窗口错误频控（5 分钟内失败 8 次锁定 15 分钟）、未授权静默伪装 `404`、`no-store` 防缓存头、爬虫/预览机器人 UA 拦截及可选代理客户端 UA 白名单。
  3. **托管规则集 HMAC 派生签名**：`/r/:name?sig=...` 基于当前 `sub_token` 派生单向不可逆 `HMAC-SHA256` 签名，不暴露主 Token 且随主 Token 轮换自动失效。
- **内置无状态远程 MCP Server（`/mcp`）**
  - 提供 Streamable HTTP（`POST /mcp`）接口及 19 个运维工具，默认脱敏敏感 Token、订阅 URL 与节点密钥，支持通过 AI 客户端完成节点查询、手动加节点、TCP 测速、规则编排与版本发布。

## 架构概览

```mermaid
flowchart LR
  Up["上游订阅 / 本地导入 / 自建节点"] -->|"直连或 SOCKS5/HTTP 前置代理"| Pipe["四阶清洗流水线 & TCP 测速"]
  Cron["Cron Triggers (*/30 * * * *)"] --> Pipe
  Pipe <--> D1[("Cloudflare D1")]
  D1 --> Compiler["Surge 6 / Surge 5 / Stash 编译器"]
  Compiler --> Sub["/sub/:token (Token + UA 守卫)"]
  D1 --> Ruleset["/r/:name?sig=... (HMAC-SHA256)"]
  D1 <--> Api["/api/* (CF Access JWT)"]
  D1 <--> Mcp["/mcp (Bearer Token / CF Access)"]
```

## 快速开始（本地开发）

```bash
# 1. 安装依赖
npm install

# 2. 从模板生成本地 Wrangler 配置（wrangler.jsonc 已被 .gitignore 忽略，防止误提交个人域名与数据库 ID）
cp wrangler.example.jsonc wrangler.jsonc

# 3. 启动本地开发服务器（自动挂载本地 D1，默认 http://127.0.0.1:8787）
npm run dev
```

> 本地开发访问 `localhost` / `127.0.0.1` 时，若未配置 `CF_ACCESS_*` 与 `MCP_API_TOKEN` 环境变量，控制面 `/api/*` 与 `/mcp` 会自动进入本地免密模式。

### 常用命令

| 命令 | 说明 |
| --- | --- |
| `npm run dev` | 启动 Vite + `@cloudflare/vite-plugin` 本地全栈开发环境 |
| `npm run typecheck` | 执行 `tsc --noEmit` 类型检查 |
| `npm run build` | 执行 TypeScript 编译与生产构建（输出至 `dist/`） |
| `npm run preview` | 生产构建并以 `wrangler dev` 本地预览 |
| `npm run deploy` | 生产构建并部署至 Cloudflare Workers |
| `npm run db:migrate:local` | 对本地 D1 执行 `migrations/` 数据库迁移 |
| `npm run db:migrate:remote` | 对远程生产 D1 执行 `migrations/` 数据库迁移 |

## 部署到 Cloudflare Workers

### 1. 准备配置与远程 D1 数据库

```bash
# 1) 若尚未复制模板，先创建本地配置
cp wrangler.example.jsonc wrangler.jsonc

# 2) 创建远程 D1 数据库，并将输出的 database_id 填入 wrangler.jsonc
npx wrangler d1 create tower-db

# 3) 初始化远程表结构
npm run db:migrate:remote
```

打开你的本地 `wrangler.jsonc`：
- 将 `d1_databases[0].database_id` 替换为上一步创建的真实 UUID；
- 取消注释 `routes` 并填入你的自定义域名（如 `tower.example.com`），模板默认已设置 `"workers_dev": false` 关闭预览子域暴露；
- 执行构建与部署：

```bash
npm run deploy
```

### 2. 配置 Cloudflare Access 零信任鉴权

部署到公网域名后，未配置 Access 时 `/api/*` 会返回 `403 UNCONFIGURED_CF_ACCESS`（Fail-Closed）。按以下步骤启用保护：

1. 进入 **Cloudflare Zero Trust → Access → Applications → Add an application (Self-hosted)**：
   - **Application domain**：填写 `tower.example.com`（保护控制台与 `/api/*`），Policy Action 设为 **Allow**（配置邮箱 OTP 或 GitHub 等登录方式）。
2. **为订阅拉取放行 Bypass 规则**：
   - 新增独立 Application（或子路径规则）覆盖 `tower.example.com/sub/*` 与 `tower.example.com/r/*`，Policy Action 选 **Bypass**（Include: Everyone），确保 Surge / Stash 定时更新无需网页登录，直接由 Worker 校验订阅 Token 与 HMAC 签名。
3. **写入 Worker 鉴权 Secrets**：

```bash
# 填写 Zero Trust Team 名称（如 myteam 或 https://myteam.cloudflareaccess.com）
npx wrangler secret put CF_ACCESS_TEAM_DOMAIN

# 填写步骤 1 中生成的 Application Audience (AUD) Tag
npx wrangler secret put CF_ACCESS_AUD
```

## 订阅下发与规则集端点

| 端点 | 参数 / 行为说明 |
| --- | --- |
| `GET /sub/:token` | 默认根据请求 `User-Agent` 自动识别 `Surge 6` / `Surge 5` / `Stash` / `Clash` |
| `GET /sub/:token?target=surge6` | 强制编译 Surge 6 配置（默认启用原生 VLESS 输出） |
| `GET /sub/:token?target=surge` | 强制编译 Surge 5 配置（默认过滤 VLESS，兼容 `?target=surge5`） |
| `GET /sub/:token?target=stash` | 强制编译 Stash / Clash.Meta YAML（兼容 `?target=clash`、`?target=yaml`） |
| `GET /sub/:token?vless=1` / `0` | 显式控制 Surge 输出中是否包含 VLESS 节点 |
| `GET /r/:name?sig=<hmac>` | 获取签名托管规则集（内置 `ai-suite.list`、`streaming.list`、`telegram-cidr.list`、`reject-telemetry.list`） |

## 内置远程 MCP Server（`/mcp`）

Tower 内置无状态 **Streamable HTTP MCP Server**（`POST /mcp`），支持标准 Bearer Token 鉴权与 Cloudflare Access 校验。

### 1. Token 管理与 Access 放行

Tower 会自动生成并持久化 160-bit 高熵 **MCP Token**（`mcp_...`），可在控制台 **「访问与拉取记录」→「远程 MCP Server 鉴权 Token」** 查看、复制客户端配置、自定义或一键轮转；也可额外注入环境变量密钥：

```bash
npx wrangler secret put MCP_API_TOKEN
```

若开启了 Cloudflare Access 保护整站域名，可二选一放行 `/mcp`：
- **方式 A（推荐）**：为 `tower.example.com/mcp` 添加 Cloudflare Access **Bypass** 规则，由 Worker 校验 `Authorization: Bearer <MCP_TOKEN>`（或 `X-MCP-Token`）。
- **方式 B**：使用 Cloudflare Access Service Token，在客户端请求头携带 `CF-Access-Client-Id` 与 `CF-Access-Client-Secret`。

### 2. MCP 客户端配置示例

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

### 3. 可用 MCP Tools（共 19 个）

| 分类 | Tool 名称 | 功能说明 |
| --- | --- | --- |
| 状态与设置 | `get_platform_state` | 获取全局设置、revision、流水线统计、策略组与规则（敏感字段默认脱敏） |
| 状态与设置 | `update_settings` | 更新重命名模板、过滤正则、最大倍率、去重与 UA 守卫（自动重建节点池） |
| 状态与设置 | `publish_revision` | 递增 `revision` 正式发布版本（可选先同步上游订阅） |
| 订阅与节点 | `list_subscriptions` | 列出订阅源配额、节点统计与状态（URL/代理凭证默认脱敏） |
| 订阅与节点 | `upsert_subscription` | 新增或更新远程/本地订阅源（支持前置代理）并自动重建节点池 |
| 订阅与节点 | `delete_subscription` | 删除订阅源并重建节点池 |
| 订阅与节点 | `sync_subscriptions` | 立即同步指定或全部已启用订阅源 |
| 订阅与节点 | `list_nodes` | 按状态、地区、订阅源、协议或关键词筛选节点 |
| 订阅与节点 | `get_node_detail` | 查看单节点详情、命中策略组及 Surge 5 / Surge 6 / Stash 编译预览 |
| 订阅与节点 | `add_manual_node` | 添加或覆盖自建单条节点至 `local://manual-nodes` 托管源 |
| 订阅与节点 | `delete_manual_node` | 从本地/自建源删除匹配节点并重建节点池 |
| 订阅与节点 | `probe_nodes` | 对目标节点执行真实 TCP 握手延迟测速并更新 `latency_ms` |
| 策略与规则 | `upsert_policy_group` | 新增或更新策略组（改名自动级联更新规则与父策略组引用） |
| 策略与规则 | `delete_policy_group` | 删除策略组并回退引用规则目标 |
| 策略与规则 | `upsert_rule` | 新增或更新分流规则与优先级 |
| 策略与规则 | `delete_rule` | 按 ID 删除分流规则 |
| 策略与规则 | `scaffold_policy_and_rules` | 根据当前节点地区一键生成标准地区策略组与基础规则 |
| 模拟与编译 | `simulate_route` | 模拟域名 / URL / IP / 进程名的路由命中与最终节点解析 |
| 模拟与编译 | `compile_profile` | 实时编译 `surge`、`surge6` 或 `stash` 配置产物与摘要 |

## 技术栈与目录结构

- **技术栈**：Cloudflare Workers · Cloudflare D1 · Cron Triggers · `cloudflare:sockets` · Hono · `@reclaimprotocol/tls` · `yaml` · React 19 · TypeScript · Vite 6
- **目录结构**：
  - `wrangler.example.jsonc`：开源模板配置（复制为 `wrangler.jsonc` 后使用，后者已被 `.gitignore` 忽略）
  - `migrations/`：D1 数据库结构迁移脚本（`0001_init.sql`、`0002_add_fetch_proxy.sql`）
  - `src/client/`：React 19 管理控制台（`views/` 包含五大核心管理视图）
  - `src/shared/`：前后端共享类型、策略组正则匹配与纯 TS `SHA-256` / `HMAC-SHA256` 实现
  - `src/worker/`：Hono 边缘路由、Cloudflare Access / MCP 鉴权、D1 持久化、TCP 测速、`proxyFetch` 前置代理、MCP Server 及 `engine/`（解析、清洗、模拟、编译）

## 安全须知

- `wrangler.jsonc`、`.dev.vars`、`.dev.vars.*`、`.env`、`.env.*`、`.wrangler/` 与 `dist/` 均已纳入 `.gitignore`，请勿提交包含个人自定义域名、D1 `database_id` 或真实密钥的文件。
- 公网部署时请务必配置 Cloudflare Access 与高熵订阅 / MCP Token，并在完成初始验证后及时通过控制台轮转密钥。

## 开源协议

基于 [MIT License](./LICENSE) 开源。
