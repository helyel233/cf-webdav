# Cloudflare WebDAV

一个运行在 Cloudflare Workers 上的轻量级多用户 WebDAV 网盘。文件内容存 R2，元数据存 KV，全部逻辑在一个 TypeScript 文件内。支持浏览器管理后台与标准 WebDAV 客户端（Windows 资源管理器、macOS Finder、RaiDrive、rclone、curl 等）。

## 功能总览

| 领域 | 能力 |
| --- | --- |
| WebDAV 协议 | RFC 4918 Class 1 + 2、RFC 6578 增量同步、RFC 5323 检索、RFC 4331 配额、Range/条件请求 |
| 管理后台 | 三级账户体系、文件管理、回收站（30 天）、访问日志、存储用量 |
| 安全 | PBKDF2 密码、TOTP 两步验证、应用专用密码、IP 白名单、登录防爆破、Turnstile 注册校验 |
| 合规 | 审计日志、日志保留/IP 脱敏可配置、个人数据导出、security.txt / robots.txt |

### WebDAV 协议

- **标准方法**：`OPTIONS` `PROPFIND` `GET` `HEAD` `PUT` `DELETE` `MKCOL` `COPY` `MOVE`，支持 `Depth: 0 / 1 / infinity`
- **Class 2 锁**：`LOCK` / `UNLOCK` 独占写锁、`Depth` 锁、超时刷新、`If` 头锁令牌校验，兼容 Office 的 LOCK-EDIT-UNLOCK 流程
- **增量同步（RFC 6578）**：`REPORT` `sync-collection`，凭 `sync-token` 只拉取上次同步后的新增/修改/删除条目，适合 rclone bisync 与移动端离线缓存
- **检索（RFC 5323）**：`SEARCH` 按文件名子串匹配，支持标准 XML `<d:literal>` 与 SQL 式 `LIKE '%关键词%'` 两种写法
- **Range 部分内容**：`GET` 支持 `Range`，返回 `206`，越界返回 `416`
- **条件请求**：`If-Match` / `If-None-Match` 写入前置校验，不满足返回 `412`
- **配额（RFC 4331）**：`PROPFIND` 返回可用/已用容量与 `creationdate`
- **路径规范化**：Unicode NFC 归一（避免 macOS Finder NFD 文件名跨平台重复），拒绝控制字符
- **语义化错误**：带请求体的 `MKCOL` → `415`；`GET` 集合 → `405`；配置 `MAX_UPLOAD_BYTES` 后超限 `PUT` → `413` 并附 `X-Upload-Limit` 头
- **流量限制**：默认每分钟 60 次请求、每小时上传 1 GB，超出返回 `429`

### 管理后台

浏览器访问 Worker 根路径进入管理界面，「超级管理员 → 用户 → WebDAV 账户」三级体系：

- **超级管理员**：创建/删除用户、管理用户名下 WebDAV 账户、查看全量访问日志与审计日志；不可查看任何文件内容
- **普通用户**：修改自己的密码、创建并管理名下 WebDAV 账户（每人最多 2 个）、管理文件、使用回收站、**一键导出个人数据**（`/?api=export-data`，JSON，不含密码哈希）
- **文件管理**：浏览、上传、新建目录、删除；删除的文件进入回收站，**30 天内可恢复**（支持批量恢复与永久删除）
- **访问日志**：请求方法、路径、状态码、客户端 IP、User-Agent 与操作账户；保留天数可配置（默认 30 天），可开启 IP 脱敏
- **审计日志**：登录、注册、改密、创建/删除账户与用户、调整配额、安全设置变更等敏感操作全量留痕，仅超管可查看（`/?view=audit`）并导出 CSV（`/?view=audit&export=csv`），保留 365 天

### 安全

- **凭证存储**：PBKDF2-SHA256（10 万次迭代）+ 每账户独立随机盐；密码策略可配置（最小长度 + 必须同时包含字母与数字）
- **会话**：Cookie `HttpOnly` / `Secure` / `SameSite=Strict`，随机 32 字节 Token，7 天有效；可选空闲超时；登出、改密、删户均即时吊销服务端会话
- **登录防爆破**：同一 IP + 用户名失败次数与锁定时长可配置（默认 5 次 / 15 分钟）；公开注册按 IP 每小时限 5 次
- **TOTP 两步验证**：用户可自助绑定/解绑验证器动态码
- **应用专用密码**：第三方客户端用独立密码访问 WebDAV，主密码不外泄，可单独吊销（上限 10 个）
- **IP 白名单**：支持精确 IP / IPv4 前缀 / CIDR，登录、后台会话与 WebDAV 访问三处生效，保存时防自锁
- **Turnstile**：配置站点/服务端密钥对后，公开注册需通过人机校验
- **合规端点**：`/robots.txt` 与 `/.well-known/security.txt`（RFC 9116，联系方式用 `SECURITY_CONTACT` 配置）无需认证即可访问
- 管理后台与 WebDAV Basic Auth 凭证相互独立

## 部署

### 方式 A：控制台部署（不需要本地 Node）

**1. 创建 KV 和 R2**

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)，进入 **Storage & databases -> KV**，**Create a namespace** 创建例如 `cf-webdav-kv`，复制 **Namespace ID**。
2. 进入 **Storage & databases -> R2**，**Create bucket** 创建全局唯一的 Bucket，例如 `cf-webdav-files-xyz789`。

**2. 创建 Worker 并添加绑定**

进入 **Workers & Pages -> Create application** 创建 Worker，在 **Settings -> Variables and Bindings** 添加：

| 类型 | 名称 | 值 |
| --- | --- | --- |
| R2 Bucket binding | `WEBDAV_BUCKET` | 第 1 步创建的 R2 Bucket |
| KV Namespace binding | `WEBDAV_KV` | 第 1 步创建的 KV Namespace |
| Variable | `DAV_PREFIX` | 留空，或填写例如 `team-files` |
| Variable | `ENABLE_ACCESS_LOG` | `true` |

**3. 发布代码**

*选项 1：Dashboard 直接发布*

1. 打开 Worker，进入 **Edit code**（如要求选择脚本类型，选 **Module Worker**）。
2. 复制 [src/index.ts](src/index.ts) 全部内容粘贴到编辑器，点击 **Save and deploy**。

> 运行时代码只有 [src/index.ts](src/index.ts) 一个文件，[wrangler.toml](wrangler.toml)、`package.json` 等均无需粘贴。如编辑器只接受 JavaScript，需先编译 TypeScript 再粘贴。

*选项 2：连接 GitHub 自动发布*

1. 在 Worker 的 **Deployments** 页面点击 **Connect to Git**，选择本仓库与部署分支（通常 `main`）。
2. 把真实 KV Namespace ID 填入 [wrangler.toml](wrangler.toml) 的 `id` 字段，确认 `bucket_name` 与 R2 Bucket 名称一致，提交推送。
3. 部署设置：**Build command** `npm run typecheck`；**Deploy command** `npm run deploy`；**Root directory** 留空。

之后每次推送代码到部署分支即自动发布。

**4. 管理员账户初始化**

新增或更换超级管理员通过 Cloudflare 控制台配置 Secret（界面以 2026 年新版控制台为准）：

1. 进入 Worker 的 **Settings -> Variables and Secrets**。
2. 添加 **Secret** 类型变量（不要选 Text——明文 Text 会在后续 `wrangler deploy` 时被清除，Secret 永久保留且加密不可见）：
   - `ADMIN_USERNAME`：管理员账户名
   - `ADMIN_PASSWORD`：至少 8 位的密码
3. 点击 **Deploy** 保存发布。**Secret 保存后立即隐藏、无法再次查看**。

说明：

- 这组 Secret **仅在同名账户不存在时一次性引导创建**；之后修改 Secret 值不会覆盖已有账户（如需重置密码，请删除该账户的 KV 数据或改用新的管理员名）。
- 删除 Secret 不会删除 KV 中已保存的管理员账户。
- 可用 `WEBDAV_USERNAME` / `WEBDAV_PASSWORD`（建议同样选 Secret）预设初始 WebDAV 客户端账户。

### 方式 B：本地自动创建资源并部署

```bash
npm install
npx wrangler login
npm run deploy:setup
```

脚本会创建或复用 KV/R2、把真实 KV ID 回写到 [wrangler.toml](wrangler.toml) 并执行 `wrangler deploy`。自定义资源名：

```bash
WEBDAV_KV_TITLE=my-kv-name WEBDAV_R2_BUCKET=my-bucket-name npm run deploy:setup
```

### 方式 C：仅手动部署

资源已在控制台创建好时，把真实 KV Namespace ID 写入 [wrangler.toml](wrangler.toml) 的 `id` 字段，然后：

```bash
npm install
npm run deploy
```

## 配置说明

| 配置项 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `WEBDAV_BUCKET` | R2 binding | 是 | 文件内容存储 |
| `WEBDAV_KV` | KV binding | 是 | 元数据、账户、会话、锁、日志等 |
| `DAV_PREFIX` | var | 否 | 路径前缀，留空为根路径，可设 `team-files` |
| `ENABLE_ACCESS_LOG` | var | 否 | `true` 启用访问日志（默认开启，[wrangler.toml](wrangler.toml) 已显式设置） |
| `ENABLE_PUBLIC_REGISTRATION` | var | 否 | 设为 `false` 关闭公开注册，仅超管可在后台创建用户 |
| `LOG_RETENTION_DAYS` | var | 否 | 访问日志保留天数（默认 30，范围 1-365），到期靠 KV TTL 自动过期 |
| `LOG_IP_REDACT` | var | 否 | `true` 时访问日志中客户端 IP 脱敏（IPv4 保留前三段 / IPv6 保留前四组） |
| `MAX_UPLOAD_BYTES` | var | 否 | 单次 PUT 上传字节上限（0/缺省 = 不限制），超出返回 `413` |
| `MIN_PASSWORD_LENGTH` | var | 否 | 密码最小长度（默认 8，范围 8-128），另要求同时包含字母与数字 |
| `SESSION_IDLE_MINUTES` | var | 否 | 会话空闲超时分钟数（0/缺省 = 不启用） |
| `LOGIN_MAX_ATTEMPTS` | var | 否 | 登录防爆破窗口期内最大失败次数（默认 5） |
| `LOGIN_LOCK_MINUTES` | var | 否 | 登录防爆破锁定分钟数（默认 15） |
| `SECURITY_CONTACT` | var | 否 | security.txt 漏洞报告联系方式，如 `mailto:security@example.com` |
| `TURNSTILE_SITE_KEY` | var | 否 | Turnstile 站点密钥（与 Secret 同时配置才启用，用于公开注册） |
| `TURNSTILE_SECRET_KEY` | Secret | 否 | Turnstile 服务端校验密钥 |
| `ADMIN_USERNAME` | Secret | 否 | 超级管理员账户名，仅在账户不存在时一次性引导 |
| `ADMIN_PASSWORD` | Secret | 否 | 超级管理员密码（≥ 8 位） |
| `WEBDAV_USERNAME` | Secret | 否 | 可选，预设初始 WebDAV 客户端账户 |
| `WEBDAV_PASSWORD` | Secret | 否 | 可选，预设初始 WebDAV 客户端密码 |

未显式设置管理员时，首次引导使用默认账户 `admin / admin123456`——**部署后请立即更换**。

## 快速上手

1. 访问 `https://你的-worker.workers.dev/` 登录（默认 `admin / admin123456`，务必尽快通过 Secret 更换）。
2. 普通用户可在登录页注册入口自行注册（默认开启），或由超管在后台创建。
3. 用户登录后创建自己的 WebDAV 账户，把服务链接、账户名与密码填入任意 WebDAV 客户端即可。
4. 验证协议可用性：

```bash
curl -i -u 账户:密码 -X OPTIONS https://你的-worker.workers.dev/
curl -i -u 账户:密码 -X MKCOL https://你的-worker.workers.dev/test-folder
curl -i -u 账户:密码 -X PROPFIND -H 'Depth: 1' https://你的-worker.workers.dev/
```

## 本地开发

```bash
cp .dev.vars.example .dev.vars   # 编辑其中的 ADMIN_USERNAME / ADMIN_PASSWORD
npm install
npx wrangler dev --local
```

本地数据写入 `.wrangler/`（已 gitignore）。类型检查：`npm run typecheck`。

本地回归测试示例：

```bash
# 基础方法
curl -i -u admin:change-this-local-password -X OPTIONS http://localhost:8787/
printf 'hello\n' | curl -i -u admin:change-this-local-password -T - http://localhost:8787/docs/hello.txt
curl -i -u admin:change-this-local-password -X PROPFIND -H 'Depth: 1' http://localhost:8787/docs/

# RFC 6578 增量同步：首次获取 sync-token，再凭 token 拉取变更
curl -s -u admin:change-this-local-password -X REPORT -H 'Depth: 1' \
  -H 'Content-Type: application/xml' --data \
  '<?xml version="1.0"?><d:sync-collection xmlns:d="DAV:"><d:sync-token/><d:sync-prop><d:getetag/></d:sync-prop></d:sync-collection>' \
  http://localhost:8787/docs/

# RFC 5323 文件名检索
curl -s -u admin:change-this-local-password -X SEARCH -H 'Content-Type: application/xml' --data \
  '<?xml version="1.0"?><d:searchrequest xmlns:d="DAV:"><d:basicsearch><d:from><d:scope><d:href>/</d:href><d:depth>infinity</d:depth></d:scope></d:from><d:where><d:like><d:prop><d:displayname/></d:prop><d:literal>%hello%</d:literal></d:like></d:where></d:basicsearch></d:searchrequest>' \
  http://localhost:8787/

# 合规端点（无需认证）
curl -s http://localhost:8787/robots.txt
curl -s http://localhost:8787/.well-known/security.txt
```

## 架构说明

| 存储 | 用途 |
| --- | --- |
| R2 | 文件字节内容（含回收站对象） |
| KV | 目录标记、文件元数据、账户与凭证、会话、锁、回收站索引、访问/审计日志、同步状态、限流计数、存储用量缓存 |

- 读取文件时以 R2 为准，KV 异常或延迟不会破坏文件内容
- 每个账户的数据通过 `tenant/<owner>/<username>` 前缀隔离（KV 与 R2 同规则）
- 账户名是存储前缀的组成部分，**创建后不可修改**，只能改密码与 UUID

## 注意事项

- 首次部署后请尽快替换默认管理员凭证（推荐通过 Cloudflare Secret 配置）
- 生产环境始终使用 HTTPS（workers.dev 域名默认启用）
- LOCK/UNLOCK 锁信息存储在 KV 上，受 KV 最终一致性（跨节点传播可达 60 秒）与读-改-写非原子性影响，属于"建议性锁"：可协调行为良好的客户端的 LOCK-EDIT-UNLOCK 流程，但不提供强互斥保证
- 增量同步状态（sync-token）按账户存于 KV，同样受 KV 最终一致性影响，仅作增量同步参考
- 账户创建/查重基于 KV 读-改-写并带冲突重试，极端并发下仍可能返回"操作繁忙"，重试即可
- KV 免费额度有限，访问日志会持续写入；不需要时可将 `ENABLE_ACCESS_LOG` 设为其他值关闭
- 若资源名已被占用，请更换随机后缀，例如 `cf-webdav-kv-a1b2c3`

## License

[MIT](LICENSE)
