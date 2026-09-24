# Cloudflare WebDAV

一个运行在 Cloudflare Workers 上的轻量级多用户 WebDAV 网盘服务。文件内容存储在 R2，KV 保存目录标记、文件元数据、会话、锁与回收站信息。支持浏览器管理后台和标准 WebDAV 客户端（Windows 资源管理器、macOS Finder、RaiDrive、rclone、curl 等）。

## 功能特性

### WebDAV 协议

- 标准方法：`OPTIONS`、`PROPFIND`、`GET`、`HEAD`、`PUT`、`DELETE`、`MKCOL`、`COPY`、`MOVE`
- **RFC 4918 Class 2 锁**：`LOCK` / `UNLOCK`，支持独占写锁、`Depth` 锁、超时刷新与 `If` 头锁令牌校验，兼容 Office 等编辑器的 LOCK-EDIT-UNLOCK 流程
- **Range 部分内容**：`GET` 支持 `Range` 请求头，返回 `206 Partial Content`，越界返回 `416`
- **条件请求**：`If-Match` / `If-None-Match` 用于写入前置校验，不满足返回 `412`
- **RFC 4331 配额属性**：`PROPFIND` 返回可用容量与已用容量
- 支持 `Depth: 0` / `1` / `infinity` 目录列举
- **流量限制**：默认每分钟 60 次请求、每小时上传 1GB，超出返回 `429`

### 管理后台

浏览器访问 Worker 根路径即可进入管理界面，采用「超级管理员 → 用户 → WebDAV 账户」三级体系：

- **超级管理员**：创建和删除用户、删除用户名下的 WebDAV 账户（含清理 owner 已不存在的孤儿账户）、查看全量访问日志；不可查看任何文件内容
- **普通用户**：修改自己的密码（需校验当前密码）、创建并管理自己名下的 WebDAV 账户（每人最多 2 个）、管理文件、查看自己及名下账户的访问日志、使用回收站
- **文件管理**：浏览、上传、新建目录、删除，删除的文件和目录进入回收站，**30 天内可恢复**（支持批量恢复与永久删除）
- **访问日志**：记录请求方法、路径、状态码、客户端 IP、User-Agent 与操作账户
- **存储用量**：用户管理页展示总容量与已用容量徽章，用户列表包含每人已用空间

### 会话与安全

- 会话 Cookie：`HttpOnly` / `Secure` / `SameSite=Strict`，随机 32 字节 Token，7 天有效
- **登出、修改密码、删除用户均即时吊销服务端会话**，已泄露的 Token 不会残留有效
- 密码使用 PBKDF2-SHA256（10 万次迭代）+ 每账户独立随机盐存储
- **登录防爆破**：同一 IP + 用户名连续失败 5 次锁定 15 分钟
- **公开注册限频**：同一 IP 每小时最多注册 5 次，可用 `ENABLE_PUBLIC_REGISTRATION=false` 完全关闭注册
- 管理后台与 WebDAV 协议（Basic Auth）凭证相互独立

## 架构说明

| 存储 | 用途 |
| --- | --- |
| R2 | 文件字节内容（含回收站对象） |
| KV | 目录标记、文件元数据、账户与凭证、会话、锁、回收站索引、访问日志、限流计数、存储用量缓存 |

- 读取文件时以 R2 为准，KV 异常或延迟不会破坏文件内容
- 每个账户的数据通过 `tenant/<owner>/<username>` 前缀隔离（KV 与 R2 同规则）
- 账户名是存储前缀的组成部分，**创建后不可修改**，只能改密码与 UUID

## 部署

### 先决条件

- Cloudflare 账号已登录，拥有 Worker、KV、R2 的创建和绑定权限
- 资源名称全局唯一，默认名称可能已被占用（被占用时加随机后缀，如 `cf-webdav-files-xyz789`）

### 方式 A：控制台部署（不需要本地 Node）

#### 第 1 步：创建 KV 和 R2

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)，进入 **Storage & databases -> KV**。
2. 点击 **Create a namespace**，创建例如 `cf-webdav-kv`，打开后复制并保存 **Namespace ID**。
3. 进入 **Storage & databases -> R2**，点击 **Create bucket**，创建全局唯一的 Bucket，例如 `cf-webdav-files-xyz789`。

#### 第 2 步：创建 Worker 并添加绑定

1. 进入 **Workers & Pages -> Create application**，创建一个 Worker（例如 `cf-webdav`）。
2. 打开 **Settings -> Variables and Bindings**，添加：

| 类型 | 名称 | 值 |
| --- | --- | --- |
| R2 Bucket binding | `WEBDAV_BUCKET` | 第 1 步创建的 R2 Bucket |
| KV Namespace binding | `WEBDAV_KV` | 第 1 步创建的 KV Namespace |
| Variable | `DAV_PREFIX` | 留空，或填写例如 `team-files` |
| Variable | `ENABLE_ACCESS_LOG` | `true` |

#### 第 3 步：发布代码

**选项 1：Dashboard 直接发布**

1. 打开 Worker，进入 **Edit code**（如要求选择脚本类型，选 **Module Worker**）。
2. 复制 [src/index.ts](src/index.ts) 的全部内容粘贴到编辑器，替换示例代码。
3. 点击 **Save and deploy**。

> 本项目运行时代码只有 [src/index.ts](src/index.ts) 一个文件。[wrangler.toml](wrangler.toml)、`package.json`、`worker-configuration.d.ts` 均不是运行时代码，无需粘贴。如编辑器只接受 JavaScript，需先将 TypeScript 编译后再完整粘贴。

**选项 2：连接 GitHub 自动发布**

1. 在 Worker 的 **Deployments** 页面点击 **Connect to Git**，授权并选择本仓库与部署分支（通常 `main`）。
2. 将第 1 步保存的真实 KV Namespace ID 填入 [wrangler.toml](wrangler.toml) 的 `id` 字段，确认 `bucket_name` 与 R2 Bucket 名称一致，提交推送。
3. 部署设置中填写：
   - **Build command**：`npm run typecheck`
   - **Deploy command**：`npm run deploy`
   - **Root directory**：留空
4. 首次构建发布完成后，访问 Worker 的 `workers.dev` 地址验证。

之后每次推送代码到部署分支即自动发布；也可在 **Deployments** 中对历史部署执行 **Retry deployment**。

#### 管理员账户初始化与新增

新增或更换超级管理员必须通过 Cloudflare 控制台配置 `ADMIN_USERNAME` 和 `ADMIN_PASSWORD`（界面以 2026 年新版控制台为准）：

1. 登录 Cloudflare Dashboard，左侧导航进入 **Workers & Pages**，点击你的 Worker。
2. 进入 **Settings** 标签页，找到 **Variables and Secrets** 区域。
3. 点击 **Add**，填写第一项：
   - **Type**：选择 **Secret**（不要选 **Text**——明文 Text 变量在后续 `wrangler deploy` 时会被清除，Secret 则永久保留且值加密不可见）；
   - **Variable name**：`ADMIN_USERNAME`；
   - **Value**：新的管理员账户名。
4. 点击 **Add variable** 继续添加第二项：
   - **Type**：**Secret**；
   - **Variable name**：`ADMIN_PASSWORD`；
   - **Value**：至少 8 位的密码。
5. 点击 **Deploy** 保存并发布，完成后用该账户登录 Worker 根地址。**Secret 保存后立即隐藏、无法再次查看**，请自行妥善保管。

**修改已有管理员**：在 **Variables and Secrets** 中 **Edit** 对应 Secret 的值后 **Deploy**；若界面不允许直接修改，可删除条目后重新添加。

说明：

- 这组 Secret **仅在账户不存在时一次性引导创建**；之后即使修改 Secret 值，已存在的同名账户也不会被自动覆盖（如需重置密码，请删除该账户对应的 KV 数据或直接改用新的管理员名）。
- 删除这两个 Secret 不会删除 KV 中已保存的管理员账户。
- 如需通过环境变量预设 WebDAV 客户端账户，可使用 `WEBDAV_USERNAME` 和 `WEBDAV_PASSWORD`（建议同样选 Secret 类型）。

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

资源已在控制台创建好时，先把真实 KV Namespace ID 写入 [wrangler.toml](wrangler.toml) 的 `id` 字段，然后：

```bash
npm install
npm run deploy
```

## 本地开发

```bash
cp .dev.vars.example .dev.vars   # 编辑其中的 ADMIN_USERNAME / ADMIN_PASSWORD
npm install
npx wrangler dev --local
```

本地数据写入 `.wrangler/`（已 gitignore）。类型检查：

```bash
npm run typecheck
```

本地测试：

```bash
curl -i -u admin:change-this-local-password -X OPTIONS http://localhost:8787/
printf 'hello\n' | curl -i -u admin:change-this-local-password -T - http://localhost:8787/docs/hello.txt
curl -i -u admin:change-this-local-password -X PROPFIND -H 'Depth: 1' http://localhost:8787/docs/
```

## 首次使用

1. 访问 `https://你的-worker.workers.dev/`，默认账户 `admin / admin123456`（未配置 Secret 时）。
2. **首次登录后请立即通过 Cloudflare Secret 配置新的管理员账户**，或至少让引导账户完成改密。
3. 普通用户可在登录页的注册入口自行注册（默认开启），或由超级管理员在后台创建。
4. 用户登录后创建自己的 WebDAV 账户，获得服务链接、账户名与密码，填入任意 WebDAV 客户端即可使用。
5. 验证协议可用性：

```bash
curl -i -u 账户:密码 -X OPTIONS https://你的-worker.workers.dev/
curl -i -u 账户:密码 -X MKCOL https://你的-worker.workers.dev/test-folder
curl -i -u 账户:密码 -X PROPFIND -H 'Depth: 1' https://你的-worker.workers.dev/
```

## 配置说明

| 配置项 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `WEBDAV_BUCKET` | R2 binding | 是 | 文件内容存储 |
| `WEBDAV_KV` | KV binding | 是 | 元数据、账户、会话、锁、日志等 |
| `DAV_PREFIX` | var | 否 | 路径前缀，留空为根路径，可设 `team-files` |
| `ENABLE_ACCESS_LOG` | var | 否 | `true` 启用访问日志（默认开启，[wrangler.toml](wrangler.toml) 已显式设置） |
| `ENABLE_PUBLIC_REGISTRATION` | var | 否 | 设为 `false` 关闭公开注册，仅超管可在后台创建用户 |
| `ADMIN_USERNAME` | Secret | 否 | 超级管理员账户名，仅在账户不存在时一次性引导 |
| `ADMIN_PASSWORD` | Secret | 否 | 超级管理员密码（≥ 8 位） |
| `WEBDAV_USERNAME` | Secret | 否 | 可选，预设初始 WebDAV 客户端账户 |
| `WEBDAV_PASSWORD` | Secret | 否 | 可选，预设初始 WebDAV 客户端密码 |

未显式设置管理员时，首次引导使用默认账户 `admin / admin123456`。

## 注意事项

- 首次部署后请尽快替换默认管理员凭证（推荐通过 Cloudflare Secret 配置）
- 生产环境始终使用 HTTPS（workers.dev 域名默认启用）
- LOCK/UNLOCK 锁信息存储在 KV 上，受 KV 最终一致性（跨节点传播可达 60 秒）与读-改-写非原子性影响，属于"建议性锁"：可协调行为良好的客户端的 LOCK-EDIT-UNLOCK 流程，但不提供强互斥保证
- 账户创建/查重基于 KV 读-改-写并带冲突重试，极端并发下仍可能返回"操作繁忙"，重试即可
- KV 免费额度有限，访问日志会持续写入；不需要时可将 `ENABLE_ACCESS_LOG` 设为其他值关闭
- 若资源名已被占用，请更换随机后缀，例如 `cf-webdav-kv-a1b2c3`
