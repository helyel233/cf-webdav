# Cloudflare WebDAV

一个运行在 Cloudflare Workers 上的轻量 WebDAV 服务。文件内容保存在 R2，KV 保存目录标记、文件元数据和会话信息，支持浏览器、curl、Windows/macOS/Linux WebDAV 客户端访问。

## 功能概览

支持 `OPTIONS`、`PROPFIND`、`GET`、`HEAD`、`PUT`、`DELETE`、`MKCOL`、`COPY` 和 `MOVE`。

默认首次登录账号为 `admin` / `admin123456`，登录 `/__admin` 后可修改用户名和密码，更新后的凭证哈希保存在 KV 中。

新增能力：
- 访问日志：记录请求方法、路径、状态码、客户端 IP 等，可在后台查看
- 流量限制：默认每分钟 60 次请求、每小时上传 1GB 上限，超出返回 429
- 回收站：删除的文件和目录可恢复，30 天内保留

## 先决条件

部署前请确认：
- 你的 Cloudflare 账号已登录
- 账号拥有 Worker、KV、R2 的创建和绑定权限
- 资源名称全局唯一，默认名称可能已被占用

## 一键部署流程

### 方式 A：控制台手动创建并绑定（最适合小白，推荐优先）

这是最容易上手的方案，适合没有本地 Node 环境、或不想先碰 Wrangler 的用户。

最简的控制台部署步骤清单：

1. 登录 Cloudflare Dashboard
2. 进入 **Workers & Pages -> Create application**
3. 创建一个 Worker，并给它起一个名字，例如 `cf-webdav`
4. 打开 **Settings -> Variables and Bindings**
5. 点击 **Add binding**，依次添加：
   - `WEBDAV_BUCKET`：新建或选择一个 R2 Bucket
   - `WEBDAV_KV`：新建或选择一个 KV Namespace
   - `DAV_PREFIX`：可选，默认留空
   - `ENABLE_ACCESS_LOG`：可选，建议设为 `true`
6. 如果需要自定义管理账号，打开 **Settings -> Secrets**，添加：
   - `ADMIN_USERNAME`
   - `ADMIN_PASSWORD`
7. 保存绑定配置后，点击 **Deploy**，等待发布完成
8. 打开 `https://你的-worker.workers.dev/__admin`，首次登录使用 `admin / admin123456`

> 重要：如果你使用 GitHub 连接部署，Cloudflare 仍会执行 `wrangler deploy` 并读取 [wrangler.toml](wrangler.toml)。即使你已经在 Dashboard 中手动绑定了 KV/R2，也必须先把其中的 `id` 改成真实的 KV Namespace ID；`replace-during-setup` 不能用于部署。

如果你使用 **GitHub 连接部署**，可以在构建设置中填写以下默认命令：

```bash
# 构建命令（Build command）
# 留空即可，或者填写：
npm run typecheck

# 部署命令（Deploy command）
npm run deploy
```

> 说明：手动在 Dashboard 创建并绑定 Worker 时，不需要填写或执行这两条命令，直接点击 **Deploy** 即可。这组命令只适合 GitHub 连接部署流程，并且要求 [wrangler.toml](wrangler.toml) 中已经写入真实的 KV Namespace ID。

> 正确做法：
> - 方式 A：使用控制台按钮部署，或者让 GitHub 自动部署
> - 方式 B：在本地先执行 `npm run deploy:setup`，自动写入真实的 KV Namespace ID，再执行 `npm run deploy`

### 方式 B：本地自动创建资源并部署

适合已经有本地 Node 环境，而且希望自动创建 KV/R2 的用户。

```bash
npm install
npx wrangler login
npm run deploy:setup
```

这个脚本会：
1. 创建或复用 KV Namespace
2. 创建或复用 R2 Bucket
3. 把真实的 KV ID 回写到 [wrangler.toml](wrangler.toml)
4. 执行 `wrangler deploy`

如果你使用自定义资源名，可设置：

```bash
WEBDAV_KV_TITLE=my-kv-name WEBDAV_R2_BUCKET=my-bucket-name npm run deploy:setup
```

### 方式 C：仅手动部署

如果资源已在控制台创建好，先把真实 KV Namespace ID 写入 [wrangler.toml](wrangler.toml) 的 `id` 字段，然后执行：

```bash
npm install
npm run deploy
```

> 首次使用时不建议直接手动部署，因为 KV ID 是账号专属值，不能直接复用他人配置。

## 本地开发

复制 `.dev.vars.example` 为 `.dev.vars`，然后修改本地密码：

```bash
cp .dev.vars.example .dev.vars
```

编辑 `.dev.vars`：

```bash
ADMIN_USERNAME=admin
ADMIN_PASSWORD=change-this-local-password
```

然后启动本地 Worker：

```bash
npm install
npx wrangler dev --local
```

本地数据会写入 `.wrangler/`，不会提交到 Git。每次修改后可执行：

```bash
npm run typecheck
```

## 验证步骤

### 1. 访问管理页

打开：

```text
https://你的-worker.workers.dev/__admin
```

首次登录使用：

```text
admin / admin123456
```

### 2. 测试 WebDAV

```bash
curl -i -u admin:admin123456 -X OPTIONS https://你的-worker.workers.dev/
curl -i -u admin:admin123456 -X MKCOL https://你的-worker.workers.dev/test-folder
curl -i -u admin:admin123456 -X PROPFIND -H 'Depth: 1' https://你的-worker.workers.dev/
```

### 3. 查看日志

在 Cloudflare Dashboard 中打开 Worker 页面，进入 **Logs**，可实时查看请求日志与错误信息。

## 配置说明

| 配置项 | 类型 | 说明 |
| --- | --- | --- |
| `WEBDAV_BUCKET` | R2 binding | 文件内容存储位置 |
| `WEBDAV_KV` | KV binding | 目录标记、元数据、凭证和会话缓存 |
| `ADMIN_USERNAME` | Secret | 可选，覆盖默认用户名 |
| `ADMIN_PASSWORD` | Secret | 可选，覆盖默认密码 |
| `DAV_PREFIX` | var | 可选前缀，如 `team-files` |
| `ENABLE_ACCESS_LOG` | var | 是否启用访问日志，默认 `true` |

如果未显式设置管理员账号，代码会使用默认 `admin` / `admin123456` 作为首次引导值；一旦用户在后台修改密码，KV 配置会覆盖环境变量。

## 管理后台功能

访问 `/__admin` 后，可使用：
- 账号设置：修改 WebDAV 用户名和密码
- 访问日志：查看请求记录
- 回收站：查看已删除的目录和文件并恢复

## 本地测试命令

```bash
curl -i -u admin:change-this-local-password -X OPTIONS http://localhost:8787/
curl -i -u admin:change-this-local-password -X MKCOL http://localhost:8787/docs
printf 'hello\n' | curl -i -u admin:change-this-local-password -T - http://localhost:8787/docs/hello.txt
curl -i -u admin:change-this-local-password -X PROPFIND -H 'Depth: 1' http://localhost:8787/docs/
curl -i -u admin:change-this-local-password http://localhost:8787/docs/hello.txt
```

## 设计说明

- `R2` 保存文件字节内容，`KV` 保存可重建的元数据和目录状态
- 读取文件时优先以 R2 为准；KV 异常或延迟不会破坏文件内容
- `Depth: infinity` 会被拒绝，推荐客户端使用 `Depth: 1`
- 当前实现是单管理员 Basic Auth，适合个人或小规模网盘使用

## 注意事项

- 首次部署后请尽快修改默认管理员密码
- 生产环境建议始终使用 HTTPS
- 不要在日志中记录 Authorization header 或文件内容
- 若资源名已被占用，请更换随机后缀，例如：
  - `cf-webdav-kv-a1b2c3`
  - `cf-webdav-files-xyz789`
