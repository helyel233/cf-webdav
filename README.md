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

### 方式 A：本地自动创建资源并部署（推荐）

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

### 方式 B：控制台手动创建并绑定

1. 在 Cloudflare Dashboard 中打开 **Workers & Pages -> Create application**
2. 选择创建 Worker
3. 在 **Settings -> Variables and Bindings** 中添加：
   - `WEBDAV_BUCKET`：R2 Bucket
   - `WEBDAV_KV`：KV Namespace
   - `DAV_PREFIX`：可选，默认空字符串
   - `ENABLE_ACCESS_LOG`：可选，默认 `true`
4. 如需覆盖默认管理员账号，可在 **Secrets** 中设置：
   - `ADMIN_USERNAME`
   - `ADMIN_PASSWORD`
5. 保存并部署

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
