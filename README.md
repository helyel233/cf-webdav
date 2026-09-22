# Cloudflare WebDAV

一个运行在 Cloudflare Workers 上的轻量 WebDAV 服务。文件内容放在 R2，KV 保存空目录标记和文件元数据，支持浏览器、`curl`、Windows/macOS/Linux WebDAV 客户端访问。

## 功能

支持 `OPTIONS`、`PROPFIND`、`GET`、`HEAD`、`PUT`、`DELETE`、`MKCOL`、`COPY` 和 `MOVE`。首次默认账号为 `admin`，默认密码为 `admin123456`；登录部署地址的 `/__admin` 管理页面后可以修改账号密码。修改后的凭证安全哈希存储在 KV 中。

## 一键部署

1. Fork 本仓库，默认资源名称为 KV `cf-webdav-kv`、R2 `cf-webdav-files`。
2. 安装 Node.js 20+，执行 `npm install`，登录：`npx wrangler login`。
3. 执行 `npm run deploy:setup`。脚本会自动创建或复用默认 KV/R2，并将 Cloudflare 返回的真实 KV namespace ID 写入 `wrangler.toml` 后部署。
4. 如需自定义资源名称，设置 `WEBDAV_KV_TITLE` 和 `WEBDAV_R2_BUCKET` 环境变量后执行同一命令。
5. 可选：通过 Secret 覆盖首次启动凭证：

   ```sh
   npx wrangler secret put ADMIN_USERNAME
   npx wrangler secret put ADMIN_PASSWORD
   ```

6. 如果资源已经准备好，也可以直接执行 `npm run deploy`。部署地址通常是 `https://cf-webdav.<你的账号>.workers.dev`。

部署后访问 `https://你的域名/__admin` 登录管理页面。若未配置 Secret，默认登录信息是 `admin / admin123456`，请首次登录后立即修改。

推送到 `main` 或手动运行 `Deploy Worker` 会触发 GitHub Actions。只需在仓库 Settings -> Secrets and variables -> Actions 中添加 `CLOUDFLARE_API_TOKEN` 和 `CLOUDFLARE_ACCOUNT_ID`，工作流会自动创建或复用默认 KV/R2、回写 namespace ID 并部署。Token 至少需要 Workers 编辑、R2 编辑和 KV 编辑权限；不要将 Token 提交到仓库。

## 通过 Cloudflare 控制台部署

以下流程不需要在本地执行 Wrangler 命令。控制台菜单名称可能会随 Cloudflare 界面更新略有变化。

### 1. 创建 R2 bucket

1. 登录 Cloudflare Dashboard，选择目标账号。
2. 打开 **R2 Object Storage**，点击 **Create bucket**。
3. 输入默认名称 `cf-webdav-files`，位置按实际用户所在地选择，然后创建。

### 2. 创建 KV namespace

1. 打开 **Workers & Pages -> KV**。
2. 点击 **Create namespace**，输入默认名称 `cf-webdav-kv`。
3. 创建后打开该 namespace 的详情，复制 **Namespace ID**。
4. 在仓库的 [wrangler.toml](wrangler.toml) 中，将 `id = "replace-during-setup"` 替换为复制的真实 ID，并提交到 GitHub。

R2 bucket 名称和 KV namespace ID 属于 Cloudflare 账号级资源，不能使用一个跨账号通用的固定 ID；这是控制台部署中唯一需要从页面复制到配置文件的绑定信息。

### 3. 通过 Workers & Pages 连接 GitHub

1. 打开 **Workers & Pages -> Create application -> Pages -> Connect to Git**，授权并选择本仓库。
2. 构建设置选择：
   - Framework preset：`None`
   - Build command：`npm install && npm run typecheck`
   - Build output directory：留空
3. 如果界面提供部署命令，填写 `npx wrangler deploy`；如果使用 Cloudflare 的 Workers Git 集成，则保留其默认 Wrangler 部署流程。
4. 选择正确的 Cloudflare 账号后点击 **Save and Deploy**。

部署完成后，在 **Workers & Pages -> cf-webdav -> Settings -> Variables and Secrets** 检查绑定：

- **R2 Bucket Bindings**：变量名填写 `WEBDAV_BUCKET`，选择 `cf-webdav-files`。
- **KV Namespace Bindings**：变量名填写 `WEBDAV_KV`，选择 `cf-webdav-kv`。
- **Environment Variables**：添加 `DAV_PREFIX`，默认值留空；如需路径前缀可填写例如 `team-files`。

在同一页面的 **Secrets** 中可选添加 `ADMIN_USERNAME` 和 `ADMIN_PASSWORD`，用于覆盖首次默认账号。保存变量后重新部署一次。

### 4. 登录和验证

打开 Worker 的 `workers.dev` 地址，访问 `/__admin`：

```text
https://你的-worker.workers.dev/__admin
```

没有配置 Secret 时，首次登录使用 `admin / admin123456`，进入页面后立即修改账号密码。随后使用 WebDAV 客户端或下面的请求验证：

```sh
curl -u 新用户名:新密码 -X PROPFIND -H 'Depth: 1' https://你的-worker.workers.dev/
```

控制台部署不会执行仓库中的 `scripts/setup-resources.mjs`；该脚本仅用于 `npm run deploy:setup` 和 GitHub Actions 自动创建资源。通过控制台部署时，应先按本节手动创建并绑定 R2/KV。

## 配置

| 配置 | 类型 | 说明 |
| --- | --- | --- |
| `WEBDAV_BUCKET` | R2 binding | 文件内容的唯一存储位置 |
| `WEBDAV_KV` | KV binding | 目录标记、文件元数据和后续扩展配置 |
| `ADMIN_USERNAME` | Secret | Basic Auth 用户名 |
| `ADMIN_PASSWORD` | Secret | Basic Auth 密码 |
| `DAV_PREFIX` | var | 可选的 R2 key 前缀，例如 `team-files` |

如果未设置 `ADMIN_USERNAME` 或 `ADMIN_PASSWORD`，代码使用默认值仅作为首次引导；账号修改后，KV 中的配置优先于环境变量。

KV 与 R2 的关系是：R2 保存可恢复的文件字节，KV 只保存可重建或用于加速目录展示的元数据。任何写入都会先写 R2，再写 KV；读取文件始终以 R2 为准，因此 KV 延迟或丢失不会损坏文件内容。

## 本地开发

复制 `.dev.vars.example` 为 `.dev.vars` 并修改密码，然后：

```sh
npm install
npx wrangler dev --local
```

本地 R2/KV 数据会放入 `.wrangler/`，不会提交到 Git。每次改动可用 `npm run typecheck` 检查类型。

## 测试

```sh
curl -i -u admin:change-this-local-password -X OPTIONS http://localhost:8787/
curl -i -u admin:change-this-local-password -X MKCOL http://localhost:8787/docs
printf 'hello\n' | curl -i -u admin:change-this-local-password -T - http://localhost:8787/docs/hello.txt
curl -i -u admin:change-this-local-password -X PROPFIND -H 'Depth: 1' http://localhost:8787/docs/
curl -i -u admin:change-this-local-password http://localhost:8787/docs/hello.txt
```

挂载到客户端时使用部署 URL，例如 macOS Finder 的“前往服务器”或 Linux 的 `davfs2`。生产环境请始终使用 HTTPS；Basic Auth 只应在 HTTPS 上使用。

## 限制与扩展

- `Depth: infinity` 被拒绝，避免深层目录触发过大的 Worker 请求；客户端应使用 `Depth: 1` 分层浏览。
- 单次 `COPY`/`MOVE` 目录操作会在 Worker 内顺序复制对象，适合个人网盘；超大目录应改为队列或 Durable Objects 任务。
- R2 的 HTTP Range 读取已传递给 `GET`/`HEAD`，可满足多数下载器的断点读取。大文件上传依赖 Workers/R2 当前请求限制；真正的分片上传建议另加 S3 Multipart Upload API，并由客户端使用临时授权直传 R2。
- KV 是最终一致的，不能作为锁或计费账本。当前实现将 R2 作为文件存在性的最终依据，目录缓存出现短暂延迟时可再次请求。
- 当前为单管理员 Basic Auth。管理页面使用 HttpOnly、Secure、SameSite Cookie 会话；多用户、细粒度 ACL、审计日志和限流可在 KV/Durable Objects 上扩展。对公网使用时建议在 Cloudflare Access 或 WAF 后增加保护。
- Worker 日志使用 `console.error`，可在 Cloudflare Dashboard 的实时日志中查看。不要记录 Authorization header 或文件内容。