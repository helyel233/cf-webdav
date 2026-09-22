# Cloudflare WebDAV

一个运行在 Cloudflare Workers 上的轻量 WebDAV 服务。文件内容放在 R2，KV 保存空目录标记和文件元数据，支持浏览器、`curl`、Windows/macOS/Linux WebDAV 客户端访问。

## 功能

支持 `OPTIONS`、`PROPFIND`、`GET`、`HEAD`、`PUT`、`DELETE`、`MKCOL`、`COPY` 和 `MOVE`。首次默认账号为 `admin`，默认密码为 `admin123456`；登录部署地址的 `/__admin` 管理页面后可以修改账号密码。修改后的凭证安全哈希存储在 KV 中。

## 部署方式（按推荐顺序）

### 方式一：Cloudflare 控制台创建并绑定资源（首选）

此方式最适合首次部署，不需要本地安装 Node.js，也不需要手动填写 KV namespace ID。

1. 登录 Cloudflare Dashboard，选择目标账号。
2. 打开 **Workers & Pages -> Create application**，连接 GitHub 并选择本仓库；如果已经创建了 `cf-webdav` Worker，直接打开它。
3. 在 Worker 的 **Settings -> Variables and Bindings** 中点击 **Add binding**。
4. 选择 **R2 Bucket**，Binding name 填写 `WEBDAV_BUCKET`，点击 **Create new bucket**，名称填写 `cf-webdav-files`，创建后选择它。
5. 再次点击 **Add binding**，选择 **KV Namespace**，Binding name 填写 `WEBDAV_KV`，点击 **Create new namespace**，名称填写 `cf-webdav-kv`，创建后选择它。
6. 添加普通变量 `DAV_PREFIX`，默认值留空；需要路径前缀时填写例如 `team-files`。
7. 在 **Secrets** 中按需添加 `ADMIN_USERNAME` 和 `ADMIN_PASSWORD`，用于覆盖首次默认账号。
8. 点击 **Save** 并部署 Worker。

如果控制台没有 **Create new** 按钮，通常是账号或 Token 缺少 R2/KV 编辑权限。可先在 **R2 Object Storage** 创建 `cf-webdav-files`，再在 **Workers & Pages -> KV** 创建 `cf-webdav-kv`，回到绑定页面选择已有资源。

### 方式二：Cloudflare 控制台连接 GitHub，并在绑定时创建资源

适合希望后续由 GitHub 自动部署的用户。

1. 在 **Workers & Pages -> Create application** 中连接 GitHub，授权并选择本仓库。
2. 绑定配置仍使用 `WEBDAV_BUCKET`、`WEBDAV_KV`，资源名称使用默认值 `cf-webdav-files`、`cf-webdav-kv`。
3. 如果绑定选择框提供 **Create new bucket** 和 **Create new namespace**，直接创建并绑定；否则先按方式一手动创建资源。
4. 在 GitHub 仓库 **Settings -> Secrets and variables -> Actions** 添加 `CLOUDFLARE_API_TOKEN` 和 `CLOUDFLARE_ACCOUNT_ID`。
5. 推送到 `main` 或手动运行 `Deploy Worker`。工作流会自动检查并复用默认 KV/R2，然后部署 Worker。

### 方式三：本地脚本自动创建 KV/R2

适合有 Node.js 环境、希望完全自动化部署的用户。默认资源名称为 KV `cf-webdav-kv`、R2 `cf-webdav-files`。

```sh
npm install
npx wrangler login
npm run deploy:setup
```

脚本会自动创建或复用资源，将 Cloudflare 返回的 KV namespace ID 写入 [wrangler.toml](wrangler.toml)，然后部署。也可以通过 `WEBDAV_KV_TITLE` 和 `WEBDAV_R2_BUCKET` 自定义资源名称。

### 方式四：手动 Wrangler 部署

如果资源已在 Cloudflare 控制台创建完成，可将 KV 的真实 Namespace ID 写入 [wrangler.toml](wrangler.toml) 的 `id` 字段，然后执行：

```sh
npm install
npm run deploy
```

不建议首次用户直接使用此方式，因为 KV namespace ID 是账号专属值，不能使用通用固定值。

### 登录和验证

打开 Worker 的 `workers.dev` 地址，访问 `/__admin`：

```text
https://你的-worker.workers.dev/__admin
```

没有配置 Secret 时，首次登录使用 `admin / admin123456`，进入页面后立即修改账号密码。随后使用 WebDAV 客户端或下面的请求验证：

```sh
curl -u 新用户名:新密码 -X PROPFIND -H 'Depth: 1' https://你的-worker.workers.dev/
```

控制台部署不会执行仓库中的 `scripts/setup-resources.mjs`。控制台流程会直接创建并绑定 R2/KV；`scripts/setup-resources.mjs` 仅用于本地 `npm run deploy:setup` 和 GitHub Actions 自动创建资源。

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