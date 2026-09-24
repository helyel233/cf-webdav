# Cloudflare WebDAV

一个运行在 Cloudflare Workers 上的轻量 WebDAV 服务。文件内容保存在 R2，KV 保存目录标记、文件元数据和会话信息，支持浏览器、curl、Windows/macOS/Linux WebDAV 客户端访问

## 功能概览

支持 `OPTIONS`、`PROPFIND`、`GET`、`HEAD`、`PUT`、`DELETE`、`MKCOL`、`COPY` 和 `MOVE`。

系统采用“管理员 -> 用户 -> WebDAV 账户”三级管理体系。初始管理员账户为 `admin`，密码为 `admin123456`。管理员只能管理用户及其 WebDAV 账户的元信息，不能查看用户或 WebDAV 账户下的文件；用户只能修改自己的密码，并管理自己名下的 WebDAV 账户和文件。

访问 Worker 域名根路径即可进入管理界面。管理员账户不能在网页注册，新增管理员必须通过 Cloudflare 控制台配置 `ADMIN_USERNAME` 和 `ADMIN_PASSWORD`。

支持多管理员：每个管理员最多拥有 2 个 WebDAV 账户。每个 WebDAV 账户拥有独立的文件、日志、限流记录和回收站，管理员只能在管理界面看到自己名下账户的数据。

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

### 方式 A：控制台部署（适合不想使用本地 Node 的用户）

控制台部署分为两种情况：

- **直接在 Dashboard 发布**：不需要修改 [wrangler.toml](wrangler.toml)，但需要在 Worker 的代码编辑器中提供项目代码。
- **连接 GitHub 自动发布**：代码从仓库构建，Cloudflare 会读取 [wrangler.toml](wrangler.toml)，需要先填写真实的 KV Namespace ID。

下面先完成两种方式都需要的资源和 Worker 配置。

#### 第 1 步：创建 KV 和 R2

1. 登录 Cloudflare Dashboard，进入 **Storage & databases -> KV**。
2. 点击 **Create a namespace**，创建一个 Namespace，例如 `cf-webdav-kv`。
3. 打开刚创建的 Namespace，复制并保存 **Namespace ID**。GitHub 自动发布时会用到它。
4. 进入 **Storage & databases -> R2**，点击 **Create bucket**。
5. 创建一个全局唯一的 Bucket，例如 `cf-webdav-files-xyz789`，并保存 Bucket 名称。

这两个资源不需要预先写入数据。Worker 首次运行时会自动写入目录元数据、凭证和会话信息。

#### 第 2 步：创建 Worker

1. 进入 **Workers & Pages -> Create application**。
2. 创建一个 Worker，例如 `cf-webdav`。
3. 按页面提示完成首次创建。暂时使用默认代码也可以，后面会替换或连接项目代码。

#### 第 3 步：添加绑定和变量

打开 Worker 的 **Settings -> Variables and Bindings**，添加以下配置：

| 类型 | 名称 | 值 |
| --- | --- | --- |
| R2 Bucket binding | `WEBDAV_BUCKET` | 第 1 步创建的 R2 Bucket |
| KV Namespace binding | `WEBDAV_KV` | 第 1 步创建的 KV Namespace |
| Variable | `DAV_PREFIX` | 留空，或填写例如 `team-files` |
| Variable | `ENABLE_ACCESS_LOG` | `true` |

如果需要自定义管理员账号，请按下方「管理员账户初始化与新增」的步骤，在 **Settings -> Variables and Secrets** 中以 **Secret** 类型添加：

| Secret 名称 | 值 | 类型勾选 |
| --- | --- | --- |
| `ADMIN_USERNAME` | 自定义用户名 | Secret |
| `ADMIN_PASSWORD` | 至少 8 位的密码 | Secret |

#### 管理员账户初始化与新增

新增或更换管理员账户必须通过 Cloudflare 控制台配置 `ADMIN_USERNAME` 和 `ADMIN_PASSWORD`，具体操作步骤如下（界面以 2026 年新版控制台为准）：

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)，左侧导航进入 **Workers & Pages**。
2. 在 **Overview** 列表中点击你的 Worker（例如 `cf-webdav`）。
3. 进入 **Settings** 标签页，找到 **Variables and Secrets** 区域（旧版控制台名为 **Variables and Bindings**）。
4. 点击 **Add** 按钮，在弹出的表单中填写第一项：
   - **Type**：选择 **Secret**（不要选 **Text**——明文 Text 变量在后续执行 `wrangler deploy` 时会被清除，Secret 则永久保留且值加密不可见）；
   - **Variable name**：填写 `ADMIN_USERNAME`；
   - **Value**：填写新的管理员账户名。
5. 点击 **Add variable** 继续在同一个表单中添加第二项：
   - **Type**：再次选择 **Secret**；
   - **Variable name**：填写 `ADMIN_PASSWORD`；
   - **Value**：填写至少 8 位的密码（代码要求密码长度 ≥ 8）。
6. 点击 **Deploy** 保存并发布。Cloudflare 会自动创建新版本并立即部署，无需手动 Redeploy。
7. 部署完成后访问 Worker 根地址，使用刚才配置的管理员账户登录。**Secret 的 Value 保存后立即隐藏、无法再次查看**，请务必自行妥善保管。

**修改已有管理员的用户名或密码**：同样进入 **Variables and Secrets**，点击 **Edit**，在列表中修改 `ADMIN_PASSWORD`（或 `ADMIN_USERNAME`）的 **Value** 后点击 **Deploy**。若当前界面不允许直接修改 Secret 值，可点击条目旁的 **X** 删除后按上述步骤重新添加。

`ADMIN_USERNAME` 和 `ADMIN_PASSWORD` 仅用于登录管理界面，不会改变 WebDAV 客户端账号。WebDAV 账号在管理界面中单独配置；如需通过环境变量预设，可使用 `WEBDAV_USERNAME` 和 `WEBDAV_PASSWORD`（同样建议选 Secret 类型）。

首次请求时，Worker 会把这组 Secret 同步为管理员角色。如果 KV 中已有同名用户，该用户会升级为管理员并使用 Secret 中的密码。已有账户会自动迁移：原有的 `admin` 保留管理员角色，其他原“管理员”账户降级为普通用户。管理员登录后可创建、删除用户，删除用户及其名下 WebDAV 账户，但不能为用户新增 WebDAV 账户，也不能查看文件、日志或回收站内容。

删除 `ADMIN_USERNAME` 和 `ADMIN_PASSWORD` Secret 不会删除 KV 中已保存的管理员账户；如需更换管理员，请配置新的 Secret 并重新部署。

#### 第 4 步：发布代码

##### 选项 1：Dashboard 直接发布

如果不想修改 [wrangler.toml](wrangler.toml)，可以直接在 Worker 的 Dashboard 代码编辑器中发布。具体操作如下：

1. 打开 Worker，进入 **Edit code** 或 **Quick edit**。
2. 如果页面要求选择脚本类型，选择 **Module Worker**；不要选择 Service Worker 格式。
3. 打开项目中的 [src/index.ts](src/index.ts)，复制文件的全部内容。
4. 将复制的内容完整粘贴到 Dashboard 的代码编辑器中，替换编辑器里的示例代码。
5. 点击 **Save and deploy** 或 **Deploy**。

本项目的运行时代码只有 [src/index.ts](src/index.ts) 一个入口文件，没有需要另外粘贴的源码模块。以下文件不需要粘贴到代码编辑器：

- [wrangler.toml](wrangler.toml)：本地 Wrangler 和 GitHub 部署配置，不是 Worker 运行时代码。
- `package.json`：本地依赖和命令配置。
- `worker-configuration.d.ts`：TypeScript 类型声明，不是运行时代码。

如果 Dashboard 编辑器明确只接受 JavaScript，不能直接粘贴 TypeScript 文件；需要先把 [src/index.ts](src/index.ts) 编译为 JavaScript，再粘贴编译后的完整脚本。不要只复制 `export default` 部分，否则同文件中的认证、WebDAV、日志和回收站函数会缺失。

粘贴代码后，确认第 3 步中的 `WEBDAV_BUCKET` 和 `WEBDAV_KV` 绑定已经保存，再点击 **Deploy**。这种方式的 KV/R2 绑定由 Dashboard 保存，不读取仓库中的 KV 占位 ID。

发布完成后，打开 `https://你的-worker.workers.dev/`，使用默认账号 `admin / admin123456` 登录。首次登录后请立即修改 WebDAV 连接信息。

##### 选项 2：连接 GitHub 自动发布

如果希望通过 Dashboard 连接 GitHub，并在之后通过推送自动部署，按下面步骤操作：

1. 在 Worker 的 **Deployments** 或代码页面点击 **Connect to Git**。
2. 授权 Cloudflare 访问 GitHub，选择包含本项目的账号、仓库和部署分支（通常是 `main`）。
3. 在仓库的 [wrangler.toml](wrangler.toml) 中，将 `id = "replace-during-setup"` 替换为第 1 步保存的真实 KV Namespace ID。
4. 确认 `bucket_name` 与第 1 步创建的 R2 Bucket 名称一致，并提交推送 [wrangler.toml](wrangler.toml)。
5. 回到 Cloudflare 的 Git 部署设置，确认项目根目录为仓库根目录，并填写：
  - **Build command**：`npm run typecheck`
  - **Deploy command**：`npm run deploy`
  - **Root directory**：留空（本项目的 `package.json` 在仓库根目录）
6. 点击 **Save and Deploy**、**Deploy** 或页面上的同名确认按钮，开始第一次构建和发布。Cloudflare 会从选定分支拉取代码，安装依赖，执行构建命令，再执行部署命令。
7. 打开 **Deployments** 查看构建日志。显示部署成功后，复制 Worker 的 `workers.dev` 地址，访问根路径验证管理界面。

连接完成后的日常发布方式是：修改代码并推送到刚才选择的部署分支，Cloudflare 会自动创建新的部署。也可以在 **Deployments** 中打开某次历史部署，使用页面提供的 **Retry deployment** 或 **Redeploy** 重新发布；具体按钮名称会因 Dashboard 版本而略有不同。

GitHub 部署时，Dashboard 中创建的 KV/R2 绑定不会自动改写仓库配置；当前项目的 `npm run deploy` 会先检查 KV ID，所以必须先完成第 3 步。如果不想把账号专属的 KV ID 提交到 Git 仓库，请使用上面的 Dashboard 直接发布方式。

#### 第 5 步：验证部署

打开 Worker 域名根地址，管理界面无需添加 `/__admin`：

```text
https://你的-worker.workers.dev/
```

默认登录信息：

```text
用户名：admin
密码：admin123456
```

管理员登录后可管理用户、删除用户名下的 WebDAV 账户，但不能为用户新增 WebDAV 账户，也不能浏览文件。用户登录后可修改自己的密码、配置 WebDAV 服务链接和密码，浏览器上传/删除文件，查看自己账户的访问日志和回收站。WebDAV 客户端使用对应 WebDAV 账户的服务链接、账户和密码。也可以执行下面的请求确认 WebDAV 已生效：

在管理中心点击“管理所有账户”可以创建管理员，并删除用户名下的 WebDAV 账户。WebDAV 账户由用户自行创建和管理；打开某个 WebDAV 账户的文件管理后，只能浏览、上传和删除该账户自己的文件。

```bash
curl -i -u admin:admin123456 -X OPTIONS https://你的-worker.workers.dev/
curl -i -u admin:admin123456 -X MKCOL https://你的-worker.workers.dev/test-folder
curl -i -u admin:admin123456 -X PROPFIND -H 'Depth: 1' https://你的-worker.workers.dev/
```

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
https://你的-worker.workers.dev/
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
| `WEBDAV_USERNAME` | Secret/var | 可选，预设 WebDAV 客户端账户 |
| `WEBDAV_PASSWORD` | Secret | 可选，预设 WebDAV 客户端密码 |
| `ADMIN_USERNAME` | Secret | 可选，覆盖默认用户名 |
| `ADMIN_PASSWORD` | Secret | 可选，覆盖默认密码 |
| `DAV_PREFIX` | var | 可选前缀，如 `team-files` |
| `ENABLE_ACCESS_LOG` | var | 是否启用访问日志，默认 `true` |

如果未显式设置管理员账号或 WebDAV 账号，代码使用默认管理员 `admin` / `admin123456` 作为首次引导值。管理员密码只能由管理员自己在管理界面修改；新增管理员必须通过 Cloudflare 控制台设置 Secret。用户和 WebDAV 账户凭证分别写入 KV，互不覆盖。

升级到多账户版本时，旧的单管理员和单 WebDAV 账户会兼容读取，并归属于当前管理员；新建账户后会使用独立的 KV/R2 前缀进行隔离。

## 管理后台功能

访问 Worker 域名根路径后，可使用：
- 管理员控制台：通过 Cloudflare Secret 初始化管理员，管理用户及其 WebDAV 账户
- 用户配置：修改自己的密码和 WebDAV 服务链接、账户、密码
- 文件管理：浏览、上传、新建目录和删除自己的文件
- 访问日志：查看当前 WebDAV 账户的请求记录
- 回收站：查看和恢复当前 WebDAV 账户已删除的目录和文件

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
- 支持 `Depth: 0`、`Depth: 1` 和 `Depth: infinity`，兼容需要递归读取目录的客户端
- 支持 RFC 4918 Class 2 锁机制（LOCK/UNLOCK）、Range 部分内容（206）、If-Match/If-None-Match 条件请求及 RFC 4331 配额属性
- 当前实现是单管理员 Basic Auth，适合个人或小规模网盘使用

## 注意事项

- 首次部署后请尽快修改默认管理员密码
- 生产环境建议始终使用 HTTPS
- 不要在日志中记录 Authorization header 或文件内容
- LOCK/UNLOCK 锁信息存储在 KV 上，受 KV 最终一致性（跨节点传播可达 60 秒）与读-改-写非原子性影响，锁为"建议性锁"：可协调行为良好的客户端（如 Office 编辑器）的 LOCK-EDIT-UNLOCK 流程，但不能提供强互斥保证，不适合用于防并发覆盖的强一致场景
- 若资源名已被占用，请更换随机后缀，例如：
  - `cf-webdav-kv-a1b2c3`
  - `cf-webdav-files-xyz789`
