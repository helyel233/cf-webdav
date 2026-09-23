# Cloudflare WebDAV

一个运行在 Cloudflare Workers 上的轻量 WebDAV 服务。文件内容保存在 R2，KV 保存目录标记、文件元数据和会话信息，支持浏览器、curl、Windows/macOS/Linux WebDAV 客户端访问

## 功能概览

支持 `OPTIONS`、`PROPFIND`、`GET`、`HEAD`、`PUT`、`DELETE`、`MKCOL`、`COPY` 和 `MOVE`。

默认首次登录账号为 `admin` / `admin123456`，访问 Worker 域名根路径即可进入管理界面；登录后可修改 WebDAV 连接信息，更新后的凭证哈希保存在 KV 中。

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

如果需要自定义管理员账号，在 **Settings -> Variables and Bindings -> Secrets** 中添加：

| Secret 名称 | 值 |
| --- | --- |
| `ADMIN_USERNAME` | 自定义用户名 |
| `ADMIN_PASSWORD` | 自定义密码 |

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

登录后可在管理界面修改 WebDAV 服务链接、账户和密码，浏览器上传/删除文件，查看访问日志和恢复回收站文件。WebDAV 客户端使用管理界面中显示的服务链接、账户和密码。也可以执行下面的请求确认 WebDAV 已生效：

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
| `ADMIN_USERNAME` | Secret | 可选，覆盖默认用户名 |
| `ADMIN_PASSWORD` | Secret | 可选，覆盖默认密码 |
| `DAV_PREFIX` | var | 可选前缀，如 `team-files` |
| `ENABLE_ACCESS_LOG` | var | 是否启用访问日志，默认 `true` |

如果未显式设置管理员账号，代码会使用默认 `admin` / `admin123456` 作为首次引导值；一旦用户在后台修改密码，KV 配置会覆盖环境变量。

## 管理后台功能

访问 Worker 域名根路径后，可使用：
- 连接配置：修改 WebDAV 服务链接、账户和密码
- 文件管理：浏览、上传、新建目录和删除文件
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
