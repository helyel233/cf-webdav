interface Env {
  WEBDAV_BUCKET: R2Bucket;
  WEBDAV_KV: KVNamespace;
  ADMIN_USERNAME?: string;
  ADMIN_PASSWORD?: string;
  WEBDAV_USERNAME?: string;
  WEBDAV_PASSWORD?: string;
  DAV_PREFIX?: string;
  // 新增：启用访问日志
  ENABLE_ACCESS_LOG?: string;
}

interface FileMeta {
  type: "file";
  size: number;
  etag?: string;
  contentType?: string;
  updatedAt: string;
}

// 新增：访问日志记录
interface AccessLog {
  timestamp: string;
  method: string;
  path: string;
  status: number;
  clientIp: string;
  userAgent: string;
  bytesSent?: number;
  user: string;
}

const METHODS = ["OPTIONS", "PROPFIND", "GET", "HEAD", "PUT", "DELETE", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"];
const META_PREFIX = "meta:";
const DIR_PREFIX = "dir:";
const CREDENTIALS_KEY = "config:credentials";
const ADMIN_CREDENTIALS_KEY = "config:admin-credentials";
const SERVICE_CONFIG_KEY = "config:service";
const ADMIN_ACCOUNTS_KEY = "config:admin-accounts";
const WEBDAV_ACCOUNTS_KEY = "config:webdav-accounts";
const SESSION_PREFIX = "session:";
const LOG_PREFIX = "log:";
const TRASH_PREFIX = "trash:";
const DEFAULT_USERNAME = "admin";
const DEFAULT_PASSWORD = "admin123456";
const SESSION_TTL = 60 * 60 * 24 * 7;
const LOG_RETENTION_DAYS = 30;
const TRASH_RETENTION_DAYS = 30;

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const startTime = Date.now();
    const pathname = new URL(request.url).pathname;
    const clientIp = request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "unknown";
    const userAgent = request.headers.get("User-Agent") || "";
    const contentLength = parseInt(request.headers.get("Content-Length") || "0");

    if (pathname === "/" && (request.method === "GET" || request.method === "POST")) return adminRequest(request, env);
    if (pathname === "/__admin" || pathname.startsWith("/__admin/")) return adminRequest(request, env);
    if (request.method === "OPTIONS") return optionsResponse();

    let username = "anonymous";
    const webdavAccount = await authenticate(request, env);
    if (!webdavAccount) {
      return new Response("Unauthorized", {
        status: 401,
        headers: { "WWW-Authenticate": 'Basic realm="Cloudflare WebDAV"' },
      });
    }
    username = webdavAccount.username;
    const scopedEnv = createScopedEnv(env, storageScope(webdavAccount));

    // 新增：检查流量限制
    const rateLimit = await checkRateLimit(scopedEnv, clientIp, request.method, contentLength);
    if (!rateLimit.allowed) {
      await logAccess(scopedEnv, { timestamp: new Date().toISOString(), method: request.method, path: pathname, status: 429, clientIp, userAgent, user: username }, startTime);
      return new Response("Too Many Requests", {
        status: 429,
        headers: {
          "Retry-After": String(rateLimit.retryAfter),
          "X-RateLimit-Limit": String(DEFAULT_RATE_LIMIT.maxRequestsPerMinute),
          "X-RateLimit-Remaining": "0",
        },
      });
    }

    let path: string;
    try {
      path = requestPath(request, env, webdavAccount);
    } catch {
      await logAccess(scopedEnv, { timestamp: new Date().toISOString(), method: request.method, path: pathname, status: 400, clientIp, userAgent, user: username }, startTime);
      return textResponse("Bad Request", 400);
    }

    let response: Response;
    try {
      switch (request.method) {
        case "PROPFIND": response = await propfind(request, scopedEnv, path, webdavAccount); break;
        case "GET": response = await getObject(scopedEnv, path, false, request); break;
        case "HEAD": response = await getObject(scopedEnv, path, true, request); break;
        case "PUT": response = await putObject(request, scopedEnv, path); break;
        case "DELETE": response = await deletePath(scopedEnv, path); break;
        case "MKCOL": response = await makeCollection(scopedEnv, path); break;
        case "COPY": response = await copyOrMove(request, scopedEnv, path, false, webdavAccount); break;
        case "MOVE": response = await copyOrMove(request, scopedEnv, path, true, webdavAccount); break;
        default:
          response = textResponse("Method Not Allowed", 405, { Allow: METHODS.join(", ") });
      }
    } catch (error) {
      console.error("WebDAV request failed", { method: request.method, path, error });
      await logAccess(scopedEnv, { timestamp: new Date().toISOString(), method: request.method, path, status: 500, clientIp, userAgent, user: username }, startTime);
      return textResponse("Internal Server Error", 500);
    }

    await logAccess(scopedEnv, { timestamp: new Date().toISOString(), method: request.method, path, status: response.status, clientIp, userAgent, bytesSent: parseInt(response.headers.get("Content-Length") || "0"), user: username }, startTime);
    return response;
  },
};

// 新增：记录访问日志
async function logAccess(env: Env, log: Omit<AccessLog, "timestamp"> & { timestamp?: string }, startTime: number): Promise<void> {
  if (env.ENABLE_ACCESS_LOG !== "true") return;

  const accessLog: AccessLog = {
    timestamp: log.timestamp || new Date().toISOString(),
    method: log.method,
    path: log.path,
    status: log.status,
    clientIp: log.clientIp,
    userAgent: log.userAgent,
    bytesSent: log.bytesSent,
    user: log.user,
  };

  const logKey = `${LOG_PREFIX}${Date.now()}-${Math.random().toString(36).slice(2)}`;
  await env.WEBDAV_KV.put(logKey, JSON.stringify(accessLog), { expirationTtl: LOG_RETENTION_DAYS * 24 * 60 * 60 });
}

async function authenticate(request: Request, env: Env): Promise<WebdavAccount | null> {
  const header = request.headers.get("Authorization");
  if (!header?.startsWith("Basic ")) return null;
  try {
    const decoded = atob(header.slice(6));
    const separator = decoded.indexOf(":");
    if (separator < 0) return null;
    const account = await getWebdavAccountByUsername(env, decoded.slice(0, separator));
    return account && await verifyPassword(decoded.slice(separator + 1), account.passwordHash, account.salt) ? account : null;
  } catch {
    return null;
  }
}

interface Credentials {
  username: string;
  passwordHash: string;
  salt: string;
}

type AdminRole = "admin" | "user";

interface AdminAccount extends Credentials {
  role?: AdminRole;
}

interface WebdavAccount extends Credentials {
  owner: string;
  url: string;
  uuid?: string;
}

interface ServiceConfig {
  url: string;
  username: string;
  password: string;
}

async function getWebdavCredentials(env: Env): Promise<Credentials> {
  const account = await getWebdavAccountByUsername(env, env.WEBDAV_USERNAME || DEFAULT_USERNAME);
  return account || {
    username: env.WEBDAV_USERNAME || DEFAULT_USERNAME,
    passwordHash: await hashPassword(env.WEBDAV_PASSWORD || DEFAULT_PASSWORD, "default-salt"), salt: "default-salt",
  };
}

async function getAdminCredentials(env: Env): Promise<Credentials> {
  const accounts = await getAdminAccounts(env);
  const first = accounts[DEFAULT_USERNAME] || Object.values(accounts)[0];
  if (first) return first;
  return {
    username: env.ADMIN_USERNAME || DEFAULT_USERNAME,
    passwordHash: await hashPassword(env.ADMIN_PASSWORD || DEFAULT_PASSWORD, "default-salt"),
    salt: "default-salt",
  };
}

async function getAdminAccounts(env: Env): Promise<Record<string, AdminAccount>> {
  const saved = await env.WEBDAV_KV.get(ADMIN_ACCOUNTS_KEY, "json") as Record<string, AdminAccount> | null;
  if (saved && Object.keys(saved).length) {
    let changed = false;
    for (const account of Object.values(saved)) {
      if (!account.role) {
        account.role = account.username === DEFAULT_USERNAME ? "admin" : "user";
        changed = true;
      }
    }
    const bootstrapUsername = env.ADMIN_USERNAME?.trim();
    if (bootstrapUsername) {
      saved[bootstrapUsername] = {
        ...(saved[bootstrapUsername] || { username: bootstrapUsername }),
        username: bootstrapUsername,
        passwordHash: await hashPassword(env.ADMIN_PASSWORD || DEFAULT_PASSWORD, "default-salt"),
        salt: "default-salt",
        role: "admin",
      };
      changed = true;
    }
    if (!Object.values(saved).some((account) => account.role === "admin")) {
      saved[DEFAULT_USERNAME] = {
        username: DEFAULT_USERNAME,
        passwordHash: await hashPassword(DEFAULT_PASSWORD, "default-salt"),
        salt: "default-salt",
        role: "admin",
      };
      changed = true;
    }
    if (changed) await env.WEBDAV_KV.put(ADMIN_ACCOUNTS_KEY, JSON.stringify(saved));
    return saved;
  }
  const legacy = await env.WEBDAV_KV.get(ADMIN_CREDENTIALS_KEY, "json") as AdminAccount | null;
  const accounts: Record<string, AdminAccount> = {
    [DEFAULT_USERNAME]: {
      username: DEFAULT_USERNAME,
      passwordHash: await hashPassword(DEFAULT_PASSWORD, "default-salt"),
      salt: "default-salt",
      role: "admin",
    },
  };
  if (legacy?.username && legacy.passwordHash && legacy.salt && legacy.username !== DEFAULT_USERNAME) {
    accounts[legacy.username] = { ...legacy, role: "user" };
  }
  const bootstrapUsername = env.ADMIN_USERNAME?.trim();
  if (bootstrapUsername && !accounts[bootstrapUsername]) {
    accounts[bootstrapUsername] = {
      username: bootstrapUsername,
      passwordHash: await hashPassword(env.ADMIN_PASSWORD || DEFAULT_PASSWORD, "default-salt"),
      salt: "default-salt",
      role: "admin",
    };
  }
  await env.WEBDAV_KV.put(ADMIN_ACCOUNTS_KEY, JSON.stringify(accounts));
  return accounts;
}

async function getWebdavAccounts(env: Env): Promise<Record<string, WebdavAccount>> {
  const saved = await env.WEBDAV_KV.get(WEBDAV_ACCOUNTS_KEY, "json") as Record<string, WebdavAccount> | null;
  if (saved && Object.keys(saved).length) {
    let changed = false;
    const usedUuids = new Set<string>();
    for (const account of Object.values(saved)) {
      if (!account.uuid || !/^\d{6}$/.test(account.uuid) || usedUuids.has(account.uuid)) {
        account.uuid = createAccountUuid(usedUuids);
        changed = true;
      }
      usedUuids.add(account.uuid);
    }
    if (changed) await env.WEBDAV_KV.put(WEBDAV_ACCOUNTS_KEY, JSON.stringify(saved));
    return saved;
  }
  const legacy = await env.WEBDAV_KV.get(CREDENTIALS_KEY, "json") as Credentials | null;
  const username = legacy?.username || env.WEBDAV_USERNAME || DEFAULT_USERNAME;
  const admin = await getAdminCredentials(env);
  const account = { username, owner: admin.username, url: new URL("https://example.invalid").origin, uuid: createAccountUuid(), passwordHash: legacy?.passwordHash || await hashPassword(env.WEBDAV_PASSWORD || DEFAULT_PASSWORD, "default-salt"), salt: legacy?.salt || "default-salt" };
  return { [username]: account };
}

async function getWebdavAccountByUsername(env: Env, username: string): Promise<WebdavAccount | null> {
  const accounts = await getWebdavAccounts(env);
  return accounts[username] || null;
}

function storageScope(account: WebdavAccount): string {
  return `tenant/${encodeURIComponent(account.owner)}/${encodeURIComponent(account.username)}`;
}

function createAccountUuid(used = new Set<string>()): string {
  let uuid = "";
  do uuid = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1_000_000).padStart(6, "0"); while (used.has(uuid));
  return uuid;
}

function webdavAccountUrl(request: Request, account: WebdavAccount): string {
  return `${new URL(request.url).origin}/${encodeURIComponent(account.owner)}/${account.uuid}`;
}

function createScopedEnv(env: Env, scope: string): Env {
  const scopedKv = new Proxy(env.WEBDAV_KV, {
    get(target, property, receiver) {
      if (property === "get" || property === "put" || property === "delete") {
        return (...args: unknown[]) => {
          if (property === "get" || property === "delete") return (target[property as "get" | "delete"] as Function).call(target, `${scope}/kv/${args[0]}`, ...args.slice(1));
          return target.put(
            `${scope}/kv/${args[0]}`,
            args[1] as Parameters<KVNamespace["put"]>[1],
            args[2] as Parameters<KVNamespace["put"]>[2],
          );
        };
      }
      if (property === "list") return async (options: { prefix?: string; [key: string]: unknown } = {}) => {
        const base = `${scope}/kv/`;
        const result = await target.list({ ...options, prefix: `${base}${options.prefix || ""}` });
        return { ...result, keys: result.keys.map((key) => ({ ...key, name: key.name.slice(base.length) })) };
      };
      return Reflect.get(target, property, receiver);
    },
  });
  const scopedBucket = new Proxy(env.WEBDAV_BUCKET, {
    get(target, property, receiver) {
      if (["get", "put", "head", "delete"].includes(String(property))) return (...args: unknown[]) => (target[property as "get" | "put" | "head" | "delete"] as Function).call(target, `${scope}/r2/${args[0]}`, ...args.slice(1));
      if (property === "list") return async (options: { prefix?: string; [key: string]: unknown } = {}) => {
        const base = `${scope}/r2/`;
        const result = await target.list({ ...options, prefix: `${base}${options.prefix || ""}` });
        return {
          ...result,
          objects: result.objects.map((object) => ({ ...object, key: object.key.slice(base.length) })),
          delimitedPrefixes: result.delimitedPrefixes.map((prefix) => prefix.slice(base.length)),
        };
      };
      return Reflect.get(target, property, receiver);
    },
  });
  return { ...env, WEBDAV_KV: scopedKv, WEBDAV_BUCKET: scopedBucket };
}

async function getServiceConfig(request: Request, env: Env): Promise<ServiceConfig> {
  const saved = await env.WEBDAV_KV.get(SERVICE_CONFIG_KEY, "json") as Partial<ServiceConfig> | null;
  return {
    url: saved?.url || new URL(request.url).origin,
    username: saved?.username || env.WEBDAV_USERNAME || DEFAULT_USERNAME,
    password: saved?.password || env.WEBDAV_PASSWORD || DEFAULT_PASSWORD,
  };
}

async function hashPassword(password: string, salt: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: new TextEncoder().encode(salt), iterations: 100_000, hash: "SHA-256" }, key, 256);
  return bytesToBase64(new Uint8Array(bits));
}

async function verifyPassword(password: string, expected: string, salt = "default-salt"): Promise<boolean> {
  const actual = await hashPassword(password, salt);
  return actual.length === expected.length && [...actual].every((character, index) => character === expected[index]);
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function adminRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const isRoot = url.pathname === "/";
  if (isRoot && url.searchParams.get("action") === "logout") {
    return new Response(null, { status: 303, headers: { Location: "/", "Set-Cookie": "cf_webdav_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0" } });
  }
  if (url.pathname === "/__admin/register") {
    if (request.method === "GET") return adminRegisterPage();
    const form = await request.formData();
    const username = String(form.get("username") || "").trim();
    const password = String(form.get("password") || "");
    const confirmPassword = String(form.get("confirmPassword") || "");
    if (!/^[A-Za-z0-9._-]{2,64}$/.test(username) || password.length < 8) return adminRegisterPage("用户名格式不正确，密码至少需要 8 位");
    if (password !== confirmPassword) return adminRegisterPage("两次输入的密码不一致");
    const accounts = await getAdminAccounts(env);
    if (accounts[username]) return adminRegisterPage("用户账户已存在");
    if (Object.keys(accounts).length >= 10) return adminRegisterPage("账户最多创建 10 个");
    const salt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
    accounts[username] = { username, salt, passwordHash: await hashPassword(password, salt), role: "user" };
    await env.WEBDAV_KV.put(ADMIN_ACCOUNTS_KEY, JSON.stringify(accounts));
    return adminLoginPage("注册成功，请使用新账户登录");
  }
  if (url.pathname === "/__admin/login" && request.method === "POST") {
    const form = await request.formData();
    const username = String(form.get("username") ?? "");
    const password = String(form.get("password") ?? "");
    const credentials = (await getAdminAccounts(env))[username];
    if (!credentials || !(await verifyPassword(password, credentials.passwordHash, credentials.salt))) return adminLoginPage("用户名或密码错误");
    const token = bytesToBase64(crypto.getRandomValues(new Uint8Array(32)));
    await env.WEBDAV_KV.put(`${SESSION_PREFIX}${token}`, username, { expirationTtl: SESSION_TTL });
    return new Response(null, { status: 303, headers: { Location: "/", "Set-Cookie": `cf_webdav_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL}` } });
  }
  const sessionUser_ = await sessionUser(request, env);
  if (!sessionUser_) return adminLoginPage();
  const sessionAccount = (await getAdminAccounts(env))[sessionUser_];
  if (sessionAccount?.role === "admin") return superAdminRequest(request, env, sessionAccount);
  const view = url.searchParams.get("view") || "home";
  if (request.method === "POST" && (isRoot || url.pathname === "/__admin")) {
    const form = await request.formData();
    const action = String(form.get("action") || "");
    const adminUsername = sessionUser_;
    const webdavAccounts = await getWebdavAccounts(env);
    const ownedAccounts = Object.values(webdavAccounts).filter((account) => account.owner === adminUsername);
    if (action === "save-user-password") {
      const password = String(form.get("userPassword") || "");
      if (password.length < 8) return await adminPage(request, env, "用户密码至少需要 8 位");
      const account = (await getAdminAccounts(env))[adminUsername];
      const salt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
      await env.WEBDAV_KV.put(ADMIN_ACCOUNTS_KEY, JSON.stringify({ ...(await getAdminAccounts(env)), [adminUsername]: { ...account, salt, passwordHash: await hashPassword(password, salt), role: "user" } }));
      return await adminPage(request, env, "密码已更新");
    }
    if (action === "create-admin" || action === "save-admin") return textResponse("普通用户无权执行管理员操作", 403);
    if (action === "create-webdav") {
      const username = String(form.get("serviceUsername") || "").trim();
      const password = String(form.get("servicePassword") || "");
      const uuid = String(form.get("accountUuid") || "").trim();
      if (ownedAccounts.length >= 2) return await adminPage(request, env, "每个管理员最多只能拥有 2 个 WebDAV 账户");
      if (webdavAccounts[username]) return await adminPage(request, env, "WebDAV 账户名已存在，请换一个");
      if (!/^[A-Za-z0-9._-]{2,64}$/.test(username) || password.length < 8) return await adminPage(request, env, "WebDAV 账户格式不正确，密码至少需要 8 位");
      if (!/^\d{6}$/.test(uuid)) return await adminPage(request, env, "UUID 必须是 6 位数字");
      if (Object.values(webdavAccounts).some((account) => account.uuid === uuid)) return await adminPage(request, env, "UUID 已存在，请换一个");
      const salt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
      const account = { username, owner: adminUsername, uuid, url: "", salt, passwordHash: await hashPassword(password, salt) };
      account.url = webdavAccountUrl(request, account);
      webdavAccounts[username] = account;
      await env.WEBDAV_KV.put(WEBDAV_ACCOUNTS_KEY, JSON.stringify(webdavAccounts));
      return await adminPage(request, env, "WebDAV 账户已创建");
    }
    if (action === "delete-webdav") {
      const accountUsername = String(form.get("accountUsername") || "");
      const account = webdavAccounts[accountUsername];
      if (!account || account.owner !== adminUsername) return textResponse("无权删除该 WebDAV 账户", 403);
      await deleteWebdavAccountData(env, account);
      delete webdavAccounts[accountUsername];
      await env.WEBDAV_KV.put(WEBDAV_ACCOUNTS_KEY, JSON.stringify(webdavAccounts));
      return await adminPage(request, env, "WebDAV 账户及其全部文件已删除");
    }
    if (action === "save-service") {
      const accountUsername = String(form.get("accountUsername") || ownedAccounts[0]?.username || "");
      const account = webdavAccounts[accountUsername];
      if (!account || account.owner !== adminUsername) return await adminPage(request, env, "无权修改该 WebDAV 账户");
      const service = {
        url: String(form.get("url") || "").trim().replace(/\/+$/, ""),
        username: String(form.get("serviceUsername") || "").trim(),
        password: String(form.get("servicePassword") || ""),
        uuid: String(form.get("accountUuid") || "").trim(),
      };
      if (!/^\d{6}$/.test(service.uuid)) return await adminPage(request, env, "UUID 必须是 6 位数字");
      if (!/^[A-Za-z0-9._-]{2,64}$/.test(service.username)) return await adminPage(request, env, "WebDAV 账户须为 2-64 位字母、数字、点、下划线或短横线");
      if (service.password.length < 8) return await adminPage(request, env, "WebDAV 密码至少需要 8 位");
      if (Object.values(webdavAccounts).some((item) => item.uuid === service.uuid && item.username !== accountUsername)) return await adminPage(request, env, "UUID 已存在，请换一个");
      const salt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
      if (service.username !== accountUsername && webdavAccounts[service.username]) return await adminPage(request, env, "WebDAV 账户名已存在，请换一个");
      delete webdavAccounts[accountUsername];
      account.username = service.username;
      account.uuid = service.uuid;
      account.salt = salt;
      account.passwordHash = await hashPassword(service.password, salt);
      account.url = webdavAccountUrl(request, account);
      webdavAccounts[service.username] = account;
      await env.WEBDAV_KV.put(WEBDAV_ACCOUNTS_KEY, JSON.stringify(webdavAccounts));
      return await adminPage(request, env, "服务连接信息已保存");
    }
    if (action === "save-admin") {
      const username = String(form.get("adminUsername") || "").trim();
      const password = String(form.get("adminPassword") || "");
      if (!/^[A-Za-z0-9._-]{2,64}$/.test(username)) return await adminPage(request, env, "管理员账户须为 2-64 位字母、数字、点、下划线或短横线");
      if (password.length < 8) return await adminPage(request, env, "管理员密码至少需要 8 位");
      const salt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
      const admins = await getAdminAccounts(env);
      delete admins[adminUsername];
      admins[username] = { username, salt, passwordHash: await hashPassword(password, salt) };
      for (const account of ownedAccounts) {
        account.owner = username;
        account.url = webdavAccountUrl(request, account);
      }
      await env.WEBDAV_KV.put(ADMIN_ACCOUNTS_KEY, JSON.stringify(admins));
      await env.WEBDAV_KV.put(WEBDAV_ACCOUNTS_KEY, JSON.stringify(webdavAccounts));
      return new Response(null, { status: 303, headers: { Location: "/", "Set-Cookie": "cf_webdav_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0" } });
    }
    if (view === "files" && ["upload", "delete", "mkdir"].includes(action)) {
      const selected = webdavAccounts[String(form.get("accountUsername") || url.searchParams.get("account") || "")];
      if (!selected || selected.owner !== adminUsername) return textResponse("请选择有权访问的 WebDAV 账户", 403);
      return adminFilesAction(request, createScopedEnv(env, storageScope(selected)), form, sessionUser_, selected.username);
    }
    if (view === "trash" && ["restore", "empty"].includes(action)) {
      const selected = webdavAccounts[String(form.get("accountUsername") || url.searchParams.get("account") || "")];
      if (!selected || selected.owner !== adminUsername) return textResponse("请选择有权访问的 WebDAV 账户", 403);
      const scopedEnv = createScopedEnv(env, storageScope(selected));
      if (action === "empty") await emptyTrash(scopedEnv);
      else await restoreFromTrash(scopedEnv, String(form.get("path") || ""));
      return new Response(null, { status: 303, headers: { Location: `/?view=trash&account=${encodeURIComponent(selected.username)}` } });
    }
  }
  if (url.pathname === "/__admin/account" && request.method === "POST") {
    const form = await request.formData();
    const username = String(form.get("username") ?? "").trim();
    const password = String(form.get("password") ?? "");
    if (!/^[A-Za-z0-9._-]{2,64}$/.test(username)) return adminPage(request, env, "管理员账户须为 2-64 位字母、数字、点、下划线或短横线");
    if (password.length < 8) return adminPage(request, env, "管理员密码至少需要 8 位");
    const salt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
    await env.WEBDAV_KV.put(ADMIN_CREDENTIALS_KEY, JSON.stringify({ username, salt, passwordHash: await hashPassword(password, salt) }));
    return new Response(null, { status: 303, headers: { Location: "/", "Set-Cookie": "cf_webdav_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0" } });
  }
  // 新增：访问日志页面
  if (url.pathname === "/__admin/logs") {
    if (request.method !== "GET") return textResponse("Method Not Allowed", 405);
    return view === "logs" ? adminLogsPage(env) : adminPage(request, env);
  }
  const ownedAccountList = Object.values(await getWebdavAccounts(env)).filter((account) => account.owner === sessionUser_);
  const requestedAccount = url.searchParams.get("account") || (view === "account" || view === "files" || view === "logs" || view === "trash" ? ownedAccountList[0]?.username : "");
  const selectedAccount = (await getWebdavAccounts(env))[requestedAccount || ""];
  if (selectedAccount && selectedAccount.owner !== sessionUser_) return textResponse("Forbidden", 403);
  if (view === "account") return selectedAccount ? adminAccountPage(request, env, selectedAccount) : adminPage(request, env, "请先选择 WebDAV 账户");
  if (view === "logs") return adminLogsPage(selectedAccount ? createScopedEnv(env, storageScope(selectedAccount)) : env);
  if (view === "files") return selectedAccount ? adminFilesPage(request, createScopedEnv(env, storageScope(selectedAccount)), selectedAccount.username) : adminPage(request, env, "请先选择 WebDAV 账户");
  if (view === "trash") return selectedAccount ? adminTrashPage(createScopedEnv(env, storageScope(selectedAccount)), selectedAccount.username) : adminPage(request, env, "请先选择 WebDAV 账户");
  if (view === "accounts") return adminPage(request, env);
  if (request.method !== "GET") return textResponse("Method Not Allowed", 405);
  return adminPage(request, env);
}

async function superAdminRequest(request: Request, env: Env, currentAdmin: AdminAccount): Promise<Response> {
  if (request.method !== "POST") return superAdminPage(env, "");
  const form = await request.formData();
  const action = String(form.get("action") || "");
  const accounts = await getAdminAccounts(env);
  if (action === "save-admin-password") {
    const password = String(form.get("adminPassword") || "");
    if (password.length < 8) return superAdminPage(env, "管理员密码至少需要 8 位");
    const salt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
    accounts[currentAdmin.username] = { ...currentAdmin, salt, passwordHash: await hashPassword(password, salt), role: "admin" };
    await env.WEBDAV_KV.put(ADMIN_ACCOUNTS_KEY, JSON.stringify(accounts));
    return superAdminPage(env, "管理员密码已更新");
  }
  if (action === "create-user") {
    const username = String(form.get("userUsername") || "").trim();
    const password = String(form.get("userPassword") || "");
    const confirmPassword = String(form.get("userPasswordConfirm") || "");
    if (!/^[A-Za-z0-9._-]{2,64}$/.test(username) || password.length < 8) return superAdminPage(env, "用户账户格式不正确，密码至少需要 8 位");
    if (password !== confirmPassword) return superAdminPage(env, "两次输入的密码不一致");
    if (accounts[username]) return superAdminPage(env, "用户账户已存在");
    if (Object.keys(accounts).length >= 10) return superAdminPage(env, "账户最多创建 10 个");
    const salt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
    accounts[username] = { username, salt, passwordHash: await hashPassword(password, salt), role: "user" };
    await env.WEBDAV_KV.put(ADMIN_ACCOUNTS_KEY, JSON.stringify(accounts));
    return superAdminPage(env, "用户账户已创建");
  }
  if (action === "create-webdav-admin") {
    const owner = String(form.get("userUsername") || "");
    const username = String(form.get("serviceUsername") || "").trim();
    const password = String(form.get("servicePassword") || "");
    const uuid = String(form.get("accountUuid") || "").trim();
    if (!accounts[owner] || accounts[owner].role === "admin") return superAdminPage(env, "只能为普通用户创建 WebDAV 账户");
    const webdavAccounts = await getWebdavAccounts(env);
    const ownedAccounts = Object.values(webdavAccounts).filter((account) => account.owner === owner);
    if (ownedAccounts.length >= 2) return superAdminPage(env, "每个用户最多拥有 2 个 WebDAV 账户");
    if (!/^[A-Za-z0-9._-]{2,64}$/.test(username) || password.length < 8) return superAdminPage(env, "WebDAV 账户格式不正确，密码至少需要 8 位");
    if (!/^\d{6}$/.test(uuid)) return superAdminPage(env, "UUID 必须是 6 位数字");
    if (webdavAccounts[username]) return superAdminPage(env, "WebDAV 账户名已存在");
    if (Object.values(webdavAccounts).some((account) => account.uuid === uuid)) return superAdminPage(env, "UUID 已存在，请换一个");
    const salt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
    const account = { username, owner, uuid, url: "", salt, passwordHash: await hashPassword(password, salt) };
    account.url = webdavAccountUrl(request, account);
    webdavAccounts[username] = account;
    await env.WEBDAV_KV.put(WEBDAV_ACCOUNTS_KEY, JSON.stringify(webdavAccounts));
    return superAdminPage(env, "WebDAV 账户已创建");
  }
  if (action === "delete-webdav-admin") {
    const username = String(form.get("serviceUsername") || "");
    const webdavAccounts = await getWebdavAccounts(env);
    const account = webdavAccounts[username];
    if (!account || !accounts[account.owner] || accounts[account.owner].role === "admin") return superAdminPage(env, "无权删除该 WebDAV 账户");
    await deleteWebdavAccountData(env, account);
    delete webdavAccounts[username];
    await env.WEBDAV_KV.put(WEBDAV_ACCOUNTS_KEY, JSON.stringify(webdavAccounts));
    return superAdminPage(env, "WebDAV 账户及其文件已删除");
  }
  if (action === "delete-user") {
    const username = String(form.get("userUsername") || "");
    const user = accounts[username];
    if (!user || user.role === "admin" || username === currentAdmin.username) return superAdminPage(env, "只能删除普通用户账户");
    const webdavAccounts = await getWebdavAccounts(env);
    for (const account of Object.values(webdavAccounts)) {
      if (account.owner === username) {
        await deleteWebdavAccountData(env, account);
        delete webdavAccounts[account.username];
      }
    }
    delete accounts[username];
    await env.WEBDAV_KV.put(WEBDAV_ACCOUNTS_KEY, JSON.stringify(webdavAccounts));
    await env.WEBDAV_KV.put(ADMIN_ACCOUNTS_KEY, JSON.stringify(accounts));
    return superAdminPage(env, "用户及其 WebDAV 账户已删除");
  }
  return superAdminPage(env, "不支持的操作");
}

async function superAdminPage(env: Env, message: string): Promise<Response> {
  const accounts = await getAdminAccounts(env);
  const users = Object.values(accounts).filter((account) => account.role !== "admin");
  const webdavAccounts = await getWebdavAccounts(env);
  const userRows = users.map((user) => {
    const ownedAccounts = Object.values(webdavAccounts).filter((account) => account.owner === user.username);
    const accountRows = ownedAccounts.map((account) => `<div class="account-row"><span>${escapeHtml(account.username)} · ${escapeHtml(account.uuid || "------")}</span><form method="post" style="display:inline" onsubmit="return confirm('确定删除此 WebDAV 账户及其全部文件吗？')"><input type="hidden" name="action" value="delete-webdav-admin"><input type="hidden" name="serviceUsername" value="${escapeHtml(account.username)}"><button class="danger-button compact-button" type="submit">删除</button></form></div>`).join("");
    return `<tr class="user-row" data-search="${escapeHtml(`${user.username} ${ownedAccounts.map((account) => account.username).join(" ")}`.toLowerCase())}"><th scope="row">${escapeHtml(user.username)}</th><td><div class="account-list">${accountRows || '<span class="muted">暂无 WebDAV 账户</span>'}</div></td><td><form method="post" class="table-form"><input type="hidden" name="action" value="create-webdav-admin"><input type="hidden" name="userUsername" value="${escapeHtml(user.username)}"><label class="sr-only" for="service-${escapeHtml(user.username)}">WebDAV 账户</label><input id="service-${escapeHtml(user.username)}" name="serviceUsername" placeholder="账户名" required><label class="sr-only" for="password-${escapeHtml(user.username)}">密码</label><input id="password-${escapeHtml(user.username)}" name="servicePassword" type="password" minlength="8" placeholder="密码" required><label class="sr-only" for="uuid-${escapeHtml(user.username)}">6 位 UUID</label><input id="uuid-${escapeHtml(user.username)}" name="accountUuid" inputmode="numeric" pattern="[0-9]{6}" minlength="6" maxlength="6" placeholder="6 位 UUID" required><button class="primary-button compact-button" type="submit">创建</button></form></td><td><form method="post" onsubmit="return confirm('确定删除该用户及其全部 WebDAV 账户和文件吗？此操作不可恢复！')"><input type="hidden" name="action" value="delete-user"><input type="hidden" name="userUsername" value="${escapeHtml(user.username)}"><button class="danger-button" type="submit">删除用户</button></form></td></tr>`;
  }).join("");
  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>管理员控制台</title><style>${ADMIN_CSS}${USER_TABLE_CSS}${FILES_CSS}</style><body><header class="topbar"><div class="topbar-inner"><div class="brand"><span class="brand-mark small">WD</span><span>管理员控制台</span></div><div><span class="status-dot">系统管理员</span><a class="text-link" style="color:#dcebe6;margin-left:16px" href="/?action=logout">退出当前账户</a></div></div></header><main class="dashboard"><section class="page-heading"><div><p class="eyebrow">ADMINISTRATION</p><h1>用户与账户管理</h1><p class="muted">管理员只能管理用户和 WebDAV 账户信息，无法查看任何文件内容。</p></div></section>${message ? `<div class="notice success">${escapeHtml(message)}</div>` : ""}<section class="content-grid"><article class="config-card"><div class="card-heading"><div><p class="eyebrow">ADMIN PASSWORD</p><h2>修改管理员密码</h2></div><span class="icon-badge">01</span></div><form method="post" class="config-form"><input type="hidden" name="action" value="save-admin-password"><label>新密码<input name="adminPassword" type="password" autocomplete="new-password" minlength="8" required></label><button class="primary-button" type="submit">保存密码</button></form></article><article class="config-card"><div class="card-heading"><div><p class="eyebrow">NEW USER</p><h2>创建用户</h2></div><span class="icon-badge">02</span></div><form method="post" class="config-form"><input type="hidden" name="action" value="create-user"><label>用户账户<input name="userUsername" autocomplete="username" required></label><label>密码<input name="userPassword" type="password" autocomplete="new-password" minlength="8" required></label><label>确认密码<input name="userPasswordConfirm" type="password" autocomplete="new-password" minlength="8" required></label><button class="primary-button" type="submit">创建用户</button></form></article></section><section class="config-card user-table-card"><div class="card-heading"><div><p class="eyebrow">USER DIRECTORY</p><h2>用户列表</h2></div><span class="icon-badge">${users.length}</span></div><label class="filter-label" for="user-filter">筛选用户或 WebDAV 账户<input id="user-filter" type="search" placeholder="输入名称筛选" oninput="filterUsers(this.value)"></label><div class="table-scroll"><table class="user-table"><thead><tr><th scope="col">用户</th><th scope="col">WebDAV 账户</th><th scope="col">创建账户</th><th scope="col">操作</th></tr></thead><tbody id="user-table-body">${userRows || '<tr><td colspan="4" class="muted empty-cell">暂无用户。</td></tr>'}</tbody></table></div><p id="user-filter-empty" class="muted empty-cell" hidden>没有匹配的用户。</p></section></main><script>function filterUsers(value){const query=value.trim().toLowerCase();let visible=0;document.querySelectorAll('.user-row').forEach((row)=>{const matched=!query||row.dataset.search.includes(query);row.hidden=!matched;if(matched)visible+=1;});document.getElementById('user-filter-empty').hidden=visible>0||!query;}</script></body></html>`);
}

function adminLandingPage(request: Request, adminUsername: string, accounts: WebdavAccount[], nextUuid: string, message: string): Response {
  const accountCards = accounts.map((account) => `<a class="config-card account-card account-choice" href="/?view=account&account=${encodeURIComponent(account.username)}"><div class="card-heading"><div><p class="eyebrow">WEBDAV ACCOUNT</p><h2>${escapeHtml(account.username)}</h2></div><span class="icon-badge">${escapeHtml(account.uuid || "------")}</span></div><p class="muted">账户链接：${escapeHtml(webdavAccountUrl(request, account))}</p><span class="primary-button inline-button">进入账户管理</span></a>`).join("");
  const createForm = accounts.length < 2 ? `<article class="config-card account-card"><div class="card-heading"><div><p class="eyebrow">NEW ACCOUNT</p><h2>新建 WebDAV 账户</h2></div><span class="icon-badge">+</span></div><p class="muted">当前管理员最多拥有 2 个 WebDAV 账户。</p><form method="post" action="/?view=home" class="config-form"><input type="hidden" name="action" value="create-webdav"><label>账户<input name="serviceUsername" autocomplete="username" required></label><label>密码<input name="servicePassword" type="password" autocomplete="new-password" minlength="8" required></label><label>6 位 UUID<input name="accountUuid" value="${escapeHtml(nextUuid)}" inputmode="numeric" pattern="[0-9]{6}" minlength="6" maxlength="6" required></label><button class="primary-button" type="submit">创建 WebDAV 账户</button></form></article>` : "";
  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>WebDAV 账户中心</title><style>${ADMIN_CSS}${FILES_CSS}</style><body><header class="topbar"><div class="topbar-inner"><div class="brand"><span class="brand-mark small">WD</span><span>WebDAV 账户中心</span></div><span class="status-dot">管理员：${escapeHtml(adminUsername)}</span></div></header><main class="dashboard"><section class="page-heading"><div><p class="eyebrow">ACCOUNT SELECTOR</p><h1>选择 WebDAV 账户</h1><p class="muted">进入账户后只能管理该账户自己的文件。</p></div><a class="text-link" href="/?action=logout">退出当前账户</a></section>${message ? `<div class="notice success">${escapeHtml(message)}</div>` : ""}<section class="content-grid">${accountCards}${createForm}</section><p class="muted">${accounts.length}/2 个 WebDAV 账户</p></main></body></html>`);
}

async function adminAccountPage(request: Request, env: Env, account: WebdavAccount): Promise<Response> {
  const scopedEnv = createScopedEnv(env, storageScope(account));
  const fileCount = (await listAllObjects(scopedEnv, "")).filter((item) => !item.key.startsWith("__trash/")).length;
  const accountUrl = webdavAccountUrl(request, account);
  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(account.username)} - WebDAV 管理</title><style>${ADMIN_CSS}${FILES_CSS}</style><body><header class="topbar"><div class="topbar-inner"><div class="brand"><span class="brand-mark small">WD</span><span>${escapeHtml(account.username)}</span></div><a class="text-link" style="color:#dcebe6" href="/?action=logout">退出当前账户</a></div></header><main class="dashboard"><section class="page-heading"><div><p class="eyebrow">WEBDAV ACCOUNT</p><h1>${escapeHtml(account.username)}</h1><p class="muted">当前账户包含 ${fileCount} 个文件，仅显示此账户的数据。</p></div><a class="text-link" href="/">返回账户选择</a></section><section class="content-grid"><article class="config-card wide-card"><div class="card-heading"><div><p class="eyebrow">CONNECTION</p><h2>账户连接信息</h2></div><span class="icon-badge">${escapeHtml(account.uuid || "------")}</span></div><p class="muted">服务链接：${escapeHtml(accountUrl)}</p><form method="post" action="/?view=account&account=${encodeURIComponent(account.username)}" class="config-form"><input type="hidden" name="action" value="save-service"><input type="hidden" name="accountUsername" value="${escapeHtml(account.username)}"><label>账户<input name="serviceUsername" value="${escapeHtml(account.username)}" autocomplete="username" required></label><label>密码<input name="servicePassword" type="password" autocomplete="new-password" minlength="8" placeholder="输入新密码" required></label><label>6 位 UUID<input name="accountUuid" value="${escapeHtml(account.uuid || "")}" inputmode="numeric" pattern="[0-9]{6}" minlength="6" maxlength="6" required></label><button class="primary-button" type="submit">保存账户信息</button></form><a class="secondary-button inline-button" href="/?view=files&account=${encodeURIComponent(account.username)}">打开此账户文件</a></article></section></main></body></html>`);
}

async function adminAccountsPage(request: Request, env: Env, adminUsername: string): Promise<Response> {
  const accounts = Object.values(await getWebdavAccounts(env)).filter((account) => account.owner === adminUsername);
  const rows = accounts.map((account) => `<article class="config-card account-card"><div class="card-heading"><div><p class="eyebrow">WEBDAV ACCOUNT</p><h2>${escapeHtml(account.username)}</h2></div><span class="icon-badge">${escapeHtml(account.username.slice(0, 2).toUpperCase())}</span></div><p class="muted">服务链接：${escapeHtml(account.url)}</p><form method="post" action="/?view=accounts" class="config-form"><input type="hidden" name="action" value="save-service"><input type="hidden" name="accountUsername" value="${escapeHtml(account.username)}"><label>账户<input name="serviceUsername" value="${escapeHtml(account.username)}" required></label><label>密码<input name="servicePassword" type="password" minlength="8" placeholder="输入新密码" required></label><label>服务链接<input name="url" type="url" value="${escapeHtml(account.url)}" required></label><button class="primary-button" type="submit">保存 WebDAV 账户</button><a class="secondary-button inline-button" href="/?view=files&account=${encodeURIComponent(account.username)}">打开此账户文件</a></form></article>`).join("");
  const createForm = accounts.length < 2 ? `<article class="config-card account-card"><div class="card-heading"><div><p class="eyebrow">NEW ACCOUNT</p><h2>创建 WebDAV 账户</h2></div><span class="icon-badge">+</span></div><p class="muted">每个管理员最多拥有 2 个 WebDAV 账户。</p><form method="post" action="/?view=accounts" class="config-form"><input type="hidden" name="action" value="create-webdav"><label>账户<input name="serviceUsername" required></label><label>密码<input name="servicePassword" type="password" minlength="8" required></label><button class="primary-button" type="submit">创建账户</button></form></article>` : "";
  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>账号管理</title><style>${ADMIN_CSS}${FILES_CSS}</style><main class="dashboard"><section class="page-heading"><div><p class="eyebrow">ACCOUNT MANAGEMENT</p><h1>账号管理</h1><p class="muted">当前管理员：${escapeHtml(adminUsername)}。每个管理员最多拥有两个 WebDAV 账户。</p></div><a class="text-link" href="/">返回管理中心</a></section><section class="content-grid">${rows}${createForm}</section><section class="config-card admin-account-card"><div class="card-heading"><div><p class="eyebrow">NEW ADMIN</p><h2>创建管理员账户</h2></div></div><form method="post" action="/?view=accounts" class="config-form"><input type="hidden" name="action" value="create-admin"><label>管理员账户<input name="adminUsername" required></label><label>管理员密码<input name="adminPassword" type="password" minlength="8" required></label><button class="primary-button" type="submit">创建管理员</button></form></section></main></html>`);
}

async function sessionUser(request: Request, env: Env): Promise<string | null> {
  const cookie = request.headers.get("Cookie")?.match(/(?:^|; )cf_webdav_session=([^;]+)/)?.[1];
  return cookie ? env.WEBDAV_KV.get(`${SESSION_PREFIX}${cookie}`) : null;
}

function adminPath(value: string): string {
  const path = value.trim().replace(/^\/+|\/+$/g, "");
  if (!path) return "";
  if (path.split("/").some((segment) => !segment || segment === "." || segment === "..")) throw new Error("invalid path");
  return path;
}

async function adminFilesAction(request: Request, env: Env, form: FormData, username: string, accountUsername: string): Promise<Response> {
  const action = String(form.get("action") || "");
  const currentPath = adminPath(String(form.get("currentPath") || ""));
  let operationPath = currentPath;
  let operationMethod = "POST";
  let responseStatus = 303;
  try {
    if (action === "upload") {
      const file = form.get("file");
      if (!(file instanceof File) || !file.name) return textResponse("请选择文件", 400);
      const path = adminPath(`${currentPath ? `${currentPath}/` : ""}${file.name}`);
      operationPath = path;
      operationMethod = "PUT";
      await env.WEBDAV_BUCKET.put(path, file.stream(), { httpMetadata: { contentType: file.type || "application/octet-stream" } });
      await env.WEBDAV_KV.put(metaKey(path), JSON.stringify({ type: "file", size: file.size, contentType: file.type || "application/octet-stream", updatedAt: new Date().toISOString() }));
    } else if (action === "mkdir") {
      const name = String(form.get("name") || "");
      operationPath = adminPath(`${currentPath ? `${currentPath}/` : ""}${name}`);
      operationMethod = "MKCOL";
      const response = await makeCollection(env, operationPath);
      responseStatus = response.status;
    } else if (action === "delete") {
      operationPath = adminPath(String(form.get("path") || ""));
      operationMethod = "DELETE";
      const response = await deletePath(env, operationPath);
      responseStatus = response.status;
    }
  } catch (error) {
    return textResponse(error instanceof Error ? error.message : "文件操作失败", 400);
  }
  await logAccess(env, { method: operationMethod, path: operationPath, status: responseStatus, clientIp: request.headers.get("CF-Connecting-IP") || "unknown", userAgent: request.headers.get("User-Agent") || "", user: username }, Date.now());
  return new Response(null, { status: 303, headers: { Location: `/?view=files&account=${encodeURIComponent(accountUsername)}${currentPath ? `&path=${encodeURIComponent(currentPath)}` : ""}` } });
}

async function adminFilesPage(request: Request, env: Env, accountUsername: string): Promise<Response> {
  const url = new URL(request.url);
  let currentPath = "";
  try {
    currentPath = adminPath(url.searchParams.get("path") || "");
  } catch {
    return textResponse("Invalid path", 400);
  }
  const prefix = currentPath ? `${currentPath}/` : "";
  const listed = await env.WEBDAV_BUCKET.list({ prefix, delimiter: "/" });
  const directories = listed.delimitedPrefixes
    .filter((item) => !item.startsWith("__trash/"))
    .map((item) => item.slice(0, -1));
  const files = listed.objects.filter((item) => !item.key.startsWith("__trash/"));
  const parent = currentPath.includes("/") ? currentPath.slice(0, currentPath.lastIndexOf("/")) : "";
  const rows = [
    ...(currentPath ? [`<tr><td class="file-name"><a href="/?view=files&account=${encodeURIComponent(accountUsername)}${parent ? `&path=${encodeURIComponent(parent)}` : ""}">↩ 返回上级目录</a></td><td>目录</td><td>-</td><td>-</td><td>-</td></tr>`] : []),
    ...directories.map((directory) => `<tr><td class="file-name"><span class="folder-icon">DIR</span><a href="/?view=files&account=${encodeURIComponent(accountUsername)}&path=${encodeURIComponent(directory)}">${escapeHtml(directory.slice(prefix.length))}/</a></td><td>目录</td><td>-</td><td>-</td><td>-</td></tr>`),
    ...files.map((file) => `<tr><td class="file-name"><span class="file-icon">FILE</span>${escapeHtml(file.key.slice(prefix.length))}</td><td>文件</td><td>${formatBytes(file.size)}</td><td>${formatDateTime(file.uploaded)}</td><td><form method="post" action="/?view=files" onsubmit="return confirm('确认删除此文件吗？')"><input type="hidden" name="action" value="delete"><input type="hidden" name="accountUsername" value="${escapeHtml(accountUsername)}"><input type="hidden" name="path" value="${escapeHtml(file.key)}"><input type="hidden" name="currentPath" value="${escapeHtml(currentPath)}"><button class="danger-button" type="submit">删除</button></form></td></tr>`),
  ].join("");
    return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>文件管理</title><style>${ADMIN_CSS}${FILES_CSS}</style><body><header class="topbar"><div class="topbar-inner"><div class="brand"><span class="brand-mark small">WD</span><span>文件管理</span></div><a class="text-link inverse" href="/">返回账户选择</a></div></header><main class="dashboard"><section class="page-heading"><div><p class="eyebrow">FILE MANAGER</p><h1>文件管理</h1><p class="muted">账户：${escapeHtml(accountUsername)}　当前位置：/${escapeHtml(currentPath)}</p></div><a class="secondary-button inline-button" href="/?view=account&account=${encodeURIComponent(accountUsername)}">返回账户管理</a></section><section class="file-actions"><form method="post" action="/?view=files" enctype="multipart/form-data"><input type="hidden" name="action" value="upload"><input type="hidden" name="accountUsername" value="${escapeHtml(accountUsername)}"><input type="hidden" name="currentPath" value="${escapeHtml(currentPath)}"><input type="file" name="file" required><button class="primary-button" type="submit">上传文件</button></form><form method="post" action="/?view=files" class="mkdir-form"><input type="hidden" name="action" value="mkdir"><input type="hidden" name="accountUsername" value="${escapeHtml(accountUsername)}"><input type="hidden" name="currentPath" value="${escapeHtml(currentPath)}"><input name="name" placeholder="新目录名称" required><button class="secondary-button" type="submit">新建目录</button></form></section><section class="file-table-wrap"><table><thead><tr><th>名称</th><th>类型</th><th>大小</th><th>上传时间</th><th>操作</th></tr></thead><tbody>${rows || '<tr><td colspan="5" class="empty-state">当前目录为空</td></tr>'}</tbody></table></section></main></body></html>`);
}

function adminLoginPage(error = ""): Response {
  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>WebDAV 管理登录</title><style>${ADMIN_CSS}</style><main class="login-shell"><section class="login-panel"><div class="brand-mark">WD</div><p class="eyebrow">CLOUD STORAGE</p><h1>WebDAV 管理</h1><p class="muted">登录后管理账号、访问日志和文件。</p>${error ? `<p class="notice success">${escapeXml(error)}</p>` : ""}<form method="post" action="/__admin/login"><label>用户名<input name="username" autocomplete="username" required></label><label>密码<input name="password" type="password" autocomplete="current-password" required></label><button class="primary-button" type="submit">登录管理后台</button></form><a class="secondary-button register-button" href="/__admin/register">注册新用户</a></section></main>`);
}

function adminRegisterPage(error = ""): Response {
  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>注册新用户</title><style>${ADMIN_CSS}</style><main class="login-shell"><section class="login-panel"><div class="brand-mark">WD</div><p class="eyebrow">NEW USER</p><h1>注册新用户</h1><p class="muted">创建用于登录管理界面的普通用户账户。</p>${error ? `<p class="error">${escapeXml(error)}</p>` : ""}<form method="post" action="/__admin/register"><label>用户名<input name="username" autocomplete="username" required></label><label>密码<input name="password" type="password" autocomplete="new-password" minlength="8" required></label><label>确认密码<input name="confirmPassword" type="password" autocomplete="new-password" minlength="8" required></label><button class="primary-button" type="submit">注册新用户</button></form><a class="secondary-button inline-button" href="/">返回登录</a></section></main>`);
}

async function adminPage(request: Request, env: Env, message = ""): Promise<Response> {
  const adminUsername = await sessionUser(request, env) || DEFAULT_USERNAME;
  const allAccounts = await getWebdavAccounts(env);
  const ownedAccounts = Object.values(allAccounts).filter((account) => account.owner === adminUsername);
  return adminLandingPage(request, adminUsername, ownedAccounts, createAccountUuid(new Set(Object.values(allAccounts).map((account) => account.uuid).filter((uuid): uuid is string => Boolean(uuid)))), message);
  const firstAccount = ownedAccounts[0];
  const service = firstAccount ? { url: firstAccount.url, username: firstAccount.username, password: "" } : await getServiceConfig(request, env);
  const fileCount = (await Promise.all(ownedAccounts.map((account) => listAllObjects(createScopedEnv(env, storageScope(account)), "")))).flat().filter((item) => !item.key.startsWith("__trash/")).length;
  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>WebDAV 控制台</title><style>${ADMIN_CSS}</style><body><header class="topbar"><div class="topbar-inner"><div class="brand"><span class="brand-mark small">WD</span><span>WebDAV 控制台</span></div><span class="status-dot">服务在线</span></div></header><main class="dashboard"><section class="page-heading"><div><p class="eyebrow">ADMIN CONSOLE</p><h1>管理中心</h1><p class="muted">域名首页就是管理界面，集中管理连接信息与文件。</p></div><a class="text-link" href="/">刷新</a></section>${message ? `<div class="notice success">${escapeXml(message)}</div>` : ""}<section class="summary-grid"><article class="summary-card accent"><span class="card-label">服务状态</span><strong>正常运行</strong><span class="card-meta">Cloudflare Worker</span></article><article class="summary-card"><span class="card-label">文件数量</span><strong>${fileCount}</strong><span class="card-meta">R2 文件对象</span></article><article class="summary-card"><span class="card-label">安全策略</span><strong>Basic Auth</strong><span class="card-meta">会话有效期 7 天</span></article></section><section class="content-grid"><article class="config-card wide-card"><div class="card-heading"><div><p class="eyebrow">WEBDAV CONNECTION</p><h2>WebDAV 连接信息</h2></div><span class="icon-badge">01</span></div><p class="muted">将下面的信息填入 WebDAV 客户端，即可访问文件。密码会保存到 KV，仅在登录后的管理界面显示。</p><form method="post" action="/?view=home" class="config-form"><input type="hidden" name="action" value="save-service"><label>服务链接<input name="url" type="url" value="${escapeHtml(service.url)}" placeholder="https://example.workers.dev" required></label><label>账户<input name="serviceUsername" value="${escapeHtml(service.username)}" autocomplete="username" required></label><label>密码<input name="servicePassword" type="password" value="${escapeHtml(service.password)}" autocomplete="new-password" minlength="8" required></label><button class="primary-button" type="submit">保存连接信息</button></form></article><article class="config-card"><div class="card-heading"><div><p class="eyebrow">FILES</p><h2>文件管理</h2></div><span class="icon-badge">02</span></div><p class="muted">在浏览器中上传、创建目录和删除文件。</p><a class="primary-button inline-button" href="/?view=files">打开文件管理</a><div class="tool-list"><a class="tool-row" href="/?view=logs"><span><strong>访问日志</strong><small>查看请求、状态码与客户端信息</small></span><span class="arrow">→</span></a><a class="tool-row" href="/?view=trash"><span><strong>回收站</strong><small>恢复误删文件，或清空过期内容</small></span><span class="arrow">→</span></a></div></article></section><section class="info-strip"><span class="info-icon">i</span><span>WebDAV 地址：${escapeHtml(service.url)}　账户：${escapeHtml(service.username)}　密码：已保存</span></section></main></body></html>`);
}

const ADMIN_CSS = `:root{font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#17212b;background:#eef2f1}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:linear-gradient(135deg,#f6f8f5 0%,#e8efed 100%)}a{color:inherit;text-decoration:none}.topbar{background:#183b3f;color:#f4f8f5}.topbar-inner{max-width:1120px;margin:auto;padding:18px 28px;display:flex;align-items:center;justify-content:space-between}.brand{display:flex;align-items:center;gap:12px;font-weight:700;letter-spacing:.01em}.brand-mark{display:grid;place-items:center;width:42px;height:42px;background:#e8b35a;color:#183b3f;font-size:13px;font-weight:900;letter-spacing:-.06em}.brand-mark.small{width:30px;height:30px;font-size:10px}.status-dot{font-size:13px;color:#c4e3cf}.status-dot:before{content:"";display:inline-block;width:7px;height:7px;margin-right:7px;border-radius:50%;background:#6bc58d}.dashboard{max-width:1120px;margin:0 auto;padding:54px 28px 72px}.page-heading{display:flex;align-items:flex-end;justify-content:space-between;gap:24px;margin-bottom:32px}.eyebrow{margin:0 0 9px;color:#8a6940;font-size:11px;font-weight:800;letter-spacing:.16em}.page-heading h1{margin:0;font-size:clamp(30px,5vw,48px);letter-spacing:-.04em}.muted{color:#667578;line-height:1.6}.text-link{color:#32656a;font-size:14px;font-weight:700}.summary-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:22px}.summary-card,.config-card{background:rgba(255,255,255,.82);border:1px solid #d7e0dc;box-shadow:0 12px 30px rgba(31,61,57,.06)}.summary-card{min-height:132px;padding:22px}.summary-card.accent{border-top:3px solid #d79b41}.card-label{display:block;margin-bottom:20px;color:#71807e;font-size:12px;font-weight:700}.summary-card strong{display:block;font-size:22px;letter-spacing:-.02em}.card-meta{display:block;margin-top:8px;color:#84918f;font-size:13px}.content-grid{display:grid;grid-template-columns:1fr 1fr;gap:22px}.config-card{padding:28px}.card-heading{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:8px}.card-heading h2{margin:0;font-size:22px;letter-spacing:-.03em}.icon-badge{display:grid;place-items:center;width:32px;height:32px;background:#eef3ee;color:#8a6940;font-size:11px;font-weight:800}.config-form{margin-top:25px}.config-form label{display:block;margin:17px 0 6px;font-size:13px;font-weight:700}.config-form input{display:block;width:100%;margin-top:7px;padding:13px 14px;border:1px solid #cbd7d3;border-radius:2px;background:#fbfcfa;color:#17212b;font:inherit;outline:none}.config-form input:focus{border-color:#4c8581;box-shadow:0 0 0 3px rgba(76,133,129,.14)}.primary-button{margin-top:20px;padding:12px 18px;border:0;border-radius:2px;background:#d79b41;color:#183b3f;font:inherit;font-weight:800;cursor:pointer}.primary-button:hover{background:#e5ae59}.tool-list{margin-top:17px;border-top:1px solid #e0e7e3}.tool-row{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:20px 0;border-bottom:1px solid #e0e7e3}.tool-row strong,.tool-row small{display:block}.tool-row small{margin-top:5px;color:#71807e;font-size:13px}.arrow{color:#397277;font-size:22px}.info-strip{display:flex;align-items:center;gap:11px;margin-top:22px;padding:16px 19px;background:#e7f0eb;color:#45625d;font-size:13px;line-height:1.5}.info-icon{display:grid;place-items:center;flex:none;width:20px;height:20px;border:1px solid #70968b;border-radius:50%;font-size:12px}.notice{margin:-12px 0 22px;padding:13px 16px;background:#e7f4eb;border-left:3px solid #3d9368}.success{color:#176b48}.error{margin:18px 0;padding:11px 13px;background:#fff0ee;color:#a43f35}.login-shell{display:grid;place-items:center;min-height:100vh;padding:24px}.login-panel{width:min(100%,420px);padding:42px;background:rgba(255,255,255,.9);border:1px solid #d7e0dc;box-shadow:0 18px 50px rgba(31,61,57,.12)}.login-panel h1{margin:0;font-size:32px;letter-spacing:-.04em}.login-panel .muted{margin:10px 0 28px}.login-panel label{display:block;margin:17px 0 6px;font-size:13px;font-weight:700}.login-panel input{display:block;width:100%;margin-top:7px;padding:13px 14px;border:1px solid #cbd7d3;border-radius:2px;background:#fbfcfa;color:#17212b;font:inherit}.login-panel .primary-button{width:100%;margin-top:25px}@media(max-width:720px){.topbar-inner,.dashboard{padding-left:20px;padding-right:20px}.dashboard{padding-top:36px}.page-heading{align-items:flex-start;flex-direction:column}.summary-grid,.content-grid{grid-template-columns:1fr}.config-card{padding:22px}}`;
const USER_TABLE_CSS = `.user-table-card{grid-column:1/-1}.filter-label{display:block;max-width:360px;margin:22px 0 16px;font-size:13px;font-weight:700}.filter-label input{display:block;width:100%;margin-top:7px;padding:11px 13px;border:1px solid #cbd7d3;border-radius:2px;background:#fff;color:#17212b;font:inherit}.table-scroll{overflow-x:auto}.user-table{width:100%;min-width:840px;border-collapse:collapse}.user-table th,.user-table td{padding:15px 12px;border-bottom:1px solid #dce5e1;text-align:left;vertical-align:top;font-size:13px}.user-table th{color:#66807a;font-size:11px;letter-spacing:.12em}.user-table tbody th{color:#17212b;font-size:14px;letter-spacing:0}.user-table th:last-child,.user-table td:last-child{width:1%;white-space:nowrap}.account-list{min-width:190px}.account-row{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:8px}.account-row:last-child{margin-bottom:0}.table-form{display:grid;grid-template-columns:repeat(3,minmax(90px,1fr));gap:7px;min-width:330px}.table-form input{width:100%;padding:9px 10px;border:1px solid #cbd7d3;border-radius:2px;background:#fff;color:#17212b;font:inherit}.table-form .primary-button{grid-column:1/-1}.compact-button{padding:8px 11px;font-size:12px}`;

const UI_POLISH_CSS = `.login-shell{background:radial-gradient(circle at 15% 15%,rgba(232,179,90,.25),transparent 32%),linear-gradient(145deg,#173b3f,#285d5d);position:relative;overflow:hidden}.login-shell:before{content:"";position:absolute;width:420px;height:420px;border:1px solid rgba(255,255,255,.14);border-radius:50%;transform:translate(55%,30%)}.login-panel{position:relative;background:rgba(255,255,255,.96);border:1px solid rgba(255,255,255,.8);box-shadow:0 24px 70px rgba(9,35,35,.28);border-radius:8px}.login-panel h1{font-size:34px;letter-spacing:-.04em}.login-panel form{margin-top:26px}.login-panel label{display:block;margin:16px 0 6px;font-size:13px;font-weight:700}.login-panel input{display:block;width:100%;margin-top:7px;padding:13px 14px;border:1px solid #cbd7d3;border-radius:4px;background:#fff;color:#17212b;font:inherit}.login-panel input:focus,.filter-label input:focus,.table-form input:focus{outline:3px solid rgba(169,209,192,.55);outline-offset:1px}.login-panel .primary-button{width:100%;margin-top:14px}.register-button{display:flex;margin-top:12px;text-align:center}.config-card,.summary-card{border-radius:7px;transition:transform .2s ease,box-shadow .2s ease}.config-card:hover,.summary-card:hover{box-shadow:0 18px 38px rgba(31,61,57,.1)}.primary-button,.secondary-button,.danger-button{border-radius:4px;transition:transform .15s ease,filter .15s ease}.primary-button:hover,.secondary-button:hover,.danger-button:hover{filter:brightness(.97);transform:translateY(-1px)}.file-table-wrap{border-radius:7px;box-shadow:0 12px 30px rgba(31,61,57,.06)}.file-table-wrap th{background:#eaf2ee}.page-heading .secondary-button{margin:0}.notice{border-radius:0 4px 4px 0}.topbar{box-shadow:0 3px 16px rgba(10,42,42,.16)}@media(max-width:760px){.page-heading .secondary-button{margin-top:4px}.login-panel{padding:28px 22px}.login-panel h1{font-size:30px}.config-card,.summary-card{border-radius:5px}}`;

function htmlResponse(body: string): Response {
  const adminForm = body.includes("<title>WebDAV 控制台</title>")
    ? `<section class="config-card admin-account-card"><div class="card-heading"><div><p class="eyebrow">ADMIN ACCOUNT</p><h2>管理员账号</h2></div><span class="icon-badge">03</span></div><p class="muted">管理员账号只用于登录此管理界面，不用于 WebDAV 客户端。</p><form method="post" action="/?view=home" class="config-form"><input type="hidden" name="action" value="save-admin"><label>管理员账户<input name="adminUsername" autocomplete="username" placeholder="例如：admin" required></label><label>管理员密码<input name="adminPassword" type="password" autocomplete="new-password" minlength="8" placeholder="至少 8 位" required></label><button class="primary-button" type="submit">保存管理员账号</button></form><a class="secondary-button inline-button" href="/?view=accounts">管理所有账户</a></section>`
    : "";
  const userPasswordForm = body.includes("<title>WebDAV 账户中心</title>")
    ? `<section class="config-card admin-account-card"><div class="card-heading"><div><p class="eyebrow">USER PASSWORD</p><h2>修改当前用户密码</h2></div></div><form method="post" action="/?view=home" class="config-form"><input type="hidden" name="action" value="save-user-password"><label>新密码<input name="userPassword" type="password" autocomplete="new-password" minlength="8" required></label><button class="primary-button" type="submit">保存密码</button></form></section>`
    : "";
  const bodyWithUserPassword = userPasswordForm ? body.replace("</main></body>", `${userPasswordForm}</main></body>`) : body;
  const renderedBody = adminForm ? bodyWithUserPassword.replace("</main></body>", `${adminForm}</main></body>`) : bodyWithUserPassword;
  const withLogout = renderedBody.replace('<span class="status-dot">服务在线</span>', '<span class="status-dot">服务在线</span><a class="text-link" style="color:#dcebe6;margin-left:16px" href="/?action=logout">退出当前账户</a>');
  const accountFileLink = withLogout.match(/<a class="secondary-button inline-button" href="\/\?view=files&account=([^"]+)">打开此账户文件<\/a>/);
  const withAccountTools = accountFileLink ? withLogout.replace(accountFileLink[0], `${accountFileLink[0]}<a class="secondary-button inline-button" href="/?view=logs&account=${accountFileLink[1]}">访问日志</a><a class="secondary-button inline-button" href="/?view=trash&account=${accountFileLink[1]}">回收站</a><form method="post" action="/?view=account" class="inline-button" onsubmit="return confirm('确定要删除此 WebDAV 账户及其全部文件吗？此操作不可恢复！')"><input type="hidden" name="action" value="delete-webdav"><input type="hidden" name="accountUsername" value="${escapeHtml(decodeURIComponent(accountFileLink[1]))}"><button class="danger-button" type="submit">删除整个账户</button></form>`) : withLogout;
  const polishedBody = withAccountTools.replace("</style>", `${UI_POLISH_CSS}</style>`);
  return new Response(polishedBody, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
}

function requestPath(request: Request, env: Env, account?: WebdavAccount): string {
  const pathname = new URL(request.url).pathname;
  const prefix = normalizePrefix(env.DAV_PREFIX ?? "");
  const path = decodeURIComponent(pathname).replace(/^\/+|\/+$/g, "");
  if (prefix && path !== prefix && !path.startsWith(`${prefix}/`)) throw new Error("outside prefix");
  let relative = prefix ? path.slice(prefix.length).replace(/^\/+/, "") : path;
  const accountPrefix = account ? `${account.owner}/${account.uuid}` : "";
  if (accountPrefix && (relative === accountPrefix || relative.startsWith(`${accountPrefix}/`))) relative = relative.slice(accountPrefix.length).replace(/^\/+/, "");
  const segments = relative ? relative.split("/") : [];
  if (segments.some((segment) => !segment || segment === "." || segment === "..")) throw new Error("invalid path");
  return segments.join("/");
}

function destinationPath(request: Request, env: Env, account?: WebdavAccount): string {
  const destination = request.headers.get("Destination");
  if (!destination) throw new Error("missing destination");
  return requestPath(new Request(new URL(destination, request.url), request), env, account);
}

function normalizePrefix(value: string): string {
  return value.replace(/^\/+|\/+$/g, "");
}

function r2Key(path: string): string {
  return path;
}

function metaKey(path: string): string {
  return `${META_PREFIX}${encodeURIComponent(path)}`;
}

function dirKey(path: string): string {
  return `${DIR_PREFIX}${encodeURIComponent(path)}`;
}

function optionsResponse(): Response {
  return new Response(null, {
    status: 204,
    headers: { Allow: METHODS.join(", "), DAV: "1", "MS-Author-Via": "DAV" },
  });
}

async function getObject(env: Env, path: string, head: boolean, request: Request): Promise<Response> {
  if (!path) return textResponse("A directory cannot be downloaded", 405);
  const object = await env.WEBDAV_BUCKET.get(r2Key(path), { range: request.headers });
  if (!object) return textResponse("Not Found", 404);
  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("ETag", object.httpEtag);
  headers.set("Accept-Ranges", "bytes");
  headers.set("Content-Length", String(object.size));
  return new Response(head ? null : object.body, { headers });
}

async function putObject(request: Request, env: Env, path: string): Promise<Response> {
  if (!path) return textResponse("A file path is required", 400);
  const contentType = request.headers.get("Content-Type") ?? "application/octet-stream";
  const object = await env.WEBDAV_BUCKET.put(r2Key(path), request.body, { httpMetadata: { contentType } });
  const metadata: FileMeta = { type: "file", size: object.size, etag: object.httpEtag, contentType, updatedAt: new Date().toISOString() };
  await env.WEBDAV_KV.put(metaKey(path), JSON.stringify(metadata));
  return new Response(null, { status: 201, headers: { ETag: object.httpEtag } });
}

async function makeCollection(env: Env, path: string): Promise<Response> {
  if (!path) return textResponse("The root collection already exists", 405);
  if (await env.WEBDAV_KV.get(dirKey(path)) || await env.WEBDAV_BUCKET.head(r2Key(path))) return textResponse("Collection already exists", 405);
  await env.WEBDAV_KV.put(dirKey(path), new Date().toISOString());
  return new Response(null, { status: 201 });
}

async function deletePath(env: Env, path: string): Promise<Response> {
  if (!path) return textResponse("The root collection cannot be deleted", 403);

  const object = await env.WEBDAV_BUCKET.head(r2Key(path));
  if (object) {
    // 软删除：移动到回收站
    const trashKey = `${TRASH_PREFIX}${Date.now()}_${path}`;
    const trashMeta = {
      originalPath: path,
      deletedAt: new Date().toISOString(),
      size: object.size,
      contentType: object.httpMetadata?.contentType,
    };

    // 复制文件到回收站位置（使用特殊前缀）
    const fileContent = await env.WEBDAV_BUCKET.get(r2Key(path));
    if (fileContent) {
      await env.WEBDAV_BUCKET.put(`__trash/${trashKey}`, fileContent.body, {
        httpMetadata: fileContent.httpMetadata,
        customMetadata: { originalPath: path, deletedAt: trashMeta.deletedAt },
      });
    }

    // 删除原文件
    await env.WEBDAV_BUCKET.delete(r2Key(path));
    await env.WEBDAV_KV.delete(metaKey(path));

    // 记录删除信息到 KV（用于管理界面显示）
    await env.WEBDAV_KV.put(`${TRASH_PREFIX}${path}`, JSON.stringify(trashMeta), {
      expirationTtl: TRASH_RETENTION_DAYS * 24 * 60 * 60,
    });

    return new Response(null, { status: 204 });
  }

  // 目录删除
  if (!(await env.WEBDAV_KV.get(dirKey(path))) && !(await hasChildren(env, path))) return textResponse("Not Found", 404);

  // 软删除目录及其内容
  const objects = await listAllObjects(env, `${path}/`);
  const deletedAt = new Date().toISOString();

  // 移动文件到回收站
  for (let index = 0; index < objects.length; index += 1000) {
    const batch = objects.slice(index, index + 1000);
    for (const item of batch) {
      const trashKey = `${TRASH_PREFIX}${Date.now()}_${item.key}`;
      const fileContent = await env.WEBDAV_BUCKET.get(item.key);
      if (fileContent) {
        await env.WEBDAV_BUCKET.put(`__trash/${trashKey}`, fileContent.body, {
          httpMetadata: fileContent.httpMetadata,
          customMetadata: { originalPath: item.key, deletedAt },
        });
      }
      await env.WEBDAV_BUCKET.delete(item.key);
    }
  }

  // 删除元数据
  await deleteMetadataUnder(env, path);

  // 记录目录删除信息
  await env.WEBDAV_KV.put(`${TRASH_PREFIX}${path}`, JSON.stringify({
    originalPath: path,
    deletedAt,
    isDirectory: true,
    fileCount: objects.length,
  }), { expirationTtl: TRASH_RETENTION_DAYS * 24 * 60 * 60 });

  return new Response(null, { status: 204 });
}

// 新增：恢复回收站文件
async function restoreFromTrash(env: Env, trashPath: string): Promise<Response> {
  const trashMeta = await env.WEBDAV_KV.get(`${TRASH_PREFIX}${trashPath}`, "json") as { originalPath: string; deletedAt: string } | null;
  if (!trashMeta) return textResponse("Not Found in Trash", 404);

  // 恢复文件
  const trashObjects = await listAllObjects(env, `__trash/${TRASH_PREFIX}`);
  for (const obj of trashObjects) {
    const customMeta = obj.customMetadata;
    if (customMeta?.originalPath === trashMeta.originalPath || customMeta?.originalPath?.startsWith(`${trashMeta.originalPath}/`)) {
      const content = await env.WEBDAV_BUCKET.get(obj.key);
      if (content) {
        await env.WEBDAV_BUCKET.put(customMeta.originalPath, content.body, {
          httpMetadata: content.httpMetadata,
        });
      }
      await env.WEBDAV_BUCKET.delete(obj.key);
    }
  }

  // 删除回收站记录
  await env.WEBDAV_KV.delete(`${TRASH_PREFIX}${trashPath}`);

  return new Response(null, { status: 204 });
}

// 新增：清空回收站
async function emptyTrash(env: Env): Promise<Response> {
  const trashObjects = await listAllObjects(env, "__trash/");
  for (let index = 0; index < trashObjects.length; index += 1000) {
    const batch = trashObjects.slice(index, index + 1000);
    await env.WEBDAV_BUCKET.delete(batch.map(item => item.key));
  }

  // 删除所有回收站元数据
  const trashMetaKeys = await listAllKV(env, TRASH_PREFIX);
  for (const key of trashMetaKeys) {
    await env.WEBDAV_KV.delete(key);
  }

  return new Response(null, { status: 204 });
}

async function copyOrMove(request: Request, env: Env, source: string, move: boolean, account?: WebdavAccount): Promise<Response> {
  if (!source) return textResponse("The root collection cannot be moved", 403);
  const destination = destinationPath(request, env, account);
  if (!destination || destination === source || destination.startsWith(`${source}/`)) return textResponse("Invalid destination", 400);
  const overwrite = (request.headers.get("Overwrite") ?? "T").toUpperCase() !== "F";
  const destinationObject = await env.WEBDAV_BUCKET.head(r2Key(destination));
  if (destinationObject && !overwrite) return textResponse("Destination exists", 412);
  if (destinationObject) await env.WEBDAV_BUCKET.delete(r2Key(destination));
  const sourceObject = await env.WEBDAV_BUCKET.get(r2Key(source));
  if (sourceObject) {
    await env.WEBDAV_BUCKET.put(r2Key(destination), sourceObject.body, { httpMetadata: sourceObject.httpMetadata });
    const sourceMeta = await env.WEBDAV_KV.get(metaKey(source));
    if (sourceMeta) await env.WEBDAV_KV.put(metaKey(destination), sourceMeta);
    if (move) {
      await env.WEBDAV_BUCKET.delete(r2Key(source));
      await env.WEBDAV_KV.delete(metaKey(source));
    }
    return new Response(null, { status: 201 });
  }
  if (!(await hasChildren(env, source)) && !(await env.WEBDAV_KV.get(dirKey(source)))) return textResponse("Not Found", 404);
  const objects = await listAllObjects(env, `${source}/`);
  for (const item of objects) {
    const body = await env.WEBDAV_BUCKET.get(item.key);
    if (body) await env.WEBDAV_BUCKET.put(`${destination}/${item.key.slice(source.length + 1)}`, body.body, { httpMetadata: body.httpMetadata });
  }
  const sourceDirs = await listAllKV(env, DIR_PREFIX);
  for (const key of sourceDirs) {
    const directory = decodeURIComponent(key.slice(DIR_PREFIX.length));
    if (directory === source || directory.startsWith(`${source}/`)) {
      await env.WEBDAV_KV.put(dirKey(`${destination}${directory.slice(source.length)}`), new Date().toISOString());
    }
  }
  if (move) await deletePath(env, source);
  await env.WEBDAV_KV.put(dirKey(destination), new Date().toISOString());
  return new Response(null, { status: 201 });
}

async function propfind(request: Request, env: Env, path: string, account?: WebdavAccount): Promise<Response> {
  const depth = (request.headers.get("Depth") ?? "infinity").trim().toLowerCase();
  if (depth !== "0" && depth !== "1" && depth !== "infinity") return textResponse("Invalid Depth header", 400);
  const rootObject = path ? await env.WEBDAV_BUCKET.head(r2Key(path)) : null;
  const rootIsDirectory = !rootObject;
  if (path && !rootObject && !(await env.WEBDAV_KV.get(dirKey(path))) && !(await hasChildren(env, path))) return textResponse("Not Found", 404);
  const entries = [{ path, directory: rootIsDirectory }];
  if (depth === "1" && rootIsDirectory) entries.push(...await listChildren(env, path));
  if (depth === "infinity" && rootIsDirectory) entries.push(...await listDescendants(env, path));
  const xml = entries.map((entry) => propResponse(request, env, entry.path, entry.directory, account)).join("");
  return new Response(`<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:">${xml}</d:multistatus>`, { status: 207, headers: { "Content-Type": "text/xml; charset=utf-8", DAV: "1", "Cache-Control": "no-store" } });
}

async function propResponse(request: Request, env: Env, path: string, directory: boolean, account?: WebdavAccount): Promise<string> {
  const object = directory ? null : await env.WEBDAV_BUCKET.head(r2Key(path));
  const displayName = path ? path.slice(path.lastIndexOf("/") + 1) : "WebDAV";
  const href = `${new URL(request.url).origin}${urlPath(env, path)}${directory ? "/" : ""}`;
  const size = object?.size ?? 0;
  const modified = object?.uploaded?.toUTCString() ?? new Date().toUTCString();
  return `<d:response><d:href>${escapeXml(href)}</d:href><d:propstat><d:prop><d:displayname>${escapeXml(displayName)}</d:displayname><d:resourcetype>${directory ? "<d:collection/>" : ""}</d:resourcetype><d:getcontentlength>${size}</d:getcontentlength><d:getlastmodified>${modified}</d:getlastmodified><d:getcontenttype>${directory ? "httpd/unix-directory" : escapeXml(object?.httpMetadata?.contentType ?? "application/octet-stream")}</d:getcontenttype>${object?.httpEtag ? `<d:getetag>${escapeXml(object.httpEtag)}</d:getetag>` : ""}</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>`;
}

function urlPath(env: Env, path: string): string {
  const prefix = normalizePrefix(env.DAV_PREFIX ?? "");
  return `/${[prefix, path].filter(Boolean).join("/").split("/").map(encodeURIComponent).join("/")}`;
}

async function listChildren(env: Env, path: string): Promise<Array<{ path: string; directory: boolean }>> {
  const prefix = path ? `${path}/` : "";
  const listed = await env.WEBDAV_BUCKET.list({ prefix, delimiter: "/" });
  const result = listed.delimitedPrefixes.map((item) => ({ path: item.slice(0, -1), directory: true }));
  for (const object of listed.objects) result.push({ path: object.key, directory: false });
  const dirs = await listAllKV(env, `${DIR_PREFIX}${encodeURIComponent(prefix)}`);
  for (const key of dirs) {
    const child = decodeURIComponent(key.slice((DIR_PREFIX + encodeURIComponent(prefix)).length));
    if (child && !child.includes("/")) result.push({ path: `${prefix}${child}`, directory: true });
  }
  return [...new Map(result.map((entry) => [entry.path, entry])).values()];
}

async function listDescendants(env: Env, path: string): Promise<Array<{ path: string; directory: boolean }>> {
  const descendants: Array<{ path: string; directory: boolean }> = [];
  const children = await listChildren(env, path);
  for (const child of children) {
    descendants.push(child);
    if (child.directory) descendants.push(...await listDescendants(env, child.path));
  }
  return descendants;
}

async function hasChildren(env: Env, path: string): Promise<boolean> {
  return (await listChildren(env, path)).length > 0;
}

async function listAllObjects(env: Env, prefix: string): Promise<R2Object[]> {
  const result: R2Object[] = [];
  let cursor: string | undefined;
  do {
    const page = await env.WEBDAV_BUCKET.list({ prefix, cursor });
    result.push(...page.objects);
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  return result;
}

async function listAllKV(env: Env, prefix: string): Promise<string[]> {
  const result: string[] = [];
  let cursor: string | undefined;
  do {
    const page = await env.WEBDAV_KV.list({ prefix, cursor, limit: 1000 });
    result.push(...page.keys.map((key) => key.name));
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return result;
}

async function deleteWebdavAccountData(env: Env, account: WebdavAccount): Promise<void> {
  const scopedEnv = createScopedEnv(env, storageScope(account));
  const [objects, keys] = await Promise.all([listAllObjects(scopedEnv, ""), listAllKV(scopedEnv, "")]);
  for (const object of objects) await scopedEnv.WEBDAV_BUCKET.delete(object.key);
  for (const key of keys) await scopedEnv.WEBDAV_KV.delete(key);
}

async function deleteMetadataUnder(env: Env, path: string): Promise<void> {
  const [files, dirs] = await Promise.all([listAllKV(env, META_PREFIX), listAllKV(env, DIR_PREFIX)]);
  const prefix = `${path}/`;
  await Promise.all([...files, ...dirs].filter((key) => {
    const marker = key.startsWith(META_PREFIX) ? META_PREFIX : DIR_PREFIX;
    const decodedPath = decodeURIComponent(key.slice(marker.length));
    return decodedPath === path || decodedPath.startsWith(prefix);
  }).map((key) => env.WEBDAV_KV.delete(key)));
}

function escapeXml(value: string): string {
  return value.replace(/[<>&'\"]/g, (character) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", "'": "&apos;", '"': "&quot;" })[character] ?? character);
}

function escapeHtml(value: string): string {
  return escapeXml(value);
}

function textResponse(body: string, status: number, extraHeaders: Record<string, string> = {}): Response {
  return new Response(body, { status, headers: { "Content-Type": "text/plain; charset=utf-8", ...extraHeaders } });
}

// 新增：流量限制配置
interface RateLimitConfig {
  maxRequestsPerMinute: number;
  maxUploadBytesPerHour: number;
}

const DEFAULT_RATE_LIMIT: RateLimitConfig = {
  maxRequestsPerMinute: 60,
  maxUploadBytesPerHour: 1024 * 1024 * 1024, // 1GB
};

const RATE_LIMIT_PREFIX = "ratelimit:";

// 新增：检查流量限制
async function checkRateLimit(env: Env, clientIp: string, method: string, contentLength: number): Promise<{ allowed: boolean; retryAfter?: number }> {
  // 默认限制，后续可扩展为从 KV 读取配置
  const config = DEFAULT_RATE_LIMIT;
  const now = Date.now();
  const minuteKey = `${RATE_LIMIT_PREFIX}${clientIp}:minute:${Math.floor(now / 60000)}`;
  const hourKey = `${RATE_LIMIT_PREFIX}${clientIp}:hour:${Math.floor(now / 3600000)}`;

  // 检查每分钟请求数
  const minuteCount = parseInt(await env.WEBDAV_KV.get(minuteKey) || "0");
  if (minuteCount >= config.maxRequestsPerMinute) {
    return { allowed: false, retryAfter: 60 - (Math.floor(now / 1000) % 60) };
  }

  // 检查每小时上传流量（仅对 PUT 请求）
  if (method === "PUT") {
    const hourBytes = parseInt(await env.WEBDAV_KV.get(hourKey) || "0");
    if (hourBytes + contentLength > config.maxUploadBytesPerHour) {
      return { allowed: false, retryAfter: 3600 - (Math.floor(now / 1000) % 3600) };
    }
  }

  // 更新计数
  await env.WEBDAV_KV.put(minuteKey, String(minuteCount + 1), { expirationTtl: 120 });
  if (method === "PUT") {
    const hourBytes = parseInt(await env.WEBDAV_KV.get(hourKey) || "0");
    await env.WEBDAV_KV.put(hourKey, String(hourBytes + contentLength), { expirationTtl: 3700 });
  }

  return { allowed: true };
}

// 新增：访问日志页面
async function adminLogsPage(env: Env): Promise<Response> {
  const logs: AccessLog[] = [];
  let cursor: string | undefined;
  do {
    const page = await env.WEBDAV_KV.list({ prefix: LOG_PREFIX, cursor, limit: 100 });
    for (const key of page.keys) {
      const log = await env.WEBDAV_KV.get(key.name, "json") as AccessLog | null;
      if (log) logs.push(log);
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);

  logs.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  const recentLogs = logs.slice(0, 100);

  const logRows = recentLogs.map(log => {
    const time = new Date(log.timestamp).toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" });
    const method = log.method;
    const path = escapeXml(log.path || "/");
    const status = log.status;
    const statusClass = status >= 400 ? "error" : status >= 300 ? "warn" : "success";
    const size = log.bytesSent ? formatBytes(log.bytesSent) : "-";
    const ip = log.clientIp || "-";
    const user = log.user || "-";
    return `<tr><td>${time}</td><td><span class="method ${method}">${method}</span></td><td class="path">${path}</td><td><span class="status ${statusClass}">${status}</span></td><td>${size}</td><td>${ip}</td><td>${user}</td></tr>`;
  }).join("");

  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>访问日志</title><style>${ADMIN_CSS}${LOGS_CSS}</style><main class="dashboard"><h1>访问日志</h1><p>最近 ${recentLogs.length} 条记录（保留 ${LOG_RETENTION_DAYS} 天）</p><table><thead><tr><th>时间</th><th>方法</th><th>路径</th><th>状态</th><th>大小</th><th>IP</th><th>用户</th></tr></thead><tbody>${logRows || '<tr><td colspan="7">暂无日志</td></tr>'}</tbody></table><p><a href="/">← 返回管理中心</a></p></main>`);
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + " MB";
  return (bytes / (1024 * 1024 * 1024)).toFixed(1) + " GB";
}

function formatDateTime(value: Date | string): string {
  return new Date(value).toLocaleString("zh-CN", { timeZone: "Asia/Shanghai", hour12: false });
}

const LOGS_CSS = `
table{width:100%;border-collapse:collapse;margin:20px 0;font-size:14px}
th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #e1e4e8}
th{background:#f6f8fa;font-weight:600}
.path{max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.method{padding:2px 6px;border-radius:3px;font-size:12px;font-weight:500}
.method.GET{background:#e3f2fd;color:#1565c0}
.method.PUT{background:#fff3e0;color:#e65100}
.method.DELETE{background:#ffebee;color:#c62828}
.method.MKCOL{background:#e8f5e9;color:#2e7d32}
.method.COPY,.method.MOVE{background:#f3e5f5;color:#6a1b9a}
.method.PROPFIND{background:#e0f2f1;color:#00695c}
.status{padding:2px 6px;border-radius:3px;font-size:12px;font-weight:500}
.status.success{background:#e8f5e9;color:#2e7d32}
.status.warn{background:#fff3e0;color:#e65100}
.status.error{background:#ffebee;color:#c62828}
a{color:#1769aa;text-decoration:none}
a:hover{text-decoration:underline}
`;

// 新增：回收站管理页面
async function adminTrashPage(env: Env, accountUsername: string): Promise<Response> {
  const trashItems: Array<{ path: string; originalPath: string; deletedAt: string; size?: number; isDirectory?: boolean }> = [];
  let cursor: string | undefined;
  do {
    const page = await env.WEBDAV_KV.list({ prefix: TRASH_PREFIX, cursor, limit: 100 });
    for (const key of page.keys) {
      const meta = await env.WEBDAV_KV.get(key.name, "json") as { originalPath: string; deletedAt: string; size?: number; isDirectory?: boolean } | null;
      if (meta) {
        const path = decodeURIComponent(key.name.slice(TRASH_PREFIX.length));
        trashItems.push({ path, ...meta });
      }
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);

  trashItems.sort((a, b) => b.deletedAt.localeCompare(a.deletedAt));

  const trashRows = trashItems.map(item => {
    const time = formatDateTime(item.deletedAt);
    const path = escapeXml(item.originalPath);
    const type = item.isDirectory ? "目录" : "文件";
    const size = item.size ? formatBytes(item.size) : "-";
    return `<tr><td>${path}</td><td>${type}</td><td>${size}</td><td>${time}</td><td><form method="post" action="/?view=trash&account=${encodeURIComponent(accountUsername)}" style="display:inline"><input type="hidden" name="action" value="restore"><input type="hidden" name="accountUsername" value="${escapeHtml(accountUsername)}"><input type="hidden" name="path" value="${escapeXml(item.path)}"><button type="submit" class="restore-btn">恢复</button></form></td></tr>`;
  }).join("");

  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>回收站</title><style>${ADMIN_CSS}${TRASH_CSS}</style><main class="dashboard"><h1>回收站</h1><p>账户：${escapeHtml(accountUsername)}。已删除的文件将在 ${TRASH_RETENTION_DAYS} 天后自动清理</p><table><thead><tr><th>原路径</th><th>类型</th><th>大小</th><th>删除时间</th><th>操作</th></tr></thead><tbody>${trashRows || '<tr><td colspan="5">回收站为空</td></tr>'}</tbody></table>${trashItems.length > 0 ? `<form method="post" action="/?view=trash&account=${encodeURIComponent(accountUsername)}" class="empty-form"><input type="hidden" name="action" value="empty"><input type="hidden" name="accountUsername" value="${escapeHtml(accountUsername)}"><button type="submit" class="empty-btn" onclick="return confirm('确定要清空回收站吗？此操作不可恢复！')">清空回收站</button></form>` : ""}<p><a href="/?view=account&account=${encodeURIComponent(accountUsername)}">← 返回账户管理</a></p></main>`);
}

const TRASH_CSS = `
table{width:100%;border-collapse:collapse;margin:20px 0;font-size:14px}
th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #e1e4e8}
th{background:#f6f8fa;font-weight:600}
.restore-btn{padding:4px 12px;background:#2e7d32;color:white;border:0;border-radius:3px;cursor:pointer;font-size:12px}
.restore-btn:hover{background:#1b5e20}
.empty-form{margin:20px 0;text-align:center}
.empty-btn{padding:10px 20px;background:#c62828;color:white;border:0;border-radius:5px;cursor:pointer;font-size:14px}
.empty-btn:hover{background:#b71c1c}
a{color:#1769aa;text-decoration:none}
a:hover{text-decoration:underline}
`;

const FILES_CSS = `
.inverse{color:#dcebe6}.file-actions{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:22px}.file-actions form{display:flex;flex-wrap:wrap;gap:8px;align-items:center}.file-actions input[type=file],.mkdir-form input{padding:11px;border:1px solid #cbd7d3;background:#fff;font:inherit}.secondary-button{padding:12px 18px;border:1px solid #397277;border-radius:2px;background:#fff;color:#285b60;font:inherit;font-weight:800;cursor:pointer}.inline-button{display:inline-block;margin:12px 0 18px}.file-table-wrap{overflow-x:auto;background:rgba(255,255,255,.82);border:1px solid #d7e0dc}.file-table-wrap table{width:100%;border-collapse:collapse;min-width:640px}.file-table-wrap th,.file-table-wrap td{padding:15px 18px;text-align:left;border-bottom:1px solid #e0e7e3}.file-table-wrap th{background:#f2f6f3;color:#60716d;font-size:12px}.file-name{font-weight:700}.file-name a{color:#285b60}.folder-icon,.file-icon{display:inline-block;width:34px;margin-right:8px;color:#a47735;font-size:9px;font-weight:900}.file-icon{color:#51817c}.danger-button{padding:7px 11px;border:1px solid #c76c61;border-radius:2px;background:#fff5f3;color:#a43f35;font:inherit;font-size:12px;cursor:pointer}.empty-state{text-align:center;color:#71807e;padding:36px!important}@media(max-width:720px){.file-actions form{width:100%}.file-actions input[type=file],.mkdir-form input{flex:1;min-width:0}}
`;
