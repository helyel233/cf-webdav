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
const ADMIN_ACCOUNTS_KEY = "config:admin-accounts";
const WEBDAV_ACCOUNTS_KEY = "config:webdav-accounts";
const SESSION_PREFIX = "session:";
const LOG_PREFIX = "log:";
const TRASH_PREFIX = "trash:";
const LOCK_PREFIX = "davlock:";
const LOCK_DEFAULT_TIMEOUT = 600;
const LOCK_MAX_TIMEOUT = 3600;
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
      await logAccess(env, { timestamp: new Date().toISOString(), method: request.method, path: pathname, status: 429, clientIp, userAgent, user: username }, startTime);
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
      await logAccess(env, { timestamp: new Date().toISOString(), method: request.method, path: pathname, status: 400, clientIp, userAgent, user: username }, startTime);
      return textResponse("Bad Request", 400);
    }
    let response: Response;
    try {
      switch (request.method) {
        case "PROPFIND": response = await propfind(request, scopedEnv, path, webdavAccount, env); break;
        case "GET": response = await getObject(scopedEnv, path, false, request); break;
        case "HEAD": response = await getObject(scopedEnv, path, true, request); break;
        case "PUT": response = await putObject(request, scopedEnv, path, webdavAccount, env); break;
        case "DELETE": response = await deletePath(scopedEnv, path, request); break;
        case "MKCOL": response = await makeCollection(scopedEnv, path, request); break;
        case "COPY": response = await copyOrMove(request, scopedEnv, path, false, webdavAccount, env); break;
        case "MOVE": response = await copyOrMove(request, scopedEnv, path, true, webdavAccount, env); break;
        case "LOCK": response = await lockResource(request, scopedEnv, path, username, webdavAccount); break;
        case "UNLOCK": response = await unlockResource(request, scopedEnv, path); break;
        default:
          response = textResponse("Method Not Allowed", 405, { Allow: METHODS.join(", ") });
      }
    } catch (error) {
      console.error("WebDAV request failed", { method: request.method, path, error });
      await logAccess(env, { timestamp: new Date().toISOString(), method: request.method, path, status: 500, clientIp, userAgent, user: username }, startTime);
      return textResponse("Internal Server Error", 500);
    }
    await logAccess(env, { timestamp: new Date().toISOString(), method: request.method, path, status: response.status, clientIp, userAgent, bytesSent: parseInt(response.headers.get("Content-Length") || "0"), user: username }, startTime);
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
  // 新增：用户级修改密码页面（需校验当前密码，仅普通用户可用）
  if (request.method === "GET" && view === "change-password") {
    return adminChangePasswordPage();
  }
  if (request.method === "POST" && (isRoot || url.pathname === "/__admin") && view === "change-password") {
    const form = await request.formData();
    if (String(form.get("action") || "") === "change-own-password") {
      const currentPassword = String(form.get("currentPassword") || "");
      const newPassword = String(form.get("newPassword") || "");
      const confirmPassword = String(form.get("confirmPassword") || "");
      if (!sessionAccount || !(await verifyPassword(currentPassword, sessionAccount.passwordHash, sessionAccount.salt))) return adminChangePasswordPage("", "当前密码不正确");
      if (newPassword.length < 8) return adminChangePasswordPage("", "新密码至少需要 8 位");
      if (newPassword !== confirmPassword) return adminChangePasswordPage("", "两次输入的新密码不一致");
      if (newPassword === currentPassword) return adminChangePasswordPage("", "新密码不能与当前密码相同");
      const salt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
      const accountsForPassword = await getAdminAccounts(env);
      accountsForPassword[sessionUser_] = { ...sessionAccount, username: sessionUser_, salt, passwordHash: await hashPassword(newPassword, salt) };
      await env.WEBDAV_KV.put(ADMIN_ACCOUNTS_KEY, JSON.stringify(accountsForPassword));
      return adminChangePasswordPage("密码已更新，请牢记新密码");
    }
  }
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
      return adminFilesAction(request, env, form, sessionUser_, selected.username, selected);
    }
    if (view === "trash" && ["restore", "purge", "empty"].includes(action)) {
      const selected = webdavAccounts[String(form.get("accountUsername") || url.searchParams.get("account") || "")];
      if (!selected || selected.owner !== adminUsername) return textResponse("请选择有权访问的 WebDAV 账户", 403);
      const scopedEnv = createScopedEnv(env, storageScope(selected));
      const clientIp = request.headers.get("CF-Connecting-IP") || "unknown";
      const userAgent = request.headers.get("User-Agent") || "";
      // 回收站操作统一记录访问日志：恢复记为 PUT、永久删除/清空记为 DELETE
      const logOperation = (method: string, operationPath: string) => logAccess(env, { method, path: operationPath, status: 200, clientIp, userAgent, user: adminUsername }, Date.now());
      if (action === "empty") {
        await emptyTrash(scopedEnv);
        await logOperation("DELETE", "__trash/*");
      } else if (action === "purge") {
        const paths = form.getAll("paths").map(String).filter(Boolean);
        for (const trashPath of paths) await purgeFromTrash(scopedEnv, trashPath);
        for (const trashPath of paths) await logOperation("DELETE", trashPath);
      } else if (action === "restore") {
        const paths = form.getAll("paths").map(String).filter(Boolean);
        const restoredPaths = paths.length ? paths : [String(form.get("path") || "")].filter(Boolean);
        for (const trashPath of restoredPaths) await restoreFromTrash(scopedEnv, trashPath);
        for (const trashPath of restoredPaths) await logOperation("PUT", trashPath);
      }
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
  // 新增：校验新建 WebDAV 账户的 UUID 是否重复
  if (url.searchParams.get("api") === "check-uuid" && request.method === "GET") {
    const uuid = String(url.searchParams.get("uuid") || "").trim();
    if (!/^\d{6}$/.test(uuid)) return new Response(JSON.stringify({ ok: false, available: false, message: "UUID 必须是 6 位数字" }), { headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
    const allAccountsForUuid = await getWebdavAccounts(env);
    const uuidDuplicated = Object.values(allAccountsForUuid).some((account) => account.uuid === uuid);
    return new Response(JSON.stringify({ ok: true, available: !uuidDuplicated, message: uuidDuplicated ? "该 UUID 已被占用，请换一个" : "该 UUID 可用" }), { headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
  }
  const ownedAccountList = Object.values(await getWebdavAccounts(env)).filter((account) => account.owner === sessionUser_);
  const requestedAccount = url.searchParams.get("account") || (view === "account" || view === "files" || view === "logs" || view === "trash" ? ownedAccountList[0]?.username : "");
  const selectedAccount = (await getWebdavAccounts(env))[requestedAccount || ""];
  if (selectedAccount && selectedAccount.owner !== sessionUser_) return textResponse("Forbidden", 403);
  if (view === "account") return selectedAccount ? adminAccountPage(request, env, selectedAccount) : adminPage(request, env, "请先选择 WebDAV 账户");
  if (view === "logs") return adminLogsPage(env, sessionUser_);
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
    return superAdminPage(env, "管理员无权为用户创建 WebDAV 账户");
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

// 公共页面骨架辅助：统一 topbar 与 page-heading 模板，避免逐页重复
function topbarHtml(title: string, right: string): string {
  return `<header class="topbar"><div class="topbar-inner"><div class="brand"><span class="brand-mark small">WD</span><span>${escapeHtml(title)}</span></div><div class="topbar-right">${right}</div></div></header>`;
}

function pageHeadingHtml(eyebrow: string, title: string, subtitle = "", extra = ""): string {
  return `<section class="page-heading"><div><p class="eyebrow">${escapeHtml(eyebrow)}</p><h1>${escapeHtml(title)}</h1>${subtitle ? `<p class="muted">${escapeHtml(subtitle)}</p>` : ""}</div>${extra}</section>`;
}

async function superAdminPage(env: Env, message: string): Promise<Response> {
  const accounts = await getAdminAccounts(env);
  const users = Object.values(accounts).filter((account) => account.role !== "admin");
  const webdavAccounts = await getWebdavAccounts(env);
  // 汇总所有用户名下 WebDAV 账户的存储用量（GB）
  const owners = [...new Set(Object.values(webdavAccounts).map((account) => account.owner))];
  const ownerUsages = await Promise.all(owners.map((owner) => getUserStorageUsage(env, owner)));
  const usedGb = (ownerUsages.reduce((total, size) => total + size, 0) / 1024 ** 3).toFixed(2);
  const usageByOwner = new Map(owners.map((owner, index) => [owner, (ownerUsages[index] / 1024 ** 3).toFixed(2)]));
  const userRows = users.map((user) => {
    const ownedAccounts = Object.values(webdavAccounts).filter((account) => account.owner === user.username);
    const accountRows = ownedAccounts.map((account) => `<div class="account-row"><span>${escapeHtml(account.username)} · ${escapeHtml(account.uuid || "------")}</span><form method="post" style="display:inline" onsubmit="return confirm('确定删除此 WebDAV 账户及其全部文件吗？')"><input type="hidden" name="action" value="delete-webdav-admin"><input type="hidden" name="serviceUsername" value="${escapeHtml(account.username)}"><button class="danger-button compact-button" type="submit">删除</button></form></div>`).join("");
    return `<tr class="user-row" data-search="${escapeHtml(`${user.username} ${ownedAccounts.map((account) => account.username).join(" ")}`.toLowerCase())}"><th scope="row">${escapeHtml(user.username)}</th><td><div class="account-list">${accountRows || '<span class="muted">暂无 WebDAV 账户</span>'}</div></td><td>${usageByOwner.get(user.username) ?? "0.00"}</td><td><form method="post" onsubmit="return confirm('确定删除该用户及其全部 WebDAV 账户和文件吗？此操作不可恢复！')"><input type="hidden" name="action" value="delete-user"><input type="hidden" name="userUsername" value="${escapeHtml(user.username)}"><button class="danger-button" type="submit">删除用户</button></form></td></tr>`;
  }).join("");
  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>超级管理员</title><style>${ADMIN_CSS}${USER_TABLE_CSS}${FILES_CSS}</style><body>${topbarHtml("超级管理员", `<span class="status-dot">系统管理员</span><a class="text-link inverse" href="/?action=logout">退出当前账户</a>`)}<main class="dashboard">${pageHeadingHtml("ADMINISTRATION", "用户与账户管理", "管理员只能管理用户和 WebDAV 账户信息，无法查看任何文件内容。", `<div class="storage-badge"><span>当前所有用户已用容量（GB）：<strong>${usedGb}</strong></span></div>`)}${message ? `<div class="notice success">${escapeHtml(message)}</div>` : ""}<section class="content-grid"><article class="config-card"><div class="card-heading"><div><p class="eyebrow">NEW USER</p><h2>创建用户</h2></div><span class="icon-badge">01</span></div><form method="post" class="config-form"><input type="hidden" name="action" value="create-user"><label>用户账户<input name="userUsername" autocomplete="username" required></label><label>密码<input name="userPassword" type="password" autocomplete="new-password" minlength="8" required></label><label>确认密码<input name="userPasswordConfirm" type="password" autocomplete="new-password" minlength="8" required></label><button class="primary-button" type="submit">创建用户</button></form></article></section><section class="config-card user-table-card"><div class="card-heading"><div><p class="eyebrow">USER DIRECTORY</p><h2>用户列表</h2></div><span class="icon-badge">${users.length}</span></div><label class="filter-label" for="user-filter">筛选用户或 WebDAV 账户<input id="user-filter" type="search" placeholder="输入名称筛选" oninput="filterUsers(this.value)"></label><div class="table-scroll"><table class="user-table"><thead><tr><th scope="col">用户</th><th scope="col">WebDAV 账户</th><th scope="col">当前已使用存储空间（GB）</th><th scope="col">操作</th></tr></thead><tbody id="user-table-body">${userRows || '<tr><td colspan="4" class="muted empty-cell">暂无用户。</td></tr>'}</tbody></table></div><p id="user-filter-empty" class="muted empty-cell" hidden>没有匹配的用户。</p></section></main><script>function filterUsers(value){const query=value.trim().toLowerCase();let visible=0;document.querySelectorAll('.user-row').forEach((row)=>{const matched=!query||row.dataset.search.includes(query);row.hidden=!matched;if(matched)visible+=1;});document.getElementById('user-filter-empty').hidden=visible>0||!query;}</script></body></html>`);
}

function adminLandingPage(request: Request, adminUsername: string, accounts: WebdavAccount[], nextUuid: string, message: string, usedStorage: number): Response {
  const usedGb = (usedStorage / 1024 ** 3).toFixed(2);
  const totalGb = String(USER_STORAGE_LIMIT / 1024 ** 3);
  const accountCards = accounts.map((account) => `<a class="config-card account-card account-choice" href="/?view=account&account=${encodeURIComponent(account.username)}"><div class="card-heading"><div><p class="eyebrow">WEBDAV ACCOUNT</p><h2>${escapeHtml(account.username)}</h2></div><span class="icon-badge">${escapeHtml(account.uuid || "------")}</span></div><p class="muted">账户链接：${escapeHtml(webdavAccountUrl(request, account))}</p><span class="primary-button inline-button">进入账户管理</span></a>`).join("");
  const createForm = accounts.length < 2 ? `<article class="config-card account-card"><div class="card-heading"><div><p class="eyebrow">NEW ACCOUNT</p><h2>新建 WebDAV 账户</h2></div><span class="icon-badge">+</span></div><p class="muted">当前管理员最多拥有 2 个 WebDAV 账户。</p><form method="post" action="/?view=home" class="config-form"><input type="hidden" name="action" value="create-webdav"><label>账户<input name="serviceUsername" autocomplete="username" required></label><label>密码<input name="servicePassword" type="password" autocomplete="new-password" minlength="8" required></label><label>6 位 UUID<div class="uuid-row"><input name="accountUuid" value="${escapeHtml(nextUuid)}" inputmode="numeric" pattern="[0-9]{6}" minlength="6" maxlength="6" required><button type="button" class="secondary-button uuid-check-btn" onclick="return checkUuidAvailability(this)">检查 UUID</button></div><span id="uuid-check-result" class="uuid-result"></span></label><button class="primary-button" type="submit">创建 WebDAV 账户</button></form></article>` : "";
  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>用户管理</title><style>${ADMIN_CSS}${FILES_CSS}</style><body>${topbarHtml("用户管理", `<span class="status-dot">管理员：${escapeHtml(adminUsername)}</span><a class="text-link inverse" href="/?view=change-password">修改密码</a><a class="text-link inverse" href="/?action=logout">退出登录</a>`)}<main class="dashboard">${pageHeadingHtml("USER MANAGEMENT", "用户管理", "进入账户后只能管理该账户自己的文件。", `<div class="storage-badge"><span>当前已用容量（GB）：<strong>${usedGb}</strong></span><span>总容量（GB）：<strong>${totalGb}</strong></span></div>`)}${message ? `<div class="notice success">${escapeHtml(message)}</div>` : ""}<section class="content-grid">${accountCards}${createForm}</section><p class="muted">${accounts.length}/2 个 WebDAV 账户</p></main><script>async function checkUuidAvailability(btn){var row=btn.closest('.uuid-row');var input=row.querySelector('input');var result=document.getElementById('uuid-check-result');var uuid=input.value.trim();result.className='uuid-result';result.textContent='检查中…';if(!/^[0-9]{6}$/.test(uuid)){result.textContent='UUID 必须是 6 位数字';result.className='uuid-result error';return false;}try{var res=await fetch('/?api=check-uuid&uuid='+encodeURIComponent(uuid));var data=await res.json();result.textContent=data.message;result.className='uuid-result '+(data.ok&&data.available?'success':'error');}catch(e){result.textContent='检查失败，请重试';result.className='uuid-result error';}return false;}</script></body></html>`);
}

async function adminAccountPage(request: Request, env: Env, account: WebdavAccount): Promise<Response> {
  const scopedEnv = createScopedEnv(env, storageScope(account));
  const fileCount = (await listAllObjects(scopedEnv, "")).filter((item) => !item.key.startsWith("__trash/")).length;
  const accountUrl = webdavAccountUrl(request, account);
  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(account.username)} - WebDAV 管理</title><style>${ADMIN_CSS}${FILES_CSS}</style><body>${topbarHtml("账户管理", `<a class="text-link inverse" href="/">返回账户选择</a><a class="text-link inverse" href="/?action=logout">退出登录</a>`)}<main class="dashboard">${pageHeadingHtml("WEBDAV ACCOUNT", account.username, `当前账户包含 ${fileCount} 个文件，仅显示此账户的数据。`)}<section class="content-grid"><article class="config-card wide-card"><div class="card-heading"><div><p class="eyebrow">CONNECTION</p><h2>账户连接信息</h2></div><span class="icon-badge">${escapeHtml(account.uuid || "------")}</span></div><p class="muted">服务链接：${escapeHtml(accountUrl)}</p><form method="post" action="/?view=account&account=${encodeURIComponent(account.username)}" class="config-form"><input type="hidden" name="action" value="save-service"><input type="hidden" name="accountUsername" value="${escapeHtml(account.username)}"><label>账户<input name="serviceUsername" value="${escapeHtml(account.username)}" autocomplete="username" required></label><label>密码<input name="servicePassword" type="password" autocomplete="new-password" minlength="8" placeholder="输入新密码" required></label><label>6 位 UUID<input name="accountUuid" value="${escapeHtml(account.uuid || "")}" inputmode="numeric" pattern="[0-9]{6}" minlength="6" maxlength="6" required></label><button class="primary-button" type="submit">保存账户信息</button></form><a class="secondary-button inline-button" href="/?view=files&account=${encodeURIComponent(account.username)}">打开此账户文件</a></article></section></main></body></html>`);
}

async function adminAccountsPage(request: Request, env: Env, adminUsername: string): Promise<Response> {
  const accounts = Object.values(await getWebdavAccounts(env)).filter((account) => account.owner === adminUsername);
  const rows = accounts.map((account) => `<article class="config-card account-card"><div class="card-heading"><div><p class="eyebrow">WEBDAV ACCOUNT</p><h2>${escapeHtml(account.username)}</h2></div><span class="icon-badge">${escapeHtml(account.username.slice(0, 2).toUpperCase())}</span></div><p class="muted">服务链接：${escapeHtml(account.url)}</p><form method="post" action="/?view=accounts" class="config-form"><input type="hidden" name="action" value="save-service"><input type="hidden" name="accountUsername" value="${escapeHtml(account.username)}"><label>账户<input name="serviceUsername" value="${escapeHtml(account.username)}" required></label><label>密码<input name="servicePassword" type="password" minlength="8" placeholder="输入新密码" required></label><label>服务链接<input name="url" type="url" value="${escapeHtml(account.url)}" required></label><button class="primary-button" type="submit">保存 WebDAV 账户</button><a class="secondary-button inline-button" href="/?view=files&account=${encodeURIComponent(account.username)}">打开此账户文件</a></form></article>`).join("");
  const createForm = accounts.length < 2 ? `<article class="config-card account-card"><div class="card-heading"><div><p class="eyebrow">NEW ACCOUNT</p><h2>创建 WebDAV 账户</h2></div><span class="icon-badge">+</span></div><p class="muted">每个管理员最多拥有 2 个 WebDAV 账户。</p><form method="post" action="/?view=accounts" class="config-form"><input type="hidden" name="action" value="create-webdav"><label>账户<input name="serviceUsername" required></label><label>密码<input name="servicePassword" type="password" minlength="8" required></label><button class="primary-button" type="submit">创建账户</button></form></article>` : "";
  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>账号管理</title><style>${ADMIN_CSS}${FILES_CSS}</style><body>${topbarHtml("账号管理", `<a class="text-link inverse" href="/">返回管理中心</a><a class="text-link inverse" href="/?action=logout">退出登录</a>`)}<main class="dashboard">${pageHeadingHtml("ACCOUNT MANAGEMENT", "账号管理", `当前管理员：${adminUsername}。每个管理员最多拥有两个 WebDAV 账户。`)}<section class="content-grid">${rows}${createForm}</section><section class="config-card admin-account-card"><div class="card-heading"><div><p class="eyebrow">NEW ADMIN</p><h2>创建管理员账户</h2></div></div><form method="post" action="/?view=accounts" class="config-form"><input type="hidden" name="action" value="create-admin"><label>管理员账户<input name="adminUsername" required></label><label>管理员密码<input name="adminPassword" type="password" minlength="8" required></label><button class="primary-button" type="submit">创建管理员</button></form></section></main></body></html>`);
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

async function adminFilesAction(request: Request, env: Env, form: FormData, username: string, accountUsername: string, account: WebdavAccount): Promise<Response> {
  const scopedEnv = createScopedEnv(env, storageScope(account));
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
      const quotaResponse = await ensureStorageCapacity(env, scopedEnv, account, path, file.size);
      if (quotaResponse) return quotaResponse;
      const existingObject = await scopedEnv.WEBDAV_BUCKET.head(path);
      await scopedEnv.WEBDAV_BUCKET.put(path, file.stream(), { httpMetadata: { contentType: file.type || "application/octet-stream" } });
      await scopedEnv.WEBDAV_KV.put(metaKey(path), JSON.stringify({ type: "file", size: file.size, contentType: file.type || "application/octet-stream", updatedAt: new Date().toISOString() }));
      await adjustAccountStorageUsage(scopedEnv, file.size - (existingObject?.size ?? 0));
    } else if (action === "mkdir") {
      const name = String(form.get("name") || "");
      operationPath = adminPath(`${currentPath ? `${currentPath}/` : ""}${name}`);
      operationMethod = "MKCOL";
      const response = await makeCollection(scopedEnv, operationPath);
      responseStatus = response.status;
    } else if (action === "delete") {
      operationPath = adminPath(String(form.get("path") || ""));
      operationMethod = "DELETE";
      const response = await deletePath(scopedEnv, operationPath);
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
    return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>文件管理</title><style>${ADMIN_CSS}${FILES_CSS}</style><body>${topbarHtml("文件管理", `<a class="text-link inverse" href="/?view=account&account=${encodeURIComponent(accountUsername)}">返回账户管理</a><a class="text-link inverse" href="/">返回账户选择</a>`)}<main class="dashboard">${pageHeadingHtml("FILE MANAGER", "文件管理", `账户：${accountUsername}　当前位置：/${currentPath}`, `<a class="secondary-button" href="/?view=trash&account=${encodeURIComponent(accountUsername)}">回收站</a>`)}<section class="file-actions"><article class="file-action-card"><div class="file-action-heading"><strong>上传文件</strong><span>选择一个文件上传到当前目录</span></div><form method="post" action="/?view=files" enctype="multipart/form-data"><input type="hidden" name="action" value="upload"><input type="hidden" name="accountUsername" value="${escapeHtml(accountUsername)}"><input type="hidden" name="currentPath" value="${escapeHtml(currentPath)}"><input type="file" name="file" required><button class="primary-button" type="submit">上传文件</button></form></article><article class="file-action-card"><div class="file-action-heading"><strong>新建目录</strong><span>在当前目录创建一个文件夹</span></div><form method="post" action="/?view=files" class="mkdir-form"><input type="hidden" name="action" value="mkdir"><input type="hidden" name="accountUsername" value="${escapeHtml(accountUsername)}"><input type="hidden" name="currentPath" value="${escapeHtml(currentPath)}"><input name="name" placeholder="目录名称" required><button class="secondary-button" type="submit">新建目录</button></form></article></section><section class="file-table-wrap"><table><thead><tr><th>名称</th><th>类型</th><th>大小</th><th>上传时间</th><th>操作</th></tr></thead><tbody>${rows || '<tr><td colspan="5" class="empty-state">当前目录为空</td></tr>'}</tbody></table></section></main></body></html>`);
}

function adminLoginPage(error = ""): Response {
  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>WebDAV 管理登录</title><style>${ADMIN_CSS}</style><main class="login-shell"><section class="login-panel"><div class="brand-mark">WD</div><p class="eyebrow">CLOUD STORAGE</p><h1>WebDAV 管理</h1><p class="muted">登录后管理账号、访问日志和文件。</p>${error ? `<p class="notice success">${escapeXml(error)}</p>` : ""}<form method="post" action="/__admin/login"><label>用户名<input name="username" autocomplete="username" required></label><label>密码<input name="password" type="password" autocomplete="current-password" required></label><button class="primary-button" type="submit">登录管理后台</button></form><a class="secondary-button register-button" href="/__admin/register">注册新用户</a></section></main>`);
}

// 新增：用户级修改密码页面（需校验当前密码）
function adminChangePasswordPage(message = "", error = ""): Response {
  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>修改密码</title><style>${ADMIN_CSS}</style><body>${topbarHtml("修改密码", `<a class="text-link inverse" href="/">返回首页</a>`)}<main class="login-shell"><section class="login-panel"><div class="brand-mark">WD</div><p class="eyebrow">ACCOUNT SECURITY</p><h1>修改密码</h1><p class="muted">为保障账户安全，修改密码前需要先验证当前密码。</p>${message ? `<p class="notice success">${escapeXml(message)}</p>` : ""}${error ? `<p class="error">${escapeXml(error)}</p>` : ""}<form method="post" action="/?view=change-password"><input type="hidden" name="action" value="change-own-password"><label>当前密码<input name="currentPassword" type="password" autocomplete="current-password" required></label><label>新密码<input name="newPassword" type="password" autocomplete="new-password" minlength="8" placeholder="至少 8 位" required></label><label>确认新密码<input name="confirmPassword" type="password" autocomplete="new-password" minlength="8" required></label><button class="primary-button" type="submit">保存新密码</button></form></section></main></body></html>`);
}

function adminRegisterPage(error = ""): Response {
  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>注册新用户</title><style>${ADMIN_CSS}</style><main class="login-shell"><section class="login-panel"><div class="brand-mark">WD</div><p class="eyebrow">NEW USER</p><h1>注册新用户</h1><p class="muted">创建用于登录管理界面的普通用户账户。</p>${error ? `<p class="error">${escapeXml(error)}</p>` : ""}<form method="post" action="/__admin/register"><label>用户名<input name="username" autocomplete="username" required></label><label>密码<input name="password" type="password" autocomplete="new-password" minlength="8" required></label><label>确认密码<input name="confirmPassword" type="password" autocomplete="new-password" minlength="8" required></label><button class="primary-button" type="submit">注册新用户</button></form><a class="secondary-button inline-button" href="/">返回登录</a></section></main>`);
}

async function adminPage(request: Request, env: Env, message = ""): Promise<Response> {
  const adminUsername = await sessionUser(request, env) || DEFAULT_USERNAME;
  const allAccounts = await getWebdavAccounts(env);
  const ownedAccounts = Object.values(allAccounts).filter((account) => account.owner === adminUsername);
  const usedStorage = await getUserStorageUsage(env, adminUsername);
  return adminLandingPage(request, adminUsername, ownedAccounts, createAccountUuid(new Set(Object.values(allAccounts).map((account) => account.uuid).filter((uuid): uuid is string => Boolean(uuid)))), message, usedStorage);
}

const ADMIN_CSS = `:root{font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#17212b;background:#eef2f1}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:linear-gradient(135deg,#f6f8f5 0%,#e8efed 100%)}a{color:inherit;text-decoration:none}.topbar{background:#183b3f;color:#f4f8f5}.topbar-inner{max-width:1120px;margin:auto;padding:18px 28px;display:flex;align-items:center;justify-content:space-between}.brand{display:flex;align-items:center;gap:12px;font-weight:700;letter-spacing:.01em}.brand-mark{display:grid;place-items:center;width:42px;height:42px;background:#e8b35a;color:#183b3f;font-size:13px;font-weight:900;letter-spacing:-.06em}.brand-mark.small{width:30px;height:30px;font-size:10px}.status-dot{font-size:13px;color:#c4e3cf}.status-dot:before{content:"";display:inline-block;width:7px;height:7px;margin-right:7px;border-radius:50%;background:#6bc58d}.dashboard{max-width:1120px;margin:0 auto;padding:54px 28px 72px}.page-heading{display:flex;align-items:flex-end;justify-content:space-between;gap:24px;margin-bottom:32px}.eyebrow{margin:0 0 9px;color:#8a6940;font-size:11px;font-weight:800;letter-spacing:.16em}.page-heading h1{margin:0;font-size:clamp(30px,5vw,48px);letter-spacing:-.04em}.muted{color:#667578;line-height:1.6}.text-link{color:#32656a;font-size:14px;font-weight:700}.inverse{color:#f4f8f5}.summary-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:22px}.summary-card,.config-card{background:rgba(255,255,255,.82);border:1px solid #d7e0dc;box-shadow:0 12px 30px rgba(31,61,57,.06)}.summary-card{min-height:132px;padding:22px}.summary-card.accent{border-top:3px solid #d79b41}.card-label{display:block;margin-bottom:20px;color:#71807e;font-size:12px;font-weight:700}.summary-card strong{display:block;font-size:22px;letter-spacing:-.02em}.card-meta{display:block;margin-top:8px;color:#84918f;font-size:13px}.content-grid{display:grid;grid-template-columns:1fr 1fr;gap:22px}.config-card{padding:28px}.card-heading{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:8px}.card-heading h2{margin:0;font-size:22px;letter-spacing:-.03em}.icon-badge{display:grid;place-items:center;width:32px;height:32px;background:#eef3ee;color:#8a6940;font-size:11px;font-weight:800}.config-form{margin-top:25px}.config-form label{display:block;margin:17px 0 6px;font-size:13px;font-weight:700}.config-form input{display:block;width:100%;margin-top:7px;padding:13px 14px;border:1px solid #cbd7d3;border-radius:2px;background:#fbfcfa;color:#17212b;font:inherit;outline:none}.config-form input:focus{border-color:#4c8581;box-shadow:0 0 0 3px rgba(76,133,129,.14)}.primary-button{margin-top:20px;padding:12px 18px;border:0;border-radius:2px;background:#d79b41;color:#183b3f;font:inherit;font-weight:800;cursor:pointer}.primary-button:hover{background:#e5ae59}.tool-list{margin-top:17px;border-top:1px solid #e0e7e3}.tool-row{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:20px 0;border-bottom:1px solid #e0e7e3}.tool-row strong,.tool-row small{display:block}.tool-row small{margin-top:5px;color:#71807e;font-size:13px}.arrow{color:#397277;font-size:22px}.info-strip{display:flex;align-items:center;gap:11px;margin-top:22px;padding:16px 19px;background:#e7f0eb;color:#45625d;font-size:13px;line-height:1.5}.info-icon{display:grid;place-items:center;flex:none;width:20px;height:20px;border:1px solid #70968b;border-radius:50%;font-size:12px}.notice{margin:-12px 0 22px;padding:13px 16px;background:#e7f4eb;border-left:3px solid #3d9368}.success{color:#176b48}.error{margin:18px 0;padding:11px 13px;background:#fff0ee;color:#a43f35}.login-shell{display:grid;place-items:center;min-height:100vh;padding:24px}.login-panel{width:min(100%,420px);padding:42px;background:rgba(255,255,255,.9);border:1px solid #d7e0dc;box-shadow:0 18px 50px rgba(31,61,57,.12)}.login-panel h1{margin:0;font-size:32px;letter-spacing:-.04em}.login-panel .muted{margin:10px 0 28px}.login-panel label{display:block;margin:17px 0 6px;font-size:13px;font-weight:700}.login-panel input{display:block;width:100%;margin-top:7px;padding:13px 14px;border:1px solid #cbd7d3;border-radius:2px;background:#fbfcfa;color:#17212b;font:inherit}.login-panel .primary-button{width:100%;margin-top:25px}@media(max-width:720px){.topbar-inner,.dashboard{padding-left:20px;padding-right:20px}.dashboard{padding-top:36px}.page-heading{align-items:flex-start;flex-direction:column}.summary-grid,.content-grid{grid-template-columns:1fr}.config-card{padding:22px}}`;
const USER_TABLE_CSS = `.user-table-card{grid-column:1/-1;margin-top:22px}.filter-label{display:block;max-width:360px;margin:22px 0 16px;font-size:13px;font-weight:700}.filter-label input{display:block;width:100%;margin-top:7px;padding:11px 13px;border:1px solid #cbd7d3;border-radius:2px;background:#fff;color:#17212b;font:inherit}.table-scroll{overflow-x:auto}.user-table{width:100%;min-width:840px;border-collapse:collapse}.user-table th,.user-table td{padding:15px 12px;border-bottom:1px solid #dce5e1;text-align:left;vertical-align:top;font-size:13px}.user-table th{color:#66807a;font-size:11px;letter-spacing:.12em}.user-table tbody th{color:#17212b;font-size:14px;letter-spacing:0}.user-table th:last-child,.user-table td:last-child{width:1%;white-space:nowrap}.account-list{min-width:190px}.account-row{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:8px}.account-row:last-child{margin-bottom:0}.table-form{display:grid;grid-template-columns:repeat(3,minmax(90px,1fr));gap:7px;min-width:330px}.table-form input{width:100%;padding:9px 10px;border:1px solid #cbd7d3;border-radius:2px;background:#fff;color:#17212b;font:inherit}.table-form .primary-button{grid-column:1/-1}.compact-button{padding:8px 11px;font-size:12px}`;

const UI_POLISH_CSS = `.login-shell{background:radial-gradient(circle at 15% 15%,rgba(232,179,90,.25),transparent 32%),linear-gradient(145deg,#173b3f,#285d5d);position:relative;overflow:hidden}.login-shell:before{content:"";position:absolute;width:420px;height:420px;border:1px solid rgba(255,255,255,.14);border-radius:50%;transform:translate(55%,30%)}.login-panel{position:relative;background:rgba(255,255,255,.96);border:1px solid rgba(255,255,255,.8);box-shadow:0 24px 70px rgba(9,35,35,.28);border-radius:8px}.login-panel h1{font-size:34px;letter-spacing:-.04em}.login-panel form{margin-top:26px}.login-panel label{display:block;margin:16px 0 6px;font-size:13px;font-weight:700}.login-panel input{display:block;width:100%;margin-top:7px;padding:13px 14px;border:1px solid #cbd7d3;border-radius:4px;background:#fff;color:#17212b;font:inherit}.login-panel input:focus,.filter-label input:focus,.table-form input:focus{outline:3px solid rgba(169,209,192,.55);outline-offset:1px}.login-panel .primary-button{width:100%;margin-top:14px}.register-button{display:flex;margin-top:12px;text-align:center}.config-card,.summary-card{border-radius:7px;transition:transform .2s ease,box-shadow .2s ease}.config-card:hover,.summary-card:hover{box-shadow:0 18px 38px rgba(31,61,57,.1)}.primary-button,.secondary-button,.danger-button{border-radius:4px;transition:transform .15s ease,filter .15s ease}.primary-button:hover,.secondary-button:hover,.danger-button:hover{filter:brightness(.97);transform:translateY(-1px)}.file-table-wrap{border-radius:7px;box-shadow:0 12px 30px rgba(31,61,57,.06)}.file-table-wrap th{background:#eaf2ee}.page-heading .secondary-button{margin:0}.notice{border-radius:0 4px 4px 0}.topbar{box-shadow:0 3px 16px rgba(10,42,42,.16)}@media(max-width:760px){.page-heading .secondary-button{margin-top:4px}.login-panel{padding:28px 22px}.login-panel h1{font-size:30px}.config-card,.summary-card{border-radius:5px}}`;

function htmlResponse(body: string): Response {
  const withLogout = body.replaceAll("返回账户选择", "返回用户管理").replace('<span class="status-dot">服务在线</span>', '<span class="status-dot">服务在线</span><a class="text-link inverse" style="margin-left:16px" href="/?action=logout">退出当前账户</a>');
  const accountFileLink = withLogout.match(/<a class="secondary-button inline-button" href="\/\?view=files&account=([^"]+)">打开此账户文件<\/a>/);
  const withAccountTools = accountFileLink ? withLogout.replace(accountFileLink[0], `<div class="account-actions">${accountFileLink[0]}<a class="secondary-button inline-button" href="/?view=logs&account=${accountFileLink[1]}">访问日志</a><a class="secondary-button inline-button" href="/?view=trash&account=${accountFileLink[1]}">回收站</a><form method="post" action="/?view=account" class="delete-account-form" onsubmit="return confirm('确定要删除此 WebDAV 账户及其全部文件吗？此操作不可恢复！')"><input type="hidden" name="action" value="delete-webdav"><input type="hidden" name="accountUsername" value="${escapeHtml(decodeURIComponent(accountFileLink[1]))}"><button class="danger-button" type="submit">删除整个账户</button></form></div>`) : withLogout;
  // 注入 UI_POLISH_CSS 和 DARK_MODE_CSS
  let polishedBody = withAccountTools.replace("</style>", `${UI_POLISH_CSS}${DARK_MODE_CSS}${TABLE_POLISH_CSS}${FORM_LAYOUT_CSS}${TOPBAR_LAYOUT_CSS}${LOGIN_DARK_CSS}${FILE_ACTION_ALIGNMENT_CSS}${THEME_TOGGLE_CSS}</style>`);
  // 在 topbar 或 login-shell 中注入暗黑模式切换按钮
  const themeToggle = '<button class="theme-toggle" onclick="toggleTheme()" title="\u5207\u6362\u660e\u6697\u6a21\u5f0f" aria-label="\u5207\u6362\u660e\u6697\u6a21\u5f0f">\u{1F319}</button>';
  if (polishedBody.includes('</div></header>')) {
    polishedBody = polishedBody.replace('</div></header>', `${themeToggle}</div></header>`);
  } else if (polishedBody.includes('<main class="login-shell">')) {
    polishedBody = polishedBody.replace('<main class="login-shell">', `<main class="login-shell">${themeToggle}`);
  }
  // 主题初始化片段置于 <head>，避免深色用户首屏闪烁（FOUC）；末尾脚本仅负责同步按钮图标
  polishedBody = polishedBody.replace("</title>", `</title>${THEME_INIT_SCRIPT}`);
  polishedBody = polishedBody.replace("</main>", `${THEME_SCRIPT}</main>`);
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
    headers: { Allow: METHODS.join(", "), DAV: "1, 2", "MS-Author-Via": "DAV" },
  });
}

// 新增：ETag 匹配比较（支持 * 与逗号分隔列表，忽略引号与弱化前缀）
function etagMatches(headerValue: string, etag: string): boolean {
  const target = etag.replace(/^W\//, "").replace(/"/g, "");
  if (headerValue.trim() === "*") return true;
  return headerValue.split(",").map((candidate) => candidate.trim().replace(/^W\//, "").replace(/"/g, "")).some((candidate) => candidate === target);
}

// 新增：解析单个 Range 头（仅支持单区间，多区间或非法值回退为 200 全量）
function parseSingleRange(header: string | null, size: number): { start: number; end: number } | "invalid" | "unsatisfiable" | null {
  if (!header) return null;
  const match = /^bytes=(\d*)-(\d*)$/.exec(header.trim());
  if (!match || (match[1] === "" && match[2] === "")) return "invalid";
  let start: number;
  let end: number;
  if (match[1] === "") {
    const suffix = Number(match[2]);
    if (suffix === 0) return "unsatisfiable";
    start = Math.max(0, size - suffix);
    end = size - 1;
  } else {
    start = Number(match[1]);
    end = match[2] === "" ? size - 1 : Math.min(Number(match[2]), size - 1);
  }
  if (start >= size) return "unsatisfiable";
  if (start > end) return "invalid";
  return { start, end };
}

// 新增：If-Range 校验（ETag 或 HTTP 日期，秒级精度）
function ifRangeSatisfied(ifRange: string, etag: string, uploaded: Date): boolean {
  const value = ifRange.trim();
  if (value.startsWith("\"") || value.startsWith("W/")) return etagMatches(value, etag);
  const headerTime = new Date(value).getTime();
  return !Number.isNaN(headerTime) && Math.floor(headerTime / 1000) === Math.floor(uploaded.getTime() / 1000);
}

// 新增：GET/HEAD 读写条件评估（If-Match → 412，If-None-Match → 304）
function evaluateReadPrecondition(request: Request, etag: string): Response | null {
  const ifMatch = request.headers.get("If-Match");
  if (ifMatch && !etagMatches(ifMatch, etag)) return textResponse("Precondition Failed", 412);
  const ifNoneMatch = request.headers.get("If-None-Match");
  if (ifNoneMatch && etagMatches(ifNoneMatch, etag)) return new Response(null, { status: 304, headers: { ETag: etag } });
  return null;
}

// 新增：写操作（PUT/DELETE/COPY/MOVE）条件评估，资源不存在时 etag 传 null
function evaluateMutatingPrecondition(request: Request, etag: string | null): Response | null {
  const ifMatch = request.headers.get("If-Match");
  if (ifMatch && (!etag || !etagMatches(ifMatch, etag))) return textResponse("Precondition Failed", 412);
  const ifNoneMatch = request.headers.get("If-None-Match");
  if (ifNoneMatch && etag && etagMatches(ifNoneMatch, etag)) return textResponse("Precondition Failed", 412);
  return null;
}

async function getObject(env: Env, path: string, head: boolean, request: Request): Promise<Response> {
  if (!path) return textResponse("A directory cannot be downloaded", 405);
  const rangeHeader = request.headers.get("Range");
  const ifRange = request.headers.get("If-Range");
  const needsMetadata = Boolean(rangeHeader || ifRange || request.headers.get("If-Match") || request.headers.get("If-None-Match"));
  const fullObject = needsMetadata ? await env.WEBDAV_BUCKET.head(r2Key(path)) : null;
  if (needsMetadata && !fullObject) return textResponse("Not Found", 404);
  if (fullObject) {
    const failed = evaluateReadPrecondition(request, fullObject.httpEtag);
    if (failed) return failed;
  }
  let range: { start: number; end: number } | null = null;
  if (rangeHeader && fullObject) {
    const parsed = parseSingleRange(rangeHeader, fullObject.size);
    if (parsed === "unsatisfiable") return new Response(null, { status: 416, headers: { "Content-Range": `bytes */${fullObject.size}`, ETag: fullObject.httpEtag } });
    if (parsed && parsed !== "invalid") range = ifRange && !ifRangeSatisfied(ifRange, fullObject.httpEtag, fullObject.uploaded) ? null : parsed;
  }
  const object = range
    ? await env.WEBDAV_BUCKET.get(r2Key(path), { range: { offset: range.start, length: range.end - range.start + 1 } })
    : await env.WEBDAV_BUCKET.get(r2Key(path));
  if (!object) return textResponse("Not Found", 404);
  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("ETag", object.httpEtag);
  headers.set("Accept-Ranges", "bytes");
  headers.set("Content-Length", String(object.size));
  let status = 200;
  if (range && fullObject) {
    headers.set("Content-Range", `bytes ${range.start}-${range.start + object.size - 1}/${fullObject.size}`);
    status = 206;
  }
  return new Response(head ? null : object.body, { status, headers });
}

// 新增：RFC 4918 Class 2 锁机制（锁信息存 KV，过期情性清理）
interface LockInfo {
  token: string;
  owner: string;
  depth: "0" | "infinity";
  timeout: number;
  expiresAt: number;
  scope: "exclusive" | "shared";
}

function lockKey(path: string): string {
  return `${LOCK_PREFIX}${encodeURIComponent(path)}`;
}

// 同一路径可挂多把锁（shared 共存），KV 值为 LockInfo 数组，兼容旧的单锁格式
async function readLocks(env: Env, path: string): Promise<LockInfo[]> {
  const key = lockKey(path);
  const raw = await env.WEBDAV_KV.get(key, "json") as LockInfo[] | LockInfo | null;
  if (!raw) return [];
  const stored = Array.isArray(raw) ? raw : [raw];
  const active = stored.filter((lock) => lock.expiresAt >= Date.now());
  if (active.length !== stored.length) await writeLocks(env, path, active);
  return active;
}

async function writeLocks(env: Env, path: string, locks: LockInfo[]): Promise<void> {
  const key = lockKey(path);
  if (!locks.length) {
    await env.WEBDAV_KV.delete(key);
    return;
  }
  const ttl = Math.max(60, Math.ceil((Math.max(...locks.map((lock) => lock.expiresAt)) - Date.now()) / 1000));
  await env.WEBDAV_KV.put(key, JSON.stringify(locks), { expirationTtl: ttl });
}

// 查找覆盖指定路径的活动锁：精确匹配任意 depth；祖先锁仅 infinity 生效，memberChange 时（新建/删除集合成员）depth-0 集合锁同样生效（RFC 4918 §7.5）
async function findActiveLocks(env: Env, path: string, memberChange = false): Promise<LockInfo[]> {
  const segments = path ? path.split("/") : [];
  const result: LockInfo[] = [];
  for (let index = segments.length; index >= 0; index--) {
    const candidate = segments.slice(0, index).join("/");
    for (const lock of await readLocks(env, candidate)) {
      if (index === segments.length || lock.depth === "infinity" || memberChange) result.push(lock);
    }
  }
  return result;
}

// 扫描 path/ 之下成员上的锁（目录递归删除/移动时需提交这些 token，RFC 4918 §7.5.2）
async function findConflictingDescendantLocks(env: Env, path: string, request?: Request): Promise<LockInfo[]> {
  if (!request) return [];
  const locks: LockInfo[] = [];
  for (const name of await listAllKV(env, LOCK_PREFIX)) {
    const descendant = decodeURIComponent(name.slice(LOCK_PREFIX.length));
    if (!descendant.startsWith(`${path}/`)) continue;
    locks.push(...await readLocks(env, descendant));
  }
  if (!locks.length) return [];
  const provided = extractIfTokens(request.headers.get("If") ?? "", path);
  return locks.filter((lock) => !provided.includes(lock.token));
}

// 解析 RFC 4918 If 头：未标记列表作用于当前资源；带资源标签的列表仅当标签指向当前路径时生效；Not 修饰的 token 不作为提交凭证
function extractIfTokens(headerValue: string | null, path: string): string[] {
  if (!headerValue) return [];
  const result: string[] = [];
  const listRegex = /(?:<([^>]+)>)?\s*\(([^()]*)\)/g;
  let listMatch: RegExpExecArray | null;
  while ((listMatch = listRegex.exec(headerValue))) {
    if (listMatch[1] && !ifTagMatchesPath(listMatch[1], path)) continue;
    const itemRegex = /(Not\s+)?<([^>]+)>|\[[^\]]*\]/g;
    let itemMatch: RegExpExecArray | null;
    while ((itemMatch = itemRegex.exec(listMatch[2]))) {
      if (!itemMatch[1] && itemMatch[2]?.startsWith("opaquelocktoken:")) result.push(itemMatch[2]);
    }
  }
  return result;
}

function ifTagMatchesPath(tag: string, path: string): boolean {
  try {
    const decoded = decodeURIComponent(new URL(tag).pathname).replace(/\/+$/, "");
    if (path === "") return decoded === "" || decoded === "/";
    return decoded === `/${path}` || decoded.endsWith(`/${path}`);
  } catch {
    return false;
  }
}

// 写操作锁校验：存在未提交 token 的活动锁时返回 423
async function assertUnlocked(env: Env, path: string, request?: Request, memberChange = false): Promise<Response | null> {
  if (!request) return null;
  const locks = await findActiveLocks(env, path, memberChange);
  if (!locks.length) return null;
  const provided = [...extractIfTokens(request.headers.get("If") ?? "", path), ...extractIfTokens(request.headers.get("Lock-Token") ?? "", path)];
  if (locks.some((lock) => provided.includes(lock.token))) return null;
  return textResponse("Resource is locked", 423);
}

// 写操作条件请求评估（If-Match / If-None-Match），无相关头时跳过查询
async function precondition(env: Env, path: string, request: Request): Promise<Response | null> {
  const ifMatch = request.headers.get("If-Match");
  const ifNoneMatch = request.headers.get("If-None-Match");
  if (!ifMatch && !ifNoneMatch) return null;
  const object = await env.WEBDAV_BUCKET.head(r2Key(path));
  return evaluateMutatingPrecondition(request, object?.httpEtag ?? null);
}

function parseTimeoutHeader(value: string | null): number {
  if (value) {
    for (const part of value.split(",")) {
      const match = /Second-(\d+)/i.exec(part.trim());
      if (match) return Math.min(Math.max(1, Number(match[1])), LOCK_MAX_TIMEOUT);
    }
  }
  return LOCK_DEFAULT_TIMEOUT;
}

function extractLockOwner(body: string, fallback: string): string {
  const match = /<(?:[\w-]+:)?owner[^>]*>([\s\S]*?)<\/(?:[\w-]+:)?owner>/i.exec(body);
  return match ? match[1].trim() : fallback;
}

function activeLockXml(lock: LockInfo, lockroot: string): string {
  return `<d:activelock><d:locktype><d:write/></d:locktype><d:lockscope><d:${lock.scope}/></d:lockscope><d:depth>${lock.depth}</d:depth><d:owner>${escapeXml(lock.owner)}</d:owner><d:timeout>Second-${lock.timeout}</d:timeout><d:locktoken><d:href>${escapeXml(lock.token)}</d:href></d:locktoken><d:lockroot><d:href>${escapeXml(lockroot)}</d:href></d:lockroot></d:activelock>`;
}

function lockDiscoveryXml(lock: LockInfo, lockroot: string): string {
  return `<?xml version="1.0" encoding="utf-8"?><d:prop xmlns:d="DAV:"><d:lockdiscovery>${activeLockXml(lock, lockroot)}</d:lockdiscovery></d:prop>`;
}

async function lockResource(request: Request, env: Env, path: string, username: string, account?: WebdavAccount): Promise<Response> {
  if (!path) return textResponse("A resource path is required", 400);
  const body = await request.text();
  const timeout = parseTimeoutHeader(request.headers.get("Timeout"));
  const depthHeader = (request.headers.get("Depth") ?? "infinity").trim().toLowerCase();
  if (depthHeader !== "0" && depthHeader !== "infinity") return textResponse("Invalid Depth header", 400);
  const depth: "0" | "infinity" = depthHeader;
  const scope: "exclusive" | "shared" = /<(?:[\w-]+:)?shared[\s/>]/i.test(body) ? "shared" : "exclusive";
  const existing = await readLocks(env, path);
  const providedIf = extractIfTokens(request.headers.get("If") ?? "", path);
  const lockroot = `${new URL(request.url).origin}${urlPath(env, path, account)}`;
  if (!body.trim()) {
    // 空请求体 = 刷新现有锁，必须通过 If 头提交对应锁 token（RFC 4918 §7.7）
    const target = existing.find((lock) => providedIf.includes(lock.token));
    if (!existing.length) return textResponse("No lock exists", 409);
    if (!target) return textResponse("Precondition Failed", 412);
    const refreshed: LockInfo = { ...target, timeout, expiresAt: Date.now() + timeout * 1000 };
    await writeLocks(env, path, existing.map((lock) => (lock.token === target.token ? refreshed : lock)));
    return new Response(lockDiscoveryXml(refreshed, lockroot), { status: 200, headers: { "Content-Type": "application/xml; charset=utf-8" } });
  }
  if (!/<lockinfo[\s/>]/i.test(body)) return textResponse("Invalid lock request body", 400);
  // 冲突检查：exclusive 与任何现存锁互斥，shared 之间可共存（RFC 4918 §6.1）
  const directConflict = existing.find((lock) => lock.scope === "exclusive" || (lock.scope === "shared" && scope === "exclusive"));
  if (directConflict && !providedIf.includes(directConflict.token)) return textResponse("Resource is already locked", 423);
  const ancestorConflict = (await findActiveLocks(env, path, true)).filter((lock) => !existing.some((candidate) => candidate.token === lock.token)).find((lock) => lock.scope === "exclusive" || (lock.scope === "shared" && scope === "exclusive"));
  if (ancestorConflict && !providedIf.includes(ancestorConflict.token)) return textResponse("Ancestor collection is locked", 423);
  // Depth: infinity 加锁需检查后代成员上冲突的锁（RFC 4918 §7.5）
  if (depth === "infinity") {
    const descendantConflict = (await findConflictingDescendantLocks(env, path, request)).find((lock) => lock.scope === "exclusive" || (lock.scope === "shared" && scope === "exclusive"));
    if (descendantConflict) return textResponse("Descendant resource is locked", 423);
  }
  // 锁定未映射 URL 时创建空资源（RFC 4918 §7.3）
  if (!(await env.WEBDAV_BUCKET.head(r2Key(path))) && !(await env.WEBDAV_KV.get(dirKey(path)))) {
    const object = await env.WEBDAV_BUCKET.put(r2Key(path), "", { httpMetadata: { contentType: "application/octet-stream" } });
    const metadata: FileMeta = { type: "file", size: object.size, etag: object.httpEtag, contentType: "application/octet-stream", updatedAt: new Date().toISOString() };
    await env.WEBDAV_KV.put(metaKey(path), JSON.stringify(metadata));
  }
  const lock: LockInfo = {
    token: `opaquelocktoken:${crypto.randomUUID()}`,
    owner: extractLockOwner(body, username),
    depth,
    timeout,
    expiresAt: Date.now() + timeout * 1000,
    scope,
  };
  await writeLocks(env, path, [...existing, lock]);
  return new Response(lockDiscoveryXml(lock, lockroot), { status: 200, headers: { "Content-Type": "application/xml; charset=utf-8", "Lock-Token": `<${lock.token}>` } });
}

async function unlockResource(request: Request, env: Env, path: string): Promise<Response> {
  if (!path) return textResponse("A resource path is required", 400);
  const tokens = extractIfTokens(request.headers.get("Lock-Token") ?? "", path);
  const locks = await readLocks(env, path);
  if (!locks.length) return textResponse("No lock exists", 409);
  const remaining = locks.filter((lock) => !tokens.includes(lock.token));
  if (remaining.length === locks.length) return textResponse("Lock token does not match", 403);
  await writeLocks(env, path, remaining);
  return new Response(null, { status: 204 });
}

async function putObject(request: Request, env: Env, path: string, account: WebdavAccount, rootEnv: Env): Promise<Response> {
  if (!path) return textResponse("A file path is required", 400);
  const preconditionResponse = await precondition(env, path, request);
  if (preconditionResponse) return preconditionResponse;
  // 覆盖已存在文件只是内容修改；新建文件属于向集合内创建成员，需受 depth-0 集合锁保护
  const existingObject = await env.WEBDAV_BUCKET.head(r2Key(path));
  const lockResponse = await assertUnlocked(env, path, request, !existingObject);
  if (lockResponse) return lockResponse;
  const contentLength = Number(request.headers.get("Content-Length"));
  if (!Number.isSafeInteger(contentLength) || contentLength < 0) return textResponse("Content-Length is required", 411);
  const quotaResponse = await ensureStorageCapacity(rootEnv, env, account, path, contentLength);
  if (quotaResponse) return quotaResponse;
  const contentType = request.headers.get("Content-Type") ?? "application/octet-stream";
  const object = await env.WEBDAV_BUCKET.put(r2Key(path), request.body, { httpMetadata: { contentType } });
  const metadata: FileMeta = { type: "file", size: object.size, etag: object.httpEtag, contentType, updatedAt: new Date().toISOString() };
  await env.WEBDAV_KV.put(metaKey(path), JSON.stringify(metadata));
  await adjustAccountStorageUsage(env, object.size - (existingObject?.size ?? 0));
  return new Response(null, { status: 201, headers: { ETag: object.httpEtag } });
}

async function makeCollection(env: Env, path: string, request?: Request): Promise<Response> {
  if (!path) return textResponse("The root collection already exists", 405);
  if (request) {
    const lockResponse = await assertUnlocked(env, path, request, true);
    if (lockResponse) return lockResponse;
  }
  if (await env.WEBDAV_KV.get(dirKey(path)) || await env.WEBDAV_BUCKET.head(r2Key(path))) return textResponse("Collection already exists", 405);
  await env.WEBDAV_KV.put(dirKey(path), new Date().toISOString());
  return new Response(null, { status: 201 });
}

async function deletePath(env: Env, path: string, request?: Request): Promise<Response> {
  if (!path) return textResponse("The root collection cannot be deleted", 403);
  if (request) {
    // 删除属于移除父集合的内部成员，depth-0 集合锁同样生效
    const lockResponse = await assertUnlocked(env, path, request, true);
    if (lockResponse) return lockResponse;
  }

  const object = await env.WEBDAV_BUCKET.head(r2Key(path));
  if (object) {
    if (request) {
      const preconditionResponse = evaluateMutatingPrecondition(request, object.httpEtag);
      if (preconditionResponse) return preconditionResponse;
    }
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
    await adjustAccountStorageUsage(env, -object.size);

    // 记录删除信息到 KV（用于管理界面显示）
    await env.WEBDAV_KV.put(`${TRASH_PREFIX}${path}`, JSON.stringify(trashMeta), {
      expirationTtl: TRASH_RETENTION_DAYS * 24 * 60 * 60,
    });

    return new Response(null, { status: 204 });
  }

  // 目录删除
  if (!(await env.WEBDAV_KV.get(dirKey(path))) && !(await hasChildren(env, path))) return textResponse("Not Found", 404);
  // 目录递归删除：成员上的锁未提交 token 时拒绝（RFC 4918 §7.5.2）
  const descendantLocks = await findConflictingDescendantLocks(env, path, request);
  if (descendantLocks.length) return textResponse("Locked descendant resources", 423);

  // 软删除目录及其内容
  const objects = await listAllObjects(env, `${path}/`);
  const removedBytes = objects.reduce((total, item) => total + item.size, 0);
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
  await adjustAccountStorageUsage(env, -removedBytes);

  return new Response(null, { status: 204 });
}

// 新增：恢复回收站文件
async function restoreFromTrash(env: Env, trashPath: string): Promise<Response> {
  const trashMeta = await env.WEBDAV_KV.get(`${TRASH_PREFIX}${trashPath}`, "json") as { originalPath: string; deletedAt: string } | null;
  if (!trashMeta) return textResponse("Not Found in Trash", 404);

  // 恢复文件
  const trashObjects = await listAllObjects(env, `__trash/${TRASH_PREFIX}`);
  let restoredBytes = 0;
  for (const obj of trashObjects) {
    const customMeta = obj.customMetadata;
    if (customMeta?.originalPath === trashMeta.originalPath || customMeta?.originalPath?.startsWith(`${trashMeta.originalPath}/`)) {
      const content = await env.WEBDAV_BUCKET.get(obj.key);
      if (content) {
        await env.WEBDAV_BUCKET.put(customMeta.originalPath, content.body, {
          httpMetadata: content.httpMetadata,
        });
        restoredBytes += content.size;
      }
      await env.WEBDAV_BUCKET.delete(obj.key);
    }
  }
  // 回收站对象不计入用量，恢复后重新计入
  await adjustAccountStorageUsage(env, restoredBytes);

  // 删除回收站记录
  await env.WEBDAV_KV.delete(`${TRASH_PREFIX}${trashPath}`);

  return new Response(null, { status: 204 });
}

// 新增：从回收站永久删除（单个条目，含目录下的全部对象）
async function purgeFromTrash(env: Env, trashPath: string): Promise<void> {
  const trashMeta = await env.WEBDAV_KV.get(`${TRASH_PREFIX}${trashPath}`, "json") as { originalPath: string; deletedAt: string } | null;
  if (!trashMeta) return;

  // 删除 __trash/ 下对应的对象（含子目录内容）
  const trashObjects = await listAllObjects(env, `__trash/${TRASH_PREFIX}`);
  for (const obj of trashObjects) {
    const customMeta = obj.customMetadata;
    if (customMeta?.originalPath === trashMeta.originalPath || customMeta?.originalPath?.startsWith(`${trashMeta.originalPath}/`)) {
      await env.WEBDAV_BUCKET.delete(obj.key);
    }
  }

  // 删除回收站元数据
  await env.WEBDAV_KV.delete(`${TRASH_PREFIX}${trashPath}`);
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

async function copyOrMove(request: Request, env: Env, source: string, move: boolean, account?: WebdavAccount, rootEnv?: Env): Promise<Response> {
  if (!source) return textResponse("The root collection cannot be moved", 403);
  const destination = destinationPath(request, env, account);
  if (!destination || destination === source || destination.startsWith(`${source}/`)) return textResponse("Invalid destination", 400);
  const overwrite = (request.headers.get("Overwrite") ?? "T").toUpperCase() !== "F";
  const destinationObject = await env.WEBDAV_BUCKET.head(r2Key(destination));
  const sourceHead = await env.WEBDAV_BUCKET.head(r2Key(source));
  const sourceLockResponse = await assertUnlocked(env, source, request, move);
  if (sourceLockResponse) return sourceLockResponse;
  const destinationLockResponse = await assertUnlocked(env, destination, request, !destinationObject);
  if (destinationLockResponse) return destinationLockResponse;
  if (destinationObject && !overwrite) return textResponse("Destination exists", 412);
  // 条件请求按 RFC 9110 针对 Request-URI（源）评估 If-Match；If-None-Match 结合目标实现"仅创建"语义
  const ifMatch = request.headers.get("If-Match");
  if (ifMatch && (!sourceHead || !etagMatches(ifMatch, sourceHead.httpEtag))) return textResponse("Precondition Failed", 412);
  const ifNoneMatch = request.headers.get("If-None-Match");
  if (ifNoneMatch && destinationObject && etagMatches(ifNoneMatch, destinationObject.httpEtag)) return textResponse("Precondition Failed", 412);
  if (!move && account && rootEnv) {
    const quotaResponse = await ensureStorageCapacity(rootEnv, env, account, destination, await storageSizeAtPath(env, source));
    if (quotaResponse) return quotaResponse;
  }
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
    // 覆盖写入目标：copy 净增源大小减去被覆盖目标；move 时源随后被移除，净减被覆盖目标
    await adjustAccountStorageUsage(env, move ? -(destinationObject?.size ?? 0) : sourceObject.size - (destinationObject?.size ?? 0));
    return new Response(null, { status: 201 });
  }
  if (!(await hasChildren(env, source)) && !(await env.WEBDAV_KV.get(dirKey(source)))) return textResponse("Not Found", 404);
  // 目录递归移动：源成员上的锁未提交 token 时拒绝（RFC 4918 §7.5.2）
  if (move) {
    const descendantLocks = await findConflictingDescendantLocks(env, source, request);
    if (descendantLocks.length) return textResponse("Locked descendant resources", 423);
  }
  const objects = await listAllObjects(env, `${source}/`);
  const sourceDirBytes = objects.reduce((total, item) => total + item.size, 0);
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
  // 目录复制净增源目录字节数；move 时下方 deletePath 已扣除源目录，两者相抵
  await adjustAccountStorageUsage(env, sourceDirBytes);
  await env.WEBDAV_KV.put(dirKey(destination), new Date().toISOString());
  return new Response(null, { status: 201 });
}

const SUPPORTEDLOCK_XML = `<d:supportedlock><d:lockentry><d:lockscope><d:exclusive/></d:lockscope><d:locktype><d:write/></d:locktype></d:lockentry><d:lockentry><d:lockscope><d:shared/></d:lockscope><d:locktype><d:write/></d:locktype></d:lockentry></d:supportedlock>`;

// 请求级预取账户内全部锁，避免 PROPFIND 逐条目遍历 KV
async function loadLockMap(env: Env): Promise<Map<string, LockInfo[]>> {
  const map = new Map<string, LockInfo[]>();
  for (const name of await listAllKV(env, LOCK_PREFIX)) {
    const lockedPath = decodeURIComponent(name.slice(LOCK_PREFIX.length));
    const locks = await readLocks(env, lockedPath);
    if (locks.length) map.set(lockedPath, locks);
  }
  return map;
}

async function propfind(request: Request, env: Env, path: string, account?: WebdavAccount, rootEnv?: Env): Promise<Response> {
  const depth = (request.headers.get("Depth") ?? "infinity").trim().toLowerCase();
  if (depth !== "0" && depth !== "1" && depth !== "infinity") return textResponse("Invalid Depth header", 400);
  const rootObject = path ? await env.WEBDAV_BUCKET.head(r2Key(path)) : null;
  const rootIsDirectory = !rootObject;
  if (path && !rootObject && !(await env.WEBDAV_KV.get(dirKey(path))) && !(await hasChildren(env, path))) return textResponse("Not Found", 404);
  // RFC 4331 配额属性：仅在集合上返回，同一目录树共享一次计算结果
  let quotaXml = "";
  if (rootIsDirectory) {
    const used = account && rootEnv ? await getUserStorageUsage(rootEnv, account.owner) : await storageSizeAtPath(env, "");
    const available = Math.max(0, USER_STORAGE_LIMIT - used);
    quotaXml = `<d:quota-used-bytes>${used}</d:quota-used-bytes><d:quota-available-bytes>${available}</d:quota-available-bytes>`;
  }
  const entries = [{ path, directory: rootIsDirectory }];
  const lockMap = await loadLockMap(env);
  if (depth === "1" && rootIsDirectory) entries.push(...await listChildren(env, path));
  if (depth === "infinity" && rootIsDirectory) entries.push(...await listDescendants(env, path));
  const xml = (await Promise.all(entries.map((entry) => propResponse(request, env, entry.path, entry.directory, account, entry.directory ? quotaXml : "", lockMap)))).join("");
  return new Response(`<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:">${xml}</d:multistatus>`, { status: 207, headers: { "Content-Type": "text/xml; charset=utf-8", DAV: "1, 2", "Cache-Control": "no-store" } });
}

async function propResponse(request: Request, env: Env, path: string, directory: boolean, account?: WebdavAccount, quotaXml = "", lockMap: Map<string, LockInfo[]> = new Map()): Promise<string> {
  const object = directory ? null : await env.WEBDAV_BUCKET.head(r2Key(path));
  const displayName = path ? path.slice(path.lastIndexOf("/") + 1) : "WebDAV";
  const href = `${new URL(request.url).origin}${urlPath(env, path, account)}${directory ? "/" : ""}`;
  const size = object?.size ?? 0;
  const modified = object?.uploaded?.toUTCString() ?? new Date().toUTCString();
  // lockdiscovery：从预取锁映射中筛出覆盖该资源的锁（精确匹配任意 depth，或 Depth: infinity 祖先）
  const applicableLocks: LockInfo[] = [];
  for (const [lockedPath, locks] of lockMap) {
    if (lockedPath === path) applicableLocks.push(...locks);
    else if (path.startsWith(`${lockedPath}/`)) applicableLocks.push(...locks.filter((lock) => lock.depth === "infinity"));
  }
  const lockXml = applicableLocks.map((lock) => activeLockXml(lock, href)).join("");
  return `<d:response><d:href>${escapeXml(href)}</d:href><d:propstat><d:prop><d:displayname>${escapeXml(displayName)}</d:displayname><d:resourcetype>${directory ? "<d:collection/>" : ""}</d:resourcetype><d:getcontentlength>${size}</d:getcontentlength><d:getlastmodified>${modified}</d:getlastmodified><d:getcontenttype>${directory ? "httpd/unix-directory" : escapeXml(object?.httpMetadata?.contentType ?? "application/octet-stream")}</d:getcontenttype>${object?.httpEtag ? `<d:getetag>${escapeXml(object.httpEtag)}</d:getetag>` : ""}${quotaXml}${SUPPORTEDLOCK_XML}${lockXml ? `<d:lockdiscovery>${lockXml}</d:lockdiscovery>` : ""}</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>`;
}

function urlPath(env: Env, path: string, account?: WebdavAccount): string {
  const prefix = normalizePrefix(env.DAV_PREFIX ?? "");
  const accountPrefix = account ? `${account.owner}/${account.uuid}` : "";
  return `/${[prefix, accountPrefix, path].filter(Boolean).join("/").split("/").map(encodeURIComponent).join("/")}`;
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
    // 必须显式 include customMetadata，否则回收站恢复/永久删除无法通过 originalPath 匹配对象
    const page = await env.WEBDAV_BUCKET.list({ prefix, cursor, include: ["customMetadata"] });
    result.push(...page.objects);
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  return result;
}

const USER_STORAGE_LIMIT = 10 * 1024 * 1024 * 1024;

async function storageSizeAtPath(env: Env, path: string): Promise<number> {
  const object = await env.WEBDAV_BUCKET.head(r2Key(path));
  if (object) return object.size;
  const objects = await listAllObjects(env, `${path}/`);
  return objects.filter((item) => !item.key.startsWith("__trash/")).reduce((total, item) => total + item.size, 0);
}

const STORAGE_USAGE_KEY = "storage-usage";

// 读取账户存储用量 KV 缓存（不含 __trash/ 回收站对象）；缓存缺失时全量扫描 R2 重建
async function getAccountStorageUsage(env: Env): Promise<number> {
  const cached = await env.WEBDAV_KV.get(STORAGE_USAGE_KEY, "json") as { bytes: number } | null;
  if (cached && Number.isFinite(cached.bytes)) return cached.bytes;
  const objects = await listAllObjects(env, "");
  const bytes = objects.filter((item) => !item.key.startsWith("__trash/")).reduce((total, item) => total + item.size, 0);
  await env.WEBDAV_KV.put(STORAGE_USAGE_KEY, JSON.stringify({ bytes, updatedAt: new Date().toISOString() }));
  return bytes;
}

// 写操作后增量更新账户存储用量缓存；KV 读改写非原子，极端并发下可能有少量漂移
async function adjustAccountStorageUsage(env: Env, delta: number): Promise<void> {
  if (!delta) return;
  const current = await getAccountStorageUsage(env);
  await env.WEBDAV_KV.put(STORAGE_USAGE_KEY, JSON.stringify({ bytes: Math.max(0, current + delta), updatedAt: new Date().toISOString() }));
}

async function getUserStorageUsage(env: Env, owner: string): Promise<number> {
  const accounts = Object.values(await getWebdavAccounts(env)).filter((account) => account.owner === owner);
  const sizes = await Promise.all(accounts.map((account) => getAccountStorageUsage(createScopedEnv(env, storageScope(account)))));
  return sizes.reduce((total, size) => total + size, 0);
}

async function ensureStorageCapacity(rootEnv: Env, accountEnv: Env, account: WebdavAccount, path: string, incomingSize: number): Promise<Response | null> {
  const currentObject = await accountEnv.WEBDAV_BUCKET.head(r2Key(path));
  const currentUsage = await getUserStorageUsage(rootEnv, account.owner);
  const projectedUsage = currentUsage - (currentObject?.size || 0) + incomingSize;
  if (projectedUsage <= USER_STORAGE_LIMIT) return null;
  return textResponse("用户所有 WebDAV 账户的文件总量不能超过 10 GB", 413, {
    "X-Storage-Limit": String(USER_STORAGE_LIMIT),
    "X-Storage-Used": String(currentUsage),
  });
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
async function adminLogsPage(env: Env, filterUser = ""): Promise<Response> {
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
  // 普通用户视图仅展示自己的操作日志；超级管理员/管理入口展示全部
  const visibleLogs = filterUser ? logs.filter((log) => log.user === filterUser) : logs;
  const recentLogs = visibleLogs.slice(0, 100);

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

  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>访问日志</title><style>${ADMIN_CSS}${LOGS_CSS}</style><body>${topbarHtml("访问日志", `<a class="text-link inverse" href="/">返回管理中心</a>`)}<main class="dashboard">${pageHeadingHtml("ACCESS LOG", "访问日志", `最近 ${recentLogs.length} 条记录（保留 ${LOG_RETENTION_DAYS} 天）`)}<section class="data-table-wrap"><table class="data-table"><thead><tr><th>时间</th><th>方法</th><th>路径</th><th>状态</th><th>大小</th><th>IP</th><th>用户</th></tr></thead><tbody>${logRows || '<tr><td colspan="7">暂无日志</td></tr>'}</tbody></table></section></main></body></html>`);
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
a{color:#1769aa;text-decoration:none}[data-theme="dark"] a{color:var(--link-color)}
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
    return `<tr><td class="check-col"><input type="checkbox" class="trash-check" form="trash-toolbar-form" name="paths" value="${escapeXml(item.path)}"></td><td>${path}</td><td>${type}</td><td>${size}</td><td>${time}</td><td><div class="row-actions"><form method="post" action="/?view=trash&account=${encodeURIComponent(accountUsername)}"><input type="hidden" name="action" value="restore"><input type="hidden" name="accountUsername" value="${escapeHtml(accountUsername)}"><input type="hidden" name="path" value="${escapeXml(item.path)}"><button type="submit" class="restore-btn">恢复</button></form><form method="post" action="/?view=trash&account=${encodeURIComponent(accountUsername)}" onsubmit="return confirm('确定要永久删除此项吗？此操作不可恢复！')"><input type="hidden" name="action" value="purge"><input type="hidden" name="accountUsername" value="${escapeHtml(accountUsername)}"><input type="hidden" name="paths" value="${escapeXml(item.path)}"><button type="submit" class="purge-btn">永久删除</button></form></div></td></tr>`;
  }).join("");

  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>回收站</title><style>${ADMIN_CSS}${FILES_CSS}${TRASH_CSS}</style><body>${topbarHtml("回收站", `<a class="text-link inverse" href="/?view=account&account=${encodeURIComponent(accountUsername)}">返回账户管理</a>`)}<main class="dashboard">${pageHeadingHtml("TRASH", "回收站", `账户：${accountUsername}。已删除的文件将在 ${TRASH_RETENTION_DAYS} 天后自动清理`, `<a class="secondary-button" href="/?view=files&account=${encodeURIComponent(accountUsername)}">回到文件管理</a>`)}<section class="data-table-wrap"><table class="data-table"><thead><tr><th class="check-col"><input type="checkbox" id="trash-select-all" onchange="toggleTrashSelect(this.checked)" title="全选" aria-label="全选"></th><th>原路径</th><th>类型</th><th>大小</th><th>删除时间</th><th>操作</th></tr></thead><tbody>${trashRows || '<tr><td colspan="6">回收站为空</td></tr>'}</tbody></table></section>${trashItems.length > 0 ? `<form id="trash-toolbar-form" method="post" action="/?view=trash&account=${encodeURIComponent(accountUsername)}" class="trash-toolbar"><input type="hidden" name="accountUsername" value="${escapeHtml(accountUsername)}"><button type="submit" name="action" value="restore" class="restore-btn" onclick="return confirmTrashRestore()">恢复选中</button><button type="submit" name="action" value="purge" class="empty-btn" onclick="return confirmTrashPurge()">永久删除选中</button><button type="submit" name="action" value="empty" class="empty-btn" onclick="return confirm('确定要清空回收站吗？此操作不可恢复！')">清空回收站</button></form><script>function toggleTrashSelect(checked){document.querySelectorAll('.trash-check').forEach(function(c){c.checked=checked});}function confirmTrashPurge(){var n=document.querySelectorAll('.trash-check:checked').length;if(!n){alert('请先勾选要操作的文件');return false;}return confirm('确定要永久删除选中的 '+n+' 项吗？此操作不可恢复！');}function confirmTrashRestore(){var n=document.querySelectorAll('.trash-check:checked').length;if(!n){alert('请先勾选要恢复的文件');return false;}return confirm('确定要恢复选中的 '+n+' 项吗？');}</script>` : ""}</main></body></html>`);
}

const TRASH_CSS = `
table{width:100%;border-collapse:collapse;margin:20px 0;font-size:14px}
th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #e1e4e8}
th{background:#f6f8fa;font-weight:600}
.restore-btn{padding:4px 12px;background:#2e7d32;color:white;border:0;border-radius:3px;cursor:pointer;font-size:12px}
.restore-btn:hover{background:#1b5e20}
.purge-btn{padding:4px 12px;min-height:40px;display:inline-flex;align-items:center;justify-content:center;background:#c62828;color:white;border:0;border-radius:3px;cursor:pointer;font-size:12px}
.purge-btn:hover{background:#b71c1c}
.row-actions{display:flex;gap:8px}
.trash-toolbar .restore-btn{padding:10px 20px;font-size:14px;border-radius:5px}
.trash-toolbar .empty-btn{margin-top:0}
.empty-form{margin:20px 0;text-align:center}
.check-col{width:44px;text-align:center}
td.check-col{text-align:center}
.trash-check{width:16px;height:16px;cursor:pointer;vertical-align:middle}
.trash-toolbar{display:flex;justify-content:flex-end;gap:10px;margin:20px 0}
.empty-btn{padding:10px 20px;background:#c62828;color:white;border:0;border-radius:5px;cursor:pointer;font-size:14px}
.empty-btn:hover{background:#b71c1c}
a{color:#1769aa;text-decoration:none}[data-theme="dark"] a{color:var(--link-color)}
a:hover{text-decoration:underline}
`;
var DARK_MODE_CSS = `:root{--bg-gradient:linear-gradient(135deg,#f6f8f5 0%,#e8efed 100%);--text-primary:#17212b;--text-secondary:#667578;--card-bg:rgba(255,255,255,.82);--card-border:#d7e0dc;--card-shadow:0 12px 30px rgba(31,61,57,.06);--input-bg:#fbfcfa;--input-border:#cbd7d3;--topbar-bg:#183b3f;--topbar-text:#f4f8f5;--table-header-bg:#f2f6f3;--table-header-text:#60716d;--table-border:#e0e7e3;--accent-gold:#d79b41;--accent-gold-hover:#e5ae59;--accent-gold-text:#183b3f;--accent-teal:#397277;--danger-bg:#fff5f3;--danger-border:#c76c61;--danger-text:#a43f35;--secondary-bg:#fff;--secondary-border:#397277;--secondary-text:#285b60;--link-color:#32656a}[data-theme="dark"]{--bg-gradient:linear-gradient(135deg,#0f1a1c 0%,#162628 100%);--text-primary:#c7d7d3;--text-secondary:#91aaa4;--card-bg:rgba(28,46,49,.82);--card-border:#2d484b;--card-shadow:0 12px 30px rgba(0,0,0,.25);--input-bg:#1a2e31;--input-border:#3a5558;--topbar-bg:#0c1618;--topbar-text:#c7d7d3;--table-header-bg:#1a2e31;--table-header-text:#a5bcb7;--table-border:#2d484b;--accent-gold:#e5ae59;--accent-gold-hover:#f0be70;--accent-gold-text:#0f1a1c;--accent-teal:#7ab8b0;--danger-bg:#2a1515;--danger-border:#a43f35;--danger-text:#e88078;--secondary-bg:transparent;--secondary-border:#5a9a9e;--secondary-text:#8fd4d8;--link-color:#7ab8b0}body{background:var(--bg-gradient);color:var(--text-primary)}.muted{color:var(--text-secondary)!important}.topbar{background:var(--topbar-bg);color:var(--topbar-text)}.topbar .text-link,.inverse{color:var(--topbar-text)}.summary-card,.config-card,.file-table-wrap,.data-table-wrap{background:var(--card-bg);border-color:var(--card-border);box-shadow:var(--card-shadow)}.config-form input,.filter-label input,.table-form input,.file-actions input,.mkdir-form input{background:var(--input-bg);border-color:var(--input-border);color:var(--text-primary)}.primary-button{background:var(--accent-gold);color:var(--accent-gold-text)}.primary-button:hover{background:var(--accent-gold-hover)}.secondary-button{background:var(--secondary-bg);border-color:var(--secondary-border);color:var(--secondary-text)}.danger-button{background:var(--danger-bg);border-color:var(--danger-border);color:var(--danger-text)}.data-table th,.user-table th,.file-table-wrap th{background:var(--table-header-bg);color:var(--table-header-text)}.data-table th,.data-table td,.user-table th,.user-table td,.file-table-wrap th,.file-table-wrap td{border-bottom-color:var(--table-border)}th,td{color:var(--text-primary)}.text-link{color:var(--link-color)}.method.GET{background:#152535;color:#6ab0e8}.method.PUT{background:#2a2015;color:#e8a555}.method.DELETE{background:#2a1515;color:#e88078}.method.MKCOL{background:#152a22;color:#5ec98f}.status.success{background:#152a22;color:#5ec98f}.status.warn{background:#2a2015;color:#e8a555}.status.error{background:#2a1515;color:#e88078}.restore-btn{background:#5ec98f;color:#fff}.empty-btn{background:var(--danger-text)}[data-theme="dark"] h1,[data-theme="dark"] h2,[data-theme="dark"] h3,[data-theme="dark"] label{color:var(--text-primary)}[data-theme="dark"] .card-meta,[data-theme="dark"] .card-label{color:var(--text-secondary)!important}[data-theme="dark"] .user-table tbody th{color:var(--text-primary)}`;
var TABLE_POLISH_CSS = `.data-table-wrap{overflow-x:auto;background:var(--card-bg);border:1px solid var(--card-border);border-radius:7px;box-shadow:var(--card-shadow)}.data-table,.user-table,.file-table-wrap table{width:100%;border-collapse:collapse}.data-table th,.data-table td,.user-table th,.user-table td,.file-table-wrap th,.file-table-wrap td{padding:14px 16px;text-align:left;vertical-align:middle;border-bottom:1px solid var(--table-border)}.data-table th,.user-table th,.file-table-wrap th{background:var(--table-header-bg);color:var(--table-header-text);font-size:12px;font-weight:800;letter-spacing:.04em}.data-table tbody tr:last-child td,.user-table tbody tr:last-child td,.file-table-wrap tbody tr:last-child td{border-bottom:0}.data-table .path{max-width:320px}.primary-button,.secondary-button,.danger-button,.restore-btn,.empty-btn{min-height:40px;display:inline-flex;align-items:center;justify-content:center;line-height:1.2}.data-table form{margin:0}.method,.status{display:inline-flex;align-items:center;min-height:26px;padding:3px 8px}.empty-form{display:flex;justify-content:flex-end;gap:10px}.empty-btn{margin-top:18px}`;
const FILES_CSS = `
.secondary-button{padding:12px 18px;border:1px solid #397277;border-radius:2px;background:#fff;color:#285b60;font:inherit;font-weight:800;cursor:pointer}.inline-button{display:inline-block;margin:12px 0 18px}.file-table-wrap{overflow-x:auto;background:rgba(255,255,255,.82);border:1px solid #d7e0dc}.file-table-wrap table{width:100%;border-collapse:collapse;min-width:640px}.file-table-wrap th,.file-table-wrap td{padding:15px 18px;text-align:left;border-bottom:1px solid #e0e7e3}.file-table-wrap th{background:#f2f6f3;color:#60716d;font-size:12px}.file-name{font-weight:700}.file-name a{color:#285b60}.folder-icon,.file-icon{display:inline-block;width:34px;margin-right:8px;color:#a47735;font-size:9px;font-weight:900}.file-icon{color:#51817c}.danger-button{padding:7px 11px;border:1px solid #c76c61;border-radius:2px;background:#fff5f3;color:#a43f35;font:inherit;font-size:12px;cursor:pointer}.empty-state{text-align:center;color:#71807e;padding:36px!important}
`;

var FORM_LAYOUT_CSS = `.icon-badge{width:auto;min-width:32px;padding:0 8px;white-space:nowrap;overflow:visible}.uuid-row{display:flex;gap:8px;align-items:center}.uuid-row input{flex:1;min-width:0;margin-top:0}.uuid-check-btn{margin:0;white-space:nowrap;height:44px;min-height:44px;display:inline-flex;align-items:center;justify-content:center;padding:0 16px;line-height:1}.uuid-result{display:block;margin-top:6px;font-size:12px}.uuid-result.error{color:#a43f35}.uuid-result.success{color:#176b48}.account-actions{display:flex;flex-wrap:wrap;align-items:center;gap:12px;margin-top:18px}.account-actions .inline-button{display:inline-flex;align-items:center;justify-content:center;margin:0;height:44px;padding:0 18px;line-height:1}.account-actions .delete-account-form{margin:0}.account-actions .danger-button{display:inline-flex;align-items:center;justify-content:center;height:44px;padding:0 18px;font-size:13px;font-weight:800;border-radius:4px}.storage-badge{display:flex;flex-direction:column;gap:5px;padding:12px 18px;background:var(--card-bg);border:1px solid var(--card-border);border-radius:7px;box-shadow:var(--card-shadow);font-size:13px;color:var(--text-secondary);white-space:nowrap}.storage-badge strong{color:var(--text-primary);font-size:15px;letter-spacing:-.02em}`;
var TOPBAR_LAYOUT_CSS = `.topbar-inner{display:flex;align-items:center;justify-content:flex-start;gap:16px}.topbar-inner>.topbar-right,.topbar-inner>div:not(.brand):last-child,.topbar-inner>.text-link{margin-left:auto}.topbar-right{display:flex;align-items:center;justify-content:flex-end;gap:16px;flex-wrap:wrap}@media(max-width:720px){.topbar-right{gap:10px}}`;
var LOGIN_DARK_CSS = `[data-theme="dark"] .login-panel{background:#182b2e;border-color:#345052;color:#c7d7d3}[data-theme="dark"] .login-panel h1,[data-theme="dark"] .login-panel label{color:#c7d7d3}[data-theme="dark"] .login-panel .muted{color:#91aaa4!important}[data-theme="dark"] .login-panel input{background:#122326;border-color:#3a5558;color:#c7d7d3}`;
var THEME_TOGGLE_CSS = `.theme-toggle{appearance:none;-webkit-appearance:none;width:36px;height:36px;padding:0;border:0;border-radius:50%;background:transparent;box-shadow:none;color:currentColor;display:grid;place-items:center;cursor:pointer;font-size:17px;line-height:1;opacity:.86}.theme-toggle:hover{background:transparent;box-shadow:none;opacity:1;transform:scale(1.08)}.theme-toggle:focus-visible{outline:2px solid currentColor;outline-offset:3px}.login-shell>.theme-toggle{position:absolute;top:16px;right:20px;margin:0;z-index:10}`;
var FILE_ACTION_ALIGNMENT_CSS = `.file-actions{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;align-items:stretch;margin-bottom:22px}.file-action-card{min-width:0;padding:18px;background:var(--card-bg);border:1px solid var(--card-border);border-radius:7px;box-shadow:var(--card-shadow)}.file-action-heading{display:flex;flex-direction:column;gap:5px;margin-bottom:14px;color:var(--text-primary)}.file-action-heading span{color:var(--text-secondary);font-size:12px}.file-action-card form{display:grid;grid-template-columns:minmax(0,1fr) 116px;align-items:center;gap:8px;width:100%;min-width:0;min-height:44px;overflow:hidden}.file-action-card input[type=file],.file-action-card input[name=name]{display:block;width:100%;min-width:0;height:44px;line-height:42px;padding:0 10px;overflow:hidden;text-overflow:ellipsis;border:1px solid #cbd7d3;background:#fff;font:inherit}.file-action-card input[type=file]::file-selector-button{height:42px;margin-right:8px;padding:0 10px;border:0;border-right:1px solid var(--input-border);background:var(--table-header-bg);color:var(--text-primary);font:inherit}.file-action-card button{width:116px;min-width:116px;height:44px;min-height:44px;padding:0 10px;margin:0;white-space:nowrap}@media(max-width:720px){.file-actions{grid-template-columns:1fr}.file-action-card form{grid-template-columns:minmax(0,1fr) 116px}}`;


const THEME_INIT_SCRIPT = `<script>(function(){try{var s=localStorage.getItem('cf-webdav-theme');if(s==='dark'||(!s&&window.matchMedia('(prefers-color-scheme:dark)').matches))document.documentElement.setAttribute('data-theme','dark');}catch(e){}})();</script>`;
const THEME_SCRIPT = `<script>(function(){var dark=document.documentElement.getAttribute('data-theme')==='dark';var t=document.querySelectorAll('.theme-toggle');for(var i=0;i<t.length;i++)t[i].textContent=dark?'\u2600\uFE0F':'\u{1F319}';})();function toggleTheme(){var h=document.documentElement;var dark=h.getAttribute('data-theme')==='dark';if(dark){h.removeAttribute('data-theme');localStorage.setItem('cf-webdav-theme','light')}else{h.setAttribute('data-theme','dark');localStorage.setItem('cf-webdav-theme','dark')}var t=document.querySelectorAll('.theme-toggle');for(var i=0;i<t.length;i++)t[i].textContent=dark?'\u{1F319}':'\u2600\uFE0F'}</script>`;


