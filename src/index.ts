interface Env {
  WEBDAV_BUCKET: R2Bucket;
  WEBDAV_KV: KVNamespace;
  // 官方 Rate Limiting binding：限流计数不占 KV 配额（见 wrangler.toml [[ratelimits]]）
  RATE_LIMITER: RateLimit;
  ADMIN_USERNAME?: string;
  ADMIN_PASSWORD?: string;
  WEBDAV_USERNAME?: string;
  WEBDAV_PASSWORD?: string;
  DAV_PREFIX?: string;
  // 新增：启用访问日志
  ENABLE_ACCESS_LOG?: string;
  ENABLE_PUBLIC_REGISTRATION?: string;
  // —— 合规与协议可选配置 ——
  // 访问日志保留天数（默认 30，1-365）
  LOG_RETENTION_DAYS?: string;
  // "true" 时访问日志中的 IP 脱敏（IPv4 保留前三段 / IPv6 保留前四组）
  LOG_IP_REDACT?: string;
  // 单次 PUT 上传字节上限（0/缺省 = 不限制，由平台请求体上限兜底）
  MAX_UPLOAD_BYTES?: string;
  // 密码最小长度（默认 8，8-128；密码另须同时包含字母与数字）
  MIN_PASSWORD_LENGTH?: string;
  // 会话空闲超时分钟数（0/缺省 = 不启用，会话固定 7 天）
  SESSION_IDLE_MINUTES?: string;
  ADMIN_IDLE_MINUTES?: string;
  // 登录防爆破：窗口期内最大失败次数（默认 5）与锁定分钟数（默认 15）
  LOGIN_MAX_ATTEMPTS?: string;
  LOGIN_LOCK_MINUTES?: string;
  // /.well-known/security.txt（RFC 9116）漏洞报告联系方式，如 mailto:security@example.com
  SECURITY_CONTACT?: string;
  // Turnstile 人机校验（公开注册防滥用）：两项同时配置才启用
  TURNSTILE_SITE_KEY?: string;
  TURNSTILE_SECRET_KEY?: string;
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
const METHODS = ["OPTIONS", "PROPFIND", "GET", "HEAD", "PUT", "DELETE", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "PROPPATCH", "REPORT", "SEARCH"];
// 新增：管理审计日志（敏感操作流水，仅超级管理员可查看导出，普通用户不可见不可删）
interface AuditLog {
  timestamp: string;
  actor: string;
  action: string;
  target: string;
  clientIp: string;
  detail?: string;
}
const AUDIT_PREFIX = "audit:";
const AUDIT_RETENTION_DAYS = 365;
// 新增：RFC 6578 sync-collection 变更状态（每账户作用域一份；KV 读改写非原子，仅作增量同步参考）
interface SyncState {
  seq: number;
  activated?: boolean;
  changes: Record<string, { seq: number; kind: "modified" | "deleted" }>;
}
const SYNC_STATE_KEY = "sync:state";
const SYNC_MAX_CHANGES = 1000;
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
// 分享链接存全局 KV（路由层无账户上下文，记录内含 storageScope），定时任务负责过期清理
const SHARE_PREFIX = "share:";
// 每用户每日访问日志写入上限（防异常客户端撑爆日志 KV）；文本预览大小上限
const MAX_DAILY_LOGS_PER_USER = 2000;
const PREVIEW_TEXT_LIMIT = 1024 * 1024;
const IMAGE_EXTENSIONS = new Set(["png", "jpg", "jpeg", "gif", "webp", "svg", "bmp", "ico", "avif"]);
const TEXT_EXTENSIONS = new Set(["txt", "md", "markdown", "json", "xml", "csv", "log", "yaml", "yml", "ini", "js", "css", "html", "htm", "py", "sh", "ts", "toml"]);
function previewKindOf(name: string): "image" | "text" | null {
  const ext = name.slice(name.lastIndexOf(".") + 1).toLowerCase();
  if (IMAGE_EXTENSIONS.has(ext)) return "image";
  if (TEXT_EXTENSIONS.has(ext)) return "text";
  return null;
}

// —— WebDAV 死属性（PROPPATCH）——
function propKey(path: string): string {
  return `${PROP_PREFIX}${encodeURIComponent(path)}`;
}

// —— TOTP 两步验证（RFC 6238，SHA-1 / 6 位 / 30 秒步长，容忍 ±1 步时钟漂移）——
function base32Encode(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

function base32Decode(input: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  const output: number[] = [];
  for (const char of input.toUpperCase().replace(/=+$/, "")) {
    const index = alphabet.indexOf(char);
    if (index < 0) continue;
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}

function generateTotpSecret(): string {
  return base32Encode(crypto.getRandomValues(new Uint8Array(20)));
}

async function verifyTotp(secretBase32: string, code: string): Promise<boolean> {
  const normalized = code.replace(/\s/g, "");
  if (!/^\d{6}$/.test(normalized) || !secretBase32) return false;
  const key = await crypto.subtle.importKey("raw", base32Decode(secretBase32) as unknown as ArrayBuffer, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const counter = Math.floor(Date.now() / 1000 / TOTP_STEP_SECONDS);
  for (const offset of [0, -1, 1]) {
    const step = counter + offset;
    const buffer = new ArrayBuffer(8);
    const view = new DataView(buffer);
    view.setUint32(0, Math.floor(step / 2 ** 32));
    view.setUint32(4, step >>> 0);
    const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, buffer));
    const position = signature[19] & 15;
    const dynamic = ((signature[position] & 127) << 24 | signature[position + 1] << 16 | signature[position + 2] << 8 | signature[position + 3]) % 1e6;
    const expected = String(dynamic).padStart(6, "0");
    if (expected.length === normalized.length && [...expected].every((char, index) => char === normalized[index])) return true;
  }
  return false;
}

// —— IP 白名单：精确 IP / IPv4 前缀（以 . 结尾，如 "203.0.113."）/ IPv4 CIDR；空列表 = 不限制 ——
function ipv4ToInt(value: string): number | null {
  const parts = value.split(".");
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    result = result * 256 + octet;
  }
  return result >>> 0;
}

function ipAllowed(ip: string, allowlist: string[]): boolean {
  if (!allowlist || !allowlist.length) return true;
  const address = ip.trim();
  for (const rule of allowlist) {
    const entry = rule.trim();
    if (!entry) continue;
    if (entry.includes("/")) {
      const [network, suffix] = entry.split("/");
      const prefixLength = Number(suffix);
      const networkInt = ipv4ToInt(network);
      const addressInt = ipv4ToInt(address);
      if (Number.isInteger(prefixLength) && prefixLength >= 0 && prefixLength <= 32 && networkInt !== null && addressInt !== null) {
        const shift = 32 - prefixLength;
        if ((networkInt >>> shift) === (addressInt >>> shift)) return true;
      }
    } else if (entry.endsWith(".") || entry.endsWith(":")) {
      if (address.startsWith(entry)) return true;
    } else if (address === entry) {
      return true;
    }
  }
  return false;
}

// 白名单条目格式校验（保存前用）：仅允许 IPv4/IPv6 字符构成的精确值、前缀或 CIDR
function isValidAllowlistEntry(entry: string): boolean {
  if (/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(entry)) return true;
  if (/^\d{1,3}(\.\d{1,3}){0,3}\.$/.test(entry)) return true;
  if (/^[0-9A-Fa-f:]+:$/.test(entry) || /^[0-9A-Fa-f:]+\/(\d{1,3})$/.test(entry) || (/^[0-9A-Fa-f:]+$/.test(entry) && entry.includes(":"))) return true;
  return false;
}

function clientIpOf(request: Request): string {
  return request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() || "unknown";
}

async function userIpAllowed(env: Env, username: string, ip: string): Promise<boolean> {
  if (ip === "unknown") return false;
  const account = (await getAdminAccounts(env))[username];
  return ipAllowed(ip, account?.ipAllowlist ?? []);
}

// 用户级存储容量上限（字节）：超管为普通用户设置的自定义上限，未设置时用系统默认
async function getUserStorageLimit(rootEnv: Env, owner: string): Promise<number> {
  const ownerAccount = (await getAdminAccounts(rootEnv))[owner];
  return ownerAccount?.storageLimitBytes && ownerAccount.storageLimitBytes > 0 ? ownerAccount.storageLimitBytes : USER_STORAGE_LIMIT;
}
const LOCK_DEFAULT_TIMEOUT = 600;
const LOCK_MAX_TIMEOUT = 3600;
// WebDAV 死属性（PROPPATCH）KV 键前缀；应用密码上限；TOTP 时间步长与待绑定密钥前缀
const PROP_PREFIX = "prop:";
const MAX_APP_PASSWORDS = 10;
const TOTP_STEP_SECONDS = 30;
const TOTP_PENDING_PREFIX = "totppending:";
const USER_LIMIT_MAX_GB = 100;
const DEFAULT_USERNAME = "admin";
const DEFAULT_PASSWORD = "admin123456";
const SESSION_TTL = 60 * 60 * 24 * 7;
const TRASH_RETENTION_DAYS = 30;

// —— 可配置合规/安全参数（环境变量驱动，缺省保持原行为）——
function intVarOf(value: string | undefined, fallback: number, min: number, max: number): number {
  const parsed = parseInt(value || "");
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}
function getLogRetentionDays(env: Env): number {
  return intVarOf(env.LOG_RETENTION_DAYS, 30, 1, 365);
}
function getMaxUploadBytes(env: Env): number {
  // 0 = 不限制，由 Cloudflare 平台的请求体上限兜底
  return intVarOf(env.MAX_UPLOAD_BYTES, 0, 0, 10 * 1024 ** 3);
}
function getMinPasswordLength(env: Env): number {
  return intVarOf(env.MIN_PASSWORD_LENGTH, 8, 8, 128);
}
function getSessionIdleSeconds(env: Env): number {
  // 0 = 不启用空闲超时，会话固定 7 天有效
  return intVarOf(env.SESSION_IDLE_MINUTES, 0, 0, 60 * 24 * 7) * 60;
}
function getAdminIdleSeconds(env: Env): number {
  // 超级管理员强制空闲超时：页面关闭后心跳停止，超时即吊销会话（近似“关闭即注销”）；0 = 禁用。
  // 默认 6 分钟：页面心跳每 5 分钟一次，需大于心跳间隔，否则页面开着也会被误判空闲
  return intVarOf(env.ADMIN_IDLE_MINUTES, 6, 0, 1440) * 60;
}
function getLoginLockConfig(env: Env): { maxAttempts: number; windowSeconds: number } {
  return { maxAttempts: intVarOf(env.LOGIN_MAX_ATTEMPTS, 5, 1, 100), windowSeconds: intVarOf(env.LOGIN_LOCK_MINUTES, 15, 1, 1440) * 60 };
}
// 密码策略：最小长度可配，且必须同时包含字母和数字；返回错误信息或 null
function passwordPolicyError(env: Env, password: string): string | null {
  const minLength = getMinPasswordLength(env);
  if (password.length < minLength) return `密码至少需要 ${minLength} 位`;
  if (!/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) return "密码必须同时包含字母和数字";
  return null;
}
// IP 脱敏：IPv4 保留前 3 段，IPv6 保留前 4 组，降低日志中的个人数据暴露面
function redactIp(ip: string): string {
  if (ip.includes(".") && !ip.includes(":")) return `${ip.split(".").slice(0, 3).join(".")}.0`;
  if (ip.includes(":")) return `${ip.split(":").slice(0, 4).join(":")}::`;
  return ip;
}
export default {
  // 定时维护（每日）：清理 KV 已过期但 R2 残留的回收站孤儿对象；重置用量缓存以实际 R2 重建，消除增量更新漂移
  async scheduled(_event: ScheduledController, env: Env, _ctx: ExecutionContext): Promise<void> {
    const accounts = await getWebdavAccounts(env);
    const cutoff = Date.now() - TRASH_RETENTION_DAYS * 24 * 60 * 60 * 1000;
    for (const account of Object.values(accounts)) {
      const scopedEnv = createScopedEnv(env, storageScope(account));
      const expired = (await listAllObjects(scopedEnv, "__trash/")).filter((obj) => {
        const deletedAt = Date.parse(obj.customMetadata?.deletedAt || "");
        return Number.isFinite(deletedAt) && deletedAt < cutoff;
      });
      for (let index = 0; index < expired.length; index += 1000) {
        await scopedEnv.WEBDAV_BUCKET.delete(expired.slice(index, index + 1000).map((obj) => obj.key));
      }
      for (const key of await listAllKV(scopedEnv, STORAGE_USAGE_KEY)) await scopedEnv.WEBDAV_KV.delete(key);
    }
  },
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const pathname = new URL(request.url).pathname;
    const clientIp = request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "unknown";
    const userAgent = request.headers.get("User-Agent") || "";
    const contentLength = parseInt(request.headers.get("Content-Length") || "0");
    if (pathname === "/" && (request.method === "GET" || request.method === "POST")) return adminRequest(request, env);
    if (pathname === "/__admin" || pathname.startsWith("/__admin/")) return adminRequest(request, env);
    if (pathname === "/s" || pathname.startsWith("/s/")) return serveShare(request, env);
    // robots.txt 与 /.well-known/security.txt（RFC 9116）：无需认证的合规固定端点
    if (request.method === "GET" && (pathname === "/robots.txt" || pathname === "/.well-known/security.txt")) return wellKnownResponse(pathname, env);
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
    // IP 白名单：WebDAV 客户端访问同样受账户所有者的白名单限制
    if (!ipAllowed(clientIp, (await getAdminAccounts(env))[webdavAccount.owner]?.ipAllowlist ?? [])) {
      await logAccess(env, { timestamp: new Date().toISOString(), method: request.method, path: pathname, status: 403, clientIp, userAgent, user: username });
      return textResponse("Forbidden: 当前 IP 不在该账户的访问白名单内", 403);
    }
    const scopedEnv = createScopedEnv(env, storageScope(webdavAccount));
    // 新增：检查流量限制
    const rateLimit = await checkRateLimit(scopedEnv, clientIp, request.method, contentLength);
    if (!rateLimit.allowed) {
      await logAccess(env, { timestamp: new Date().toISOString(), method: request.method, path: pathname, status: 429, clientIp, userAgent, user: username });
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
      await logAccess(env, { timestamp: new Date().toISOString(), method: request.method, path: pathname, status: 400, clientIp, userAgent, user: username });
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
        case "PROPPATCH": response = await proppatch(request, scopedEnv, path, webdavAccount); break;
        case "REPORT": response = await reportMethod(request, scopedEnv, path, webdavAccount); break;
        case "SEARCH": response = await searchMethod(request, scopedEnv, path, webdavAccount); break;
        default:
          response = textResponse("Method Not Allowed", 405, { Allow: METHODS.join(", ") });
      }
    } catch (error) {
      console.error("WebDAV request failed", { method: request.method, path, error });
      await logAccess(env, { timestamp: new Date().toISOString(), method: request.method, path, status: 500, clientIp, userAgent, user: username });
      return textResponse("Internal Server Error", 500);
    }
    await logAccess(env, { timestamp: new Date().toISOString(), method: request.method, path, status: response.status, clientIp, userAgent, bytesSent: request.method === "PUT" ? contentLength : parseInt(response.headers.get("Content-Length") || "0"), user: username });
    return response;
  },
};
// 新增：记录访问日志；键以倒序毫秒时间戳开头，KV list 字典序升序即最新在前
async function logAccess(env: Env, log: Omit<AccessLog, "timestamp"> & { timestamp?: string }): Promise<void> {
  if (env.ENABLE_ACCESS_LOG !== "true") return;
  // 只记录失败请求（4xx/5xx）与分享（SHARE）操作；成功的普通操作不再记录，以省 KV 写入配额
  if (log.status < 400 && log.method !== "SHARE") return;
  // IP 脱敏（LOG_IP_REDACT）与保留天数（LOG_RETENTION_DAYS）均为合规可配置项
  const retentionDays = getLogRetentionDays(env);
  const accessLog: AccessLog = {
    timestamp: log.timestamp || new Date().toISOString(),
    method: log.method,
    path: log.path,
    status: log.status,
    clientIp: env.LOG_IP_REDACT === "true" ? redactIp(log.clientIp) : log.clientIp,
    userAgent: log.userAgent,
    bytesSent: log.bytesSent,
    user: log.user,
  };

  // 每用户每日写入上限：超过即丢弃新日志，防止异常客户端在保留期内把日志 KV 撑爆
  const dailyKey = `loglimit:${accessLog.user || "anonymous"}:${accessLog.timestamp.slice(0, 10)}`;
  let writtenToday = 0;
  try { writtenToday = parseInt(await env.WEBDAV_KV.get(dailyKey) || "0"); } catch { }
  if (writtenToday >= MAX_DAILY_LOGS_PER_USER) {
    console.warn("Daily access log limit reached, dropping log for user", accessLog.user);
    return;
  }
  const logKey = `${LOG_PREFIX}${String(1e13 - Date.now()).padStart(13, "0")}-${Math.random().toString(36).slice(2)}`;
  try {
    await env.WEBDAV_KV.put(logKey, JSON.stringify(accessLog), { expirationTtl: retentionDays * 24 * 60 * 60 });
    // 每日上限计数器按约 1/10 概率批量 +10 回写，省 90% 计数器写入；
    // 上限仅作防滥用安全阀，允许 ±少量计数误差
    if (Math.random() < 0.1) await env.WEBDAV_KV.put(dailyKey, String(writtenToday + 10), { expirationTtl: 172800 });
  } catch (error) {
    // 日志写入失败不应影响主请求的响应
    console.error("Failed to write access log", error);
  }
}

// 管理审计日志：记录敏感操作（登录、改密、TOTP/白名单变更、账户增删、配额调整等），仅超级管理员可查看导出
async function logAudit(env: Env, entry: Omit<AuditLog, "timestamp"> & { timestamp?: string }): Promise<void> {
  const auditLog: AuditLog = {
    timestamp: entry.timestamp || new Date().toISOString(),
    actor: entry.actor,
    action: entry.action,
    target: entry.target,
    clientIp: entry.clientIp,
    detail: entry.detail,
  };
  const auditKey = `${AUDIT_PREFIX}${String(1e13 - Date.now()).padStart(13, "0")}-${Math.random().toString(36).slice(2)}`;
  try {
    await env.WEBDAV_KV.put(auditKey, JSON.stringify(auditLog), { expirationTtl: AUDIT_RETENTION_DAYS * 24 * 60 * 60 });
  } catch (error) {
    console.error("Failed to write audit log", error);
  }
}

async function listAuditLogs(env: Env, limit = 500): Promise<AuditLog[]> {
  const logs: AuditLog[] = [];
  let cursor: string | undefined;
  do {
    const page = await env.WEBDAV_KV.list({ prefix: AUDIT_PREFIX, cursor, limit: 100 });
    const pageLogs = await Promise.all(page.keys.map(async (key) => await env.WEBDAV_KV.get(key.name, "json") as AuditLog | null));
    for (const log of pageLogs) if (log) logs.push(log);
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor && logs.length < limit * 3);
  logs.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  return logs.slice(0, limit);
}

// 彻底清除指定用户（及其 WebDAV 账户）的访问日志与审计记录，用于删除用户时的数据最小化选项
async function purgeLogsForUsers(env: Env, usernames: string[]): Promise<void> {
  const targets = new Set(usernames);
  for (const prefix of [LOG_PREFIX, AUDIT_PREFIX]) {
    for (const key of await listAllKV(env, prefix)) {
      const entry = await env.WEBDAV_KV.get(key, "json") as { user?: string; actor?: string } | null;
      if (entry && ((entry.user && targets.has(entry.user)) || (entry.actor && targets.has(entry.actor)))) await env.WEBDAV_KV.delete(key);
    }
  }
}

// RFC 6578 sync-collection：变更记录存 KV（路径 → 最近变更序号/类型），REPORT 按序号返回增量
async function readSyncState(env: Env): Promise<SyncState> {
  try {
    const state = await env.WEBDAV_KV.get(SYNC_STATE_KEY, "json") as SyncState | null;
    if (state && Number.isFinite(state.seq) && state.changes) return state;
  } catch { }
  return { seq: 0, changes: {} };
}

async function recordSyncChange(env: Env, path: string, kind: "modified" | "deleted"): Promise<void> {
  if (!path) return;
  try {
    const state = await readSyncState(env);
    // 懒激活：默认不记录变更；仅当出现过 sync-token REPORT 客户端（见 reportMethod）后才开始写，省 KV 写入
    if (!state.activated) return;
    state.seq += 1;
    state.changes = { ...state.changes, [path]: { seq: state.seq, kind } };
    const keys = Object.keys(state.changes);
    if (keys.length > SYNC_MAX_CHANGES) {
      // 变更记录超上限时淘汰最老条目，避免无限增长
      keys.sort((a, b) => state.changes[a].seq - state.changes[b].seq);
      for (const key of keys.slice(0, keys.length - SYNC_MAX_CHANGES)) delete state.changes[key];
    }
    await env.WEBDAV_KV.put(SYNC_STATE_KEY, JSON.stringify(state));
  } catch {
    // 同步状态记录失败不影响主操作
  }
}

// Turnstile 人机校验：配置 TURNSTILE_SECRET_KEY 后公开注册强制验证
async function verifyTurnstile(env: Env, form: FormData, ip: string): Promise<boolean> {
  if (!env.TURNSTILE_SECRET_KEY) return true;
  const token = String(form.get("cf-turnstile-response") || "");
  if (!token) return false;
  try {
    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ secret: env.TURNSTILE_SECRET_KEY, response: token, remoteip: ip }).toString(),
    });
    const data = await res.json() as { success?: boolean };
    return Boolean(data.success);
  } catch {
    return false;
  }
}

// robots.txt 与 /.well-known/security.txt（RFC 9116）：搜索引擎禁引与漏洞报告联系方式
function wellKnownResponse(pathname: string, env: Env): Response {
  const body = pathname === "/robots.txt"
    ? "User-agent: *\nDisallow: /\n"
    : `Contact: ${env.SECURITY_CONTACT || "mailto:admin@example.com"}\nExpires: ${new Date(Date.now() + 7 * 86400000).toISOString().slice(0, 10)}\nPreferred-Languages: zh-CN, en\n`;
  return new Response(body, { headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "public, max-age=3600" } });
}

// 数据可携带性（GDPR/PIPL）：用户可导出自己的全部元数据为 JSON（不含文件内容与密码哈希）
async function exportUserDataResponse(env: Env, username: string): Promise<Response> {
  const account = (await getAdminAccounts(env))[username];
  const ownedAccounts = Object.values(await getWebdavAccounts(env)).filter((item) => item.owner === username);
  const ownedNames = new Set([username, ...ownedAccounts.map((item) => item.username)]);
  const logs: AccessLog[] = [];
  for (const key of await listAllKV(env, LOG_PREFIX)) {
    const log = await env.WEBDAV_KV.get(key, "json") as AccessLog | null;
    if (log && ownedNames.has(log.user)) logs.push(log);
  }
  const shares: Array<{ account?: string; path?: string; createdAt?: string; expiresAt?: string }> = [];
  for (const key of await listAllKV(env, SHARE_PREFIX)) {
    const share = await env.WEBDAV_KV.get(key, "json") as { owner?: string; account?: string; path?: string; createdAt?: string; expiresAt?: string } | null;
    if (share && share.owner === username) shares.push({ account: share.account, path: share.path, createdAt: share.createdAt, expiresAt: share.expiresAt });
  }
  const payload = {
    generatedAt: new Date().toISOString(),
    profile: { username, role: account?.role ?? "user", storageLimitBytes: account?.storageLimitBytes ?? 0, totpEnabled: Boolean(account?.totpSecret), ipAllowlist: account?.ipAllowlist ?? [] },
    webdavAccounts: ownedAccounts.map((item) => ({ username: item.username, uuid: item.uuid ?? "", url: item.url, quotaBytes: item.quotaBytes ?? 0, appPasswordCount: (item.appPasswords ?? []).length })),
    accessLogs: logs,
    shares,
  };
  return new Response(JSON.stringify(payload, null, 2), { headers: { "Content-Type": "application/json; charset=utf-8", "Content-Disposition": `attachment; filename="webdav-data-${encodeURIComponent(username)}-${new Date().toISOString().slice(0, 10)}.json"`, "Cache-Control": "no-store" } });
}

async function authenticate(request: Request, env: Env): Promise<WebdavAccount | null> {
  const header = request.headers.get("Authorization");
  if (!header?.startsWith("Basic ")) return null;
  try {
    const decoded = atob(header.slice(6));
    const separator = decoded.indexOf(":");
    if (separator < 0) return null;
    const account = await getWebdavAccountByUsername(env, decoded.slice(0, separator));
    if (!account) return null;
    const password = decoded.slice(separator + 1);
    if (await verifyPassword(password, account.passwordHash, account.salt)) return account;
    // 应用专用密码：第三方客户端用独立密码访问，主密码不外泄，可单独吊销
    for (const appEntry of account.appPasswords ?? []) {
      if (await verifyPassword(password, appEntry.passwordHash, appEntry.salt)) return account;
    }
    return null;
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
  // 用户级存储容量上限（字节），0/缺省 = 使用系统默认 USER_STORAGE_LIMIT
  storageLimitBytes?: number;
  // TOTP 两步验证密钥（base32），缺省 = 未启用
  totpSecret?: string;
  // 登录与 WebDAV 访问 IP 白名单（精确 IP / IPv4 前缀 / IPv4 CIDR），空 = 不限制
  ipAllowlist?: string[];
  // 登录状态保持时长（小时）：168=7天/72=3天/24=1天/12/1；0=关闭浏览器即注销；普通用户缺省 24，超级管理员强制 0
  sessionDurationHours?: number;
  // 超管重置密码后置位：未改密前登录仅可访问改密页，改密成功清除
  mustChangePassword?: boolean;
  // TOTP 恢复码（SHA-256 十六进制哈希，每个仅可用一次，明文只在生成时展示一次）
  recoveryCodes?: string[];
}

interface AppPasswordEntry {
  id: string;
  name: string;
  salt: string;
  passwordHash: string;
  createdAt: string;
}

interface WebdavAccount extends Credentials {
  owner: string;
  url: string;
  uuid?: string;
  // 单账户容量配额（字节），0/缺省 = 不限制（仅受用户级总上限约束）
  quotaBytes?: number;
  // 应用专用密码：第三方客户端使用，主密码不外泄，可单独吊销
  appPasswords?: AppPasswordEntry[];
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
    // env 注入的管理员仅在账户不存在时一次性引导：每请求无条件覆盖会回滚界面改密，并触发 KV 同键写冲突
    const bootstrapUsername = env.ADMIN_USERNAME?.trim();
    if (bootstrapUsername && !saved[bootstrapUsername]) {
      const salt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
      saved[bootstrapUsername] = {
        username: bootstrapUsername,
        passwordHash: await hashPassword(env.ADMIN_PASSWORD || DEFAULT_PASSWORD, salt),
        salt,
        role: "admin",
      };
      changed = true;
    }
    if (!Object.values(saved).some((account) => account.role === "admin")) {
      const salt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
      saved[DEFAULT_USERNAME] = {
        username: DEFAULT_USERNAME,
        passwordHash: await hashPassword(DEFAULT_PASSWORD, salt),
        salt,
        role: "admin",
      };
      changed = true;
    }
    if (changed) await env.WEBDAV_KV.put(ADMIN_ACCOUNTS_KEY, JSON.stringify(saved));
    return saved;
  }
  const legacy = await env.WEBDAV_KV.get(ADMIN_CREDENTIALS_KEY, "json") as AdminAccount | null;
  const defaultSalt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
  const accounts: Record<string, AdminAccount> = {
    [DEFAULT_USERNAME]: {
      username: DEFAULT_USERNAME,
      passwordHash: await hashPassword(DEFAULT_PASSWORD, defaultSalt),
      salt: defaultSalt,
      role: "admin",
    },
  };
  if (legacy?.username && legacy.passwordHash && legacy.salt && legacy.username !== DEFAULT_USERNAME) {
    accounts[legacy.username] = { ...legacy, role: "user" };
  }
  const bootstrapUsername = env.ADMIN_USERNAME?.trim();
  if (bootstrapUsername && !accounts[bootstrapUsername]) {
    const salt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
    accounts[bootstrapUsername] = {
      username: bootstrapUsername,
      passwordHash: await hashPassword(env.ADMIN_PASSWORD || DEFAULT_PASSWORD, salt),
      salt,
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
  const account = { username, owner: admin.username, url: new URL("https://example.invalid").origin, uuid: createAccountUuid(), passwordHash: legacy?.passwordHash || await hashPassword(env.WEBDAV_PASSWORD || DEFAULT_PASSWORD, legacy?.salt || "default-salt"), salt: legacy?.salt || "default-salt" };
  // 必须持久化：否则 uuid 每次请求随机变化，且每请求重复执行 PBKDF2
  await env.WEBDAV_KV.put(WEBDAV_ACCOUNTS_KEY, JSON.stringify({ [username]: account }));
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

// 用户名校验：字母数字开头结尾，允许内嵌点/下划线/短横线，禁止连续点与首尾点（用户名会进入存储前缀）
function isValidUsername(name: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}[A-Za-z0-9_-]$/.test(name) && !name.includes("..");
}

// 账户表是 KV 单键 JSON 快照，读-改-写无原生原子性：写回前重读比对快照，检测到并发修改则整体重试（最多 3 次）
async function mutateAccountTable<T>(
  env: Env,
  key: string,
  bootstrap: () => Promise<Record<string, T>>,
  transaction: (accounts: Record<string, T>) => Promise<string | null>,
): Promise<string | null> {
  for (let attempt = 0; attempt < 3; attempt++) {
    const raw = await env.WEBDAV_KV.get(key);
    const accounts = raw ? JSON.parse(raw) as Record<string, T> : await bootstrap();
    const error = await transaction(accounts);
    if (error) return error;
    if (await env.WEBDAV_KV.get(key) !== raw) continue;
    await env.WEBDAV_KV.put(key, JSON.stringify(accounts));
    return null;
  }
  return "操作繁忙，请稍后重试";
}

// 后台登录/注册防爆破：按维度计数，窗口期内达到上限即拒绝
async function checkAuthAttempts(env: Env, dimension: string, limit: number, windowSeconds: number): Promise<boolean> {
  const now = Date.now();
  const kvKey = `authlimit:${dimension}:${Math.floor(now / (windowSeconds * 1000))}`;
  const count = parseInt(await env.WEBDAV_KV.get(kvKey) || "0");
  if (count >= limit) return false;
  await env.WEBDAV_KV.put(kvKey, String(count + 1), { expirationTtl: windowSeconds });
  return true;
}

function sessionToken(request: Request): string | null {
  return request.headers.get("Cookie")?.match(/(?:^|; )cf_webdav_session=([^;]+)/)?.[1] || null;
}

// 吊销指定用户的全部会话（会话值为用户名或 { user, lastSeen } JSON）
async function revokeUserSessions(env: Env, username: string): Promise<void> {
  const sessions = await env.WEBDAV_KV.list({ prefix: SESSION_PREFIX });
  const doomed: Promise<void>[] = [];
  for (const key of sessions.keys) {
    if (sessionValueOf(await env.WEBDAV_KV.get(key.name))?.user === username) doomed.push(env.WEBDAV_KV.delete(key.name));
  }
  await Promise.all(doomed);
}

// 同一账户并发活跃会话上限：登录后超出则吊销最旧的会话（防凭证扩散）
const MAX_SESSIONS_PER_USER = 5;
async function limitUserSessions(env: Env, username: string, max: number = MAX_SESSIONS_PER_USER): Promise<void> {
  const sessions = await env.WEBDAV_KV.list({ prefix: SESSION_PREFIX });
  const owned: Array<{ name: string; lastSeen: number }> = [];
  for (const key of sessions.keys) {
    const session = sessionValueOf(await env.WEBDAV_KV.get(key.name));
    if (session?.user === username) owned.push({ name: key.name, lastSeen: session.lastSeen });
  }
  if (owned.length <= max) return;
  owned.sort((a, b) => a.lastSeen - b.lastSeen);
  await Promise.all(owned.slice(0, owned.length - max).map((item) => env.WEBDAV_KV.delete(item.name)));
}

// 列出指定用户当前全部活跃会话（按最后活跃时间倒序；name 为完整 KV 键，便于精准吊销）
async function listUserSessions(env: Env, username: string): Promise<Array<{ name: string; lastSeen: number; exp?: number }>> {
  const sessions = await env.WEBDAV_KV.list({ prefix: SESSION_PREFIX });
  const owned: Array<{ name: string; lastSeen: number; exp?: number }> = [];
  for (const key of sessions.keys) {
    const session = sessionValueOf(await env.WEBDAV_KV.get(key.name));
    if (session?.user === username) owned.push({ name: key.name, lastSeen: session.lastSeen, exp: session.exp });
  }
  return owned.sort((a, b) => b.lastSeen - a.lastSeen);
}

async function sha256Hex(value: string): Promise<string> {
  const bits = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(bits)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

// 生成 10 个 8 位十六进制恢复码（明文仅展示一次，服务端只存 SHA-256 哈希）
function generateRecoveryCodes(): string[] {
  return Array.from({ length: 10 }, () => [...crypto.getRandomValues(new Uint8Array(4))].map((byte) => byte.toString(16).padStart(2, "0")).join(""));
}

// 登录时尝试消费一个恢复码：匹配即从账户表移除该哈希并放行
async function consumeRecoveryCode(env: Env, username: string, code: string): Promise<boolean> {
  const normalized = code.trim().toLowerCase();
  if (!/^[0-9a-f]{8}$/.test(normalized)) return false;
  const hash = await sha256Hex(normalized);
  let consumed = false;
  await mutateAccountTable<AdminAccount>(env, ADMIN_ACCOUNTS_KEY, () => getAdminAccounts(env), async (accounts) => {
    const account = accounts[username];
    if (!account?.recoveryCodes?.includes(hash)) return "恢复码不匹配";
    accounts[username] = { ...account, recoveryCodes: account.recoveryCodes.filter((item) => item !== hash) };
    consumed = true;
    return null;
  });
  return consumed;
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
      if (["get", "put", "head", "delete"].includes(String(property))) return (...args: unknown[]) => {
        // delete 支持键名数组批量删除：需对数组每个元素分别加前缀，否则整组会被拼成一个非法键名
        if (property === "delete" && Array.isArray(args[0])) {
          return (target.delete as Function).call(target, (args[0] as string[]).map((key) => `${scope}/r2/${key}`), ...args.slice(1));
        }
        return (target[property as "get" | "put" | "head" | "delete"] as Function).call(target, `${scope}/r2/${args[0]}`, ...args.slice(1));
      };
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
    // 登出必须吊销服务端会话，仅清 cookie 会让泄露的 token 继续有效
    const token = sessionToken(request);
    if (token) await env.WEBDAV_KV.delete(`${SESSION_PREFIX}${token}`);
    return new Response(null, { status: 303, headers: { Location: "/", "Set-Cookie": "cf_webdav_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0" } });
  }
  if (url.pathname === "/__admin/register") {
    if (env.ENABLE_PUBLIC_REGISTRATION === "false") return adminLoginPage("注册已关闭，请联系管理员创建账户");
    if (request.method === "GET") return adminRegisterPage(env);
    // 公开注册按 IP 限频，防止恶意占满账户名额
    const registerIp = request.headers.get("CF-Connecting-IP") || "unknown";
    if (!(await checkAuthAttempts(env, `register:${registerIp}`, 5, 3600))) return adminRegisterPage(env, "注册尝试过于频繁，请一小时后再试");
    const form = await request.formData();
    // Turnstile 人机校验：配置 TURNSTILE_SECRET_KEY 后强制验证，防自动化滥用
    if (!(await verifyTurnstile(env, form, registerIp))) return adminRegisterPage(env, "人机验证未通过，请重试");
    const username = String(form.get("username") || "").trim();
    const password = String(form.get("password") || "");
    const confirmPassword = String(form.get("confirmPassword") || "");
    if (!isValidUsername(username)) return adminRegisterPage(env, "用户名格式不正确");
    const registerPasswordError = passwordPolicyError(env, password);
    if (registerPasswordError) return adminRegisterPage(env, registerPasswordError);
    if (password !== confirmPassword) return adminRegisterPage(env, "两次输入的密码不一致");
    const registerError = await mutateAccountTable<AdminAccount>(env, ADMIN_ACCOUNTS_KEY, () => getAdminAccounts(env), async (accounts) => {
      if (accounts[username]) return "用户账户已存在";
      if (Object.keys(accounts).length >= 10) return "账户最多创建 10 个";
      const salt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
      accounts[username] = { username, salt, passwordHash: await hashPassword(password, salt), role: "user" };
      return null;
    });
    if (registerError) return adminRegisterPage(env, registerError);
    await logAudit(env, { actor: username, action: "register", target: username, clientIp: registerIp });
    return adminLoginPage("注册成功，请使用新账户登录");
  }
  if (url.pathname === "/__admin/login" && request.method === "POST") {
    const form = await request.formData();
    const username = String(form.get("username") ?? "");
    const password = String(form.get("password") ?? "");
    // 登录防爆破参数可配置（LOGIN_MAX_ATTEMPTS / LOGIN_LOCK_MINUTES）
    const lock = getLoginLockConfig(env);
    const lockMessage = `尝试次数过多，请 ${Math.ceil(lock.windowSeconds / 60)} 分钟后再试`;
    const credentials = (await getAdminAccounts(env))[username];
    if (!credentials || !(await verifyPassword(password, credentials.passwordHash, credentials.salt))) {
      // 登录失败按 IP+用户名限频，防止暴力破解
      const loginIp = clientIpOf(request);
      if (!(await checkAuthAttempts(env, `login:${loginIp}:${username}`, lock.maxAttempts, lock.windowSeconds))) return adminLoginPage(lockMessage);
      return adminLoginPage("用户名或密码错误");
    }
    const loginIp = clientIpOf(request);
    // IP 白名单：密码验证通过后仍需校验来源 IP，未配置则不限制
    if (!ipAllowed(loginIp, credentials.ipAllowlist ?? [])) {
      if (!(await checkAuthAttempts(env, `login:${loginIp}:${username}`, lock.maxAttempts, lock.windowSeconds))) return adminLoginPage(lockMessage);
      return adminLoginPage("当前 IP 不在该账户的访问白名单内");
    }
    // TOTP 两步验证：已绑定的账户需输入验证器动态码；动态码错误时尝试一次性恢复码
    if (credentials.totpSecret) {
      const totpCode = String(form.get("totpCode") || "");
      if (!(await verifyTotp(credentials.totpSecret, totpCode)) && !(await consumeRecoveryCode(env, username, totpCode))) {
        if (!(await checkAuthAttempts(env, `login:${loginIp}:${username}`, lock.maxAttempts, lock.windowSeconds))) return adminLoginPage(lockMessage);
        return adminLoginPage("两步验证码错误或已过期");
      }
    }
    // 会话记录最后活跃时间（支持 SESSION_IDLE_MINUTES 空闲超时）；保持时长由用户在用户管理页自选
    const token = bytesToBase64(crypto.getRandomValues(new Uint8Array(32)));
    // sessionDurationHours = 0 时不设 Max-Age：Cookie 成为浏览器会话 Cookie，关闭浏览器即注销；KV 以 7 天兜底过期
    // 超级管理员会话强制“关闭浏览器即注销”；普通用户自选（缺省 1 天）
    const sessionHours = credentials.role === "admin" ? 0 : credentials.sessionDurationHours ?? 24;
    const sessionTtl = sessionHours > 0 ? Math.max(3600, Math.round(sessionHours * 3600)) : SESSION_TTL;
    // exp 为绝对过期毫秒时间戳：KV TTL 可被刷新重写，绝对时间保证“保持时长”语义不被活跃请求延长
    await env.WEBDAV_KV.put(`${SESSION_PREFIX}${token}`, JSON.stringify({ user: username, lastSeen: Date.now(), exp: Date.now() + sessionTtl * 1000, role: credentials.role === "admin" ? "admin" : "user" }), { expirationTtl: sessionTtl });
    // 并发会话上限：超出则吊销最旧会话
    await limitUserSessions(env, username);
    await logAudit(env, { actor: username, action: "login", target: username, clientIp: loginIp });
    // 超管重置过密码的账户：登录后强制进入改密页
    const loginRedirect = credentials.mustChangePassword ? "/?view=change-password" : "/";
    const sessionCookie = `cf_webdav_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/${sessionHours > 0 ? `; Max-Age=${sessionTtl}` : ""}`;
    return new Response(null, { status: 303, headers: { Location: loginRedirect, "Set-Cookie": sessionCookie } });
  }
  // 会话诊断：展示当前请求是否携带 Cookie 与服务端会话状态，用于定位“Cookie 存在但仍要求登录”类问题
  const sessionUser_ = await sessionUser(request, env);
  if (!sessionUser_) return adminLoginPage();
  const sessionAccount = (await getAdminAccounts(env))[sessionUser_];
  // 会话级 IP 白名单校验：启用白名单后，来自非信任 IP 的已登录会话同样拒绝（覆盖超管与普通用户路径）
  if (sessionAccount && !ipAllowed(clientIpOf(request), sessionAccount.ipAllowlist ?? [])) return textResponse("Forbidden: 当前 IP 不在该账户的访问白名单内", 403);
  if (sessionAccount?.role === "admin") return superAdminRequest(request, env, sessionAccount);
  const view = url.searchParams.get("view") || "home";
  // 强制改密门禁：超管重置过密码的账户，改密成功前仅可访问安全设置页
  if (sessionAccount?.mustChangePassword && view !== "change-password") {
    return new Response(null, { status: 303, headers: { Location: "/?view=change-password" } });
  }
  // 新增：用户级修改密码页面（需校验当前密码，仅普通用户可用）
  if (request.method === "GET" && view === "change-password") {
    return adminChangePasswordPage(env, sessionUser_, "", "", "", [], sessionToken(request) ?? "");
  }
  if (request.method === "POST" && (isRoot || url.pathname === "/__admin") && view === "change-password") {
    const form = await request.formData();
    if (String(form.get("action") || "") === "change-own-password") {
      const currentPassword = String(form.get("currentPassword") || "");
      const newPassword = String(form.get("newPassword") || "");
      const confirmPassword = String(form.get("confirmPassword") || "");
      if (!sessionAccount || !(await verifyPassword(currentPassword, sessionAccount.passwordHash, sessionAccount.salt))) return adminChangePasswordPage(env, sessionUser_, "", "当前密码不正确");
      const ownPasswordError = passwordPolicyError(env, newPassword);
      if (ownPasswordError) return adminChangePasswordPage(env, sessionUser_, "", ownPasswordError);
      if (newPassword !== confirmPassword) return adminChangePasswordPage(env, sessionUser_, "", "两次输入的新密码不一致");
      if (newPassword === currentPassword) return adminChangePasswordPage(env, sessionUser_, "", "新密码不能与当前密码相同");
      const changeError = await mutateAccountTable<AdminAccount>(env, ADMIN_ACCOUNTS_KEY, () => getAdminAccounts(env), async (accounts) => {
        const account = accounts[sessionUser_];
        if (!account) return "账户不存在";
        const salt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
        accounts[sessionUser_] = { ...account, username: sessionUser_, salt, passwordHash: await hashPassword(newPassword, salt), mustChangePassword: undefined };
        return null;
      });
      if (changeError) return adminChangePasswordPage(env, sessionUser_, "", changeError);
      await logAudit(env, { actor: sessionUser_, action: "change-own-password", target: sessionUser_, clientIp: clientIpOf(request) });
      // 改密后吊销该用户全部会话（含当前），要求用新密码重新登录
      await revokeUserSessions(env, sessionUser_);
      return new Response(null, { status: 303, headers: { Location: "/__admin/login", "Set-Cookie": "cf_webdav_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0" } });
    } else if (String(form.get("action") || "") === "totp-setup-start") {
      const secret = generateTotpSecret();
      await env.WEBDAV_KV.put(`${TOTP_PENDING_PREFIX}${sessionUser_}`, secret, { expirationTtl: 600 });
      return adminChangePasswordPage(env, sessionUser_, "", "", secret);
    } else if (String(form.get("action") || "") === "totp-setup-confirm") {
      const secret = await env.WEBDAV_KV.get(`${TOTP_PENDING_PREFIX}${sessionUser_}`);
      if (!secret) return adminChangePasswordPage(env, sessionUser_, "", "绑定会话已过期，请重新新增令牌");
      if (!(await verifyTotp(secret, String(form.get("totpCode") || "")))) return adminChangePasswordPage(env, sessionUser_, "", "验证码错误，请确认验证器时间与密钥后重试", secret);
      // 每次绑定生成 10 个一次性恢复码：服务端只存 SHA-256 哈希，明文仅在绑定成功的响应中展示一次
      const recoveryCodes = generateRecoveryCodes();
      const recoveryHashes = await Promise.all(recoveryCodes.map((code) => sha256Hex(code)));
      const bindError = await mutateAccountTable<AdminAccount>(env, ADMIN_ACCOUNTS_KEY, () => getAdminAccounts(env), async (accounts) => {
        const account = accounts[sessionUser_];
        if (!account) return "账户不存在";
        accounts[sessionUser_] = { ...account, totpSecret: secret, recoveryCodes: recoveryHashes };
        return null;
      });
      await env.WEBDAV_KV.delete(`${TOTP_PENDING_PREFIX}${sessionUser_}`);
      return bindError ? adminChangePasswordPage(env, sessionUser_, "", bindError) : adminChangePasswordPage(env, sessionUser_, "TOTP 令牌已绑定，下次登录需输入验证器动态码", "", "", recoveryCodes, sessionToken(request) ?? "");
    } else if (String(form.get("action") || "") === "totp-disable") {
      const current = (await getAdminAccounts(env))[sessionUser_];
      if (!current?.totpSecret) return adminChangePasswordPage(env, sessionUser_, "", "尚未启用两步验证");
      if (!(await verifyTotp(current.totpSecret, String(form.get("totpCode") || "")))) return adminChangePasswordPage(env, sessionUser_, "", "验证码错误，无法删除令牌");
      const disableError = await mutateAccountTable<AdminAccount>(env, ADMIN_ACCOUNTS_KEY, () => getAdminAccounts(env), async (accounts) => {
        const account = accounts[sessionUser_];
        if (!account) return "账户不存在";
        accounts[sessionUser_] = { ...account, totpSecret: undefined, recoveryCodes: undefined };
        return null;
      });
      return disableError ? adminChangePasswordPage(env, sessionUser_, "", disableError) : adminChangePasswordPage(env, sessionUser_, "TOTP 令牌已删除，登录仅需密码");
    } else if (String(form.get("action") || "") === "logout-others") {
      // 活跃会话管理：保留当前会话，吊销该用户其余全部会话
      const currentToken = sessionToken(request) ?? "";
      const sessions = await listUserSessions(env, sessionUser_);
      const others = sessions.filter((session) => session.name !== `${SESSION_PREFIX}${currentToken}`);
      await Promise.all(others.map((session) => env.WEBDAV_KV.delete(session.name)));
      await logAudit(env, { actor: sessionUser_, action: "logout-others", target: sessionUser_, clientIp: clientIpOf(request), detail: `吊销 ${others.length} 个其他会话` });
      return adminChangePasswordPage(env, sessionUser_, others.length ? `已登出其他 ${others.length} 个会话` : "当前没有其他活跃会话", "", "", [], currentToken);
    }
  }
  // 账户安全设置：TOTP 两步验证绑定/解绑 + IP 白名单
  if (request.method === "GET" && view === "security") return securityPage(request, env, sessionUser_);
  if (request.method === "POST" && (isRoot || url.pathname === "/__admin") && view === "security") {
    const form = await request.formData();
    const securityAction = String(form.get("action") || "");
    if (securityAction === "totp-setup-start") {
      const secret = generateTotpSecret();
      // 待绑定密钥仅存 10 分钟，确认码验证通过后才写入账户
      await env.WEBDAV_KV.put(`${TOTP_PENDING_PREFIX}${sessionUser_}`, secret, { expirationTtl: 600 });
      return securityPage(request, env, sessionUser_, { pendingSecret: secret });
    }
    if (securityAction === "totp-setup-confirm") {
      const secret = await env.WEBDAV_KV.get(`${TOTP_PENDING_PREFIX}${sessionUser_}`);
      if (!secret) return securityPage(request, env, sessionUser_, { error: "绑定会话已过期，请重新生成密钥" });
      if (!(await verifyTotp(secret, String(form.get("totpCode") || "")))) return securityPage(request, env, sessionUser_, { pendingSecret: secret, error: "验证码错误，请确认验证器时间与密钥后重试" });
      // 每次绑定生成 10 个一次性恢复码：服务端只存 SHA-256 哈希，明文仅在绑定成功的响应中展示一次
      const recoveryCodes = generateRecoveryCodes();
      const recoveryHashes = await Promise.all(recoveryCodes.map((code) => sha256Hex(code)));
      const bindError = await mutateAccountTable<AdminAccount>(env, ADMIN_ACCOUNTS_KEY, () => getAdminAccounts(env), async (accounts) => {
        const account = accounts[sessionUser_];
        if (!account) return "账户不存在";
        accounts[sessionUser_] = { ...account, totpSecret: secret, recoveryCodes: recoveryHashes };
        return null;
      });
      await env.WEBDAV_KV.delete(`${TOTP_PENDING_PREFIX}${sessionUser_}`);
      if (!bindError) await logAudit(env, { actor: sessionUser_, action: "totp-enable", target: sessionUser_, clientIp: clientIpOf(request) });
      return bindError ? securityPage(request, env, sessionUser_, { error: bindError }) : securityPage(request, env, sessionUser_, { message: "两步验证已启用， 下次登录需输入验证器动态码", recoveryCodes });
    }
    if (securityAction === "totp-disable") {
      const current = (await getAdminAccounts(env))[sessionUser_];
      if (!current?.totpSecret) return securityPage(request, env, sessionUser_, { error: "尚未启用两步验证" });
      if (!(await verifyTotp(current.totpSecret, String(form.get("totpCode") || "")))) return securityPage(request, env, sessionUser_, { error: "验证码错误，无法解除绑定" });
      const disableError = await mutateAccountTable<AdminAccount>(env, ADMIN_ACCOUNTS_KEY, () => getAdminAccounts(env), async (accounts) => {
        const account = accounts[sessionUser_];
        if (!account) return "账户不存在";
        accounts[sessionUser_] = { ...account, totpSecret: undefined, recoveryCodes: undefined };
        return null;
      });
      if (!disableError) await logAudit(env, { actor: sessionUser_, action: "totp-disable", target: sessionUser_, clientIp: clientIpOf(request) });
      return disableError ? securityPage(request, env, sessionUser_, { error: disableError }) : securityPage(request, env, sessionUser_, { message: "两步验证已关闭" });
    }
    if (securityAction === "ip-allowlist-save") {
      const entries = String(form.get("allowlist") || "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
      if (entries.length > 50) return securityPage(request, env, sessionUser_, { error: "白名单最多 50 条" });
      const invalid = entries.find((entry) => !isValidAllowlistEntry(entry));
      if (invalid) return securityPage(request, env, sessionUser_, { error: `白名单条目格式不正确：${invalid}` });
      // 防自锁：保存后必须仍包含当前来源 IP（本地开发无法获取真实 IP 时跳过该校验）
      const clientIp = clientIpOf(request);
      if (entries.length && clientIp !== "unknown" && !ipAllowed(clientIp, entries)) return securityPage(request, env, sessionUser_, { error: `当前 IP ${clientIp} 不在新白名单内，保存会将自己锁在账户外，请补充后重试` });
      const allowError = await mutateAccountTable<AdminAccount>(env, ADMIN_ACCOUNTS_KEY, () => getAdminAccounts(env), async (accounts) => {
        const account = accounts[sessionUser_];
        if (!account) return "账户不存在";
        accounts[sessionUser_] = { ...account, ipAllowlist: entries };
        return null;
      });
      if (!allowError) await logAudit(env, { actor: sessionUser_, action: "ip-allowlist-save", target: sessionUser_, clientIp: clientIpOf(request), detail: entries.length ? `${entries.length} 条规则` : "已清空" });
      return allowError ? securityPage(request, env, sessionUser_, { error: allowError }) : securityPage(request, env, sessionUser_, { message: entries.length ? "IP 白名单已更新" : "IP 白名单已清空（不再限制登录与 WebDAV 来源）" });
    }
  }
  if (request.method === "POST" && (isRoot || url.pathname === "/__admin")) {
    // 流式上传：必须在 formData 解析前拦截（formData 会整体缓冲请求体），请求体直接管道到 R2
    if (url.searchParams.get("action") === "upload-stream") {
      const uploadAccount = (await getWebdavAccounts(env))[String(url.searchParams.get("account") || "")];
      if (!uploadAccount || uploadAccount.owner !== sessionUser_) return textResponse("请选择有权访问的 WebDAV 账户", 403);
      return adminUploadStream(request, env, uploadAccount, url);
    }
    const form = await request.formData();
    const action = String(form.get("action") || "");
    const adminUsername = sessionUser_;
    const webdavAccounts = await getWebdavAccounts(env);
    const ownedAccounts = Object.values(webdavAccounts).filter((account) => account.owner === adminUsername);
    if (action === "save-user-password") {
      const password = String(form.get("userPassword") || "");
      const userPasswordError = passwordPolicyError(env, password);
      if (userPasswordError) return await adminPage(request, env, userPasswordError);
      // 必须已存在：无条件 upsert 会让已删除账户凭旧会话复活
      const saveError = await mutateAccountTable<AdminAccount>(env, ADMIN_ACCOUNTS_KEY, () => getAdminAccounts(env), async (accounts) => {
        const account = accounts[adminUsername];
        if (!account) return "账户不存在";
        const salt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
        accounts[adminUsername] = { ...account, salt, passwordHash: await hashPassword(password, salt), role: "user" };
        return null;
      });
      if (saveError) return await adminPage(request, env, saveError);
      await logAudit(env, { actor: adminUsername, action: "save-user-password", target: adminUsername, clientIp: clientIpOf(request) });
      return await adminPage(request, env, "密码已更新");
    }
    if (action === "create-admin" || action === "save-admin") return textResponse("普通用户无权执行管理员操作", 403);
    // 登录状态自选（7天/3天/1天/12小时/1小时/关闭浏览器即注销）；保存后当前会话立即按新时长调整
    if (action === "set-session-duration") {
      const allowedHours = [168, 72, 24, 12, 1, 0];
      const sessionHours = Number(form.get("sessionHours"));
      if (!allowedHours.includes(sessionHours)) return await adminPage(request, env, "登录状态时长不合法");
      const durationError = await mutateAccountTable<AdminAccount>(env, ADMIN_ACCOUNTS_KEY, () => getAdminAccounts(env), async (accounts) => {
        const account = accounts[adminUsername];
        if (!account) return "账户不存在";
        accounts[adminUsername] = { ...account, sessionDurationHours: sessionHours };
        return null;
      });
      if (durationError) return await adminPage(request, env, durationError);
      await logAudit(env, { actor: adminUsername, action: "set-session-duration", target: adminUsername, clientIp: clientIpOf(request), detail: sessionHours > 0 ? `${sessionHours} 小时` : "关闭浏览器即注销" });
      // 立即应用到当前会话：Cookie 与 KV TTL 同步刷新；0 时改为浏览器会话 Cookie（关闭浏览器即注销）
      const currentToken = sessionToken(request);
      const sessionRaw = currentToken ? await env.WEBDAV_KV.get(`${SESSION_PREFIX}${currentToken}`) : null;
      if (currentToken && sessionRaw) {
        if (sessionHours > 0) {
          const ttl = Math.max(3600, Math.round(sessionHours * 3600));
          await env.WEBDAV_KV.put(`${SESSION_PREFIX}${currentToken}`, JSON.stringify({ user: adminUsername, lastSeen: Date.now(), exp: Date.now() + ttl * 1000 }), { expirationTtl: ttl });
          return new Response(null, { status: 303, headers: { Location: "/", "Set-Cookie": `cf_webdav_session=${currentToken}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${ttl}` } });
        }
        await env.WEBDAV_KV.put(`${SESSION_PREFIX}${currentToken}`, JSON.stringify({ user: adminUsername, lastSeen: Date.now(), exp: Date.now() + SESSION_TTL * 1000 }), { expirationTtl: SESSION_TTL });
        return new Response(null, { status: 303, headers: { Location: "/", "Set-Cookie": `cf_webdav_session=${currentToken}; HttpOnly; Secure; SameSite=Lax; Path=/` } });
      }
      return await adminPage(request, env, "登录状态已更新");
    }
    if (action === "create-webdav") {
      const username = String(form.get("serviceUsername") || "").trim();
      const password = String(form.get("servicePassword") || "");
      const uuid = String(form.get("accountUuid") || "").trim();
      const createPasswordError = passwordPolicyError(env, password);
      if (createPasswordError) return await adminPage(request, env, createPasswordError);
      if (!/^\d{6}$/.test(uuid)) return await adminPage(request, env, "UUID 必须是 6 位数字");
      // 查重与写入同事务，消除并发下的重名/同 UUID TOCTOU
      const createError = await mutateAccountTable<WebdavAccount>(env, WEBDAV_ACCOUNTS_KEY, () => getWebdavAccounts(env), async (accounts) => {
        if (Object.values(accounts).filter((account) => account.owner === adminUsername).length >= 2) return "每个管理员最多只能拥有 2 个 WebDAV 账户";
        if (accounts[username]) return "WebDAV 账户名已存在，请换一个";
        if (!isValidUsername(username)) return "WebDAV 账户名格式不正确";
        if (Object.values(accounts).some((account) => account.uuid === uuid)) return "UUID 已存在，请换一个";
        const salt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
        const account: WebdavAccount = { username, owner: adminUsername, uuid, url: "", salt, passwordHash: await hashPassword(password, salt) };
        account.url = webdavAccountUrl(request, account);
        accounts[username] = account;
        return null;
      });
      return createError ? await adminPage(request, env, createError) : (await logAudit(env, { actor: adminUsername, action: "create-webdav", target: username, clientIp: clientIpOf(request) }), await adminPage(request, env, "WebDAV 账户已创建"));
    }
    if (action === "delete-webdav") {
      const accountUsername = String(form.get("accountUsername") || "");
      const account = webdavAccounts[accountUsername];
      if (!account || account.owner !== adminUsername) return textResponse("无权删除该 WebDAV 账户", 403);
      await deleteWebdavAccountData(env, account);
      const deleteError = await mutateAccountTable<WebdavAccount>(env, WEBDAV_ACCOUNTS_KEY, () => getWebdavAccounts(env), async (accounts) => {
        delete accounts[accountUsername];
        return null;
      });
      if (deleteError) return await adminPage(request, env, deleteError);
      await logAudit(env, { actor: adminUsername, action: "delete-webdav", target: accountUsername, clientIp: clientIpOf(request) });
      return await adminPage(request, env, "WebDAV 账户及其全部文件已删除");
    }
    if (action === "save-service") {
      const accountUsername = String(form.get("accountUsername") || ownedAccounts[0]?.username || "");
      const account = webdavAccounts[accountUsername];
      if (!account || account.owner !== adminUsername) return await adminPage(request, env, "无权修改该 WebDAV 账户");
      // 账户名是存储前缀（storageScope）的组成部分，改名会导致名下全部数据不可达，因此禁止修改
      const service = {
        password: String(form.get("servicePassword") || ""),
        uuid: String(form.get("accountUuid") || "").trim(),
      };
      if (!/^\d{6}$/.test(service.uuid)) return await adminPage(request, env, "UUID 必须是 6 位数字");
      const servicePasswordError = passwordPolicyError(env, service.password);
      if (servicePasswordError) return await adminPage(request, env, servicePasswordError);
      // 单账户配额（GB，0 = 不限制）；上限取超管为本用户设置的容量上限（默认 10 GB），超出则拒绝
      const quotaGb = Number(form.get("quotaGb") || "0");
      const quotaCeilingGb = (await getUserStorageLimit(env, adminUsername)) / 1024 ** 3;
      if (!Number.isFinite(quotaGb) || quotaGb < 0 || quotaGb > quotaCeilingGb) return await adminPage(request, env, `配额必须介于 0（不限制）与 ${quotaCeilingGb % 1 === 0 ? quotaCeilingGb.toFixed(0) : quotaCeilingGb} GB 之间`);
      const saveError = await mutateAccountTable<WebdavAccount>(env, WEBDAV_ACCOUNTS_KEY, () => getWebdavAccounts(env), async (accounts) => {
        if (Object.values(accounts).some((item) => item.uuid === service.uuid && item.username !== accountUsername)) return "UUID 已存在，请换一个";
        const target = accounts[accountUsername];
        if (!target) return "WebDAV 账户不存在";
        const salt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
        target.uuid = service.uuid;
        target.salt = salt;
        target.passwordHash = await hashPassword(service.password, salt);
        target.url = webdavAccountUrl(request, target);
        target.quotaBytes = quotaGb > 0 ? Math.round(quotaGb * 1024 ** 3) : 0;
        return null;
      });
      return saveError ? await adminPage(request, env, saveError) : await adminPage(request, env, "服务连接信息已保存");
    }
    if (action === "create-app-password") {
      const accountUsername = String(form.get("accountUsername") || ownedAccounts[0]?.username || "");
      const account = webdavAccounts[accountUsername];
      if (!account || account.owner !== adminUsername) return textResponse("无权修改该 WebDAV 账户", 403);
      const appName = String(form.get("appName") || "").trim().slice(0, 32);
      if (!appName) return adminAccountPage(request, env, account, "", "请填写用途名称");
      const plain = bytesToBase64(crypto.getRandomValues(new Uint8Array(18)));
      const entrySalt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
      const entry = { id: crypto.randomUUID(), name: appName, salt: entrySalt, passwordHash: await hashPassword(plain, entrySalt), createdAt: new Date().toISOString() };
      const createError = await mutateAccountTable<WebdavAccount>(env, WEBDAV_ACCOUNTS_KEY, () => getWebdavAccounts(env), async (accounts) => {
        const target = accounts[accountUsername];
        if (!target) return "WebDAV 账户不存在";
        if ((target.appPasswords?.length ?? 0) >= MAX_APP_PASSWORDS) return `应用密码最多 ${MAX_APP_PASSWORDS} 个，请先吊销不再使用的密码`;
        target.appPasswords = [...(target.appPasswords ?? []), entry];
        return null;
      });
      return createError ? adminAccountPage(request, env, account, "", createError) : adminAccountPage(request, env, (await getWebdavAccounts(env))[accountUsername] ?? account, plain);
    }
    if (action === "revoke-app-password") {
      const accountUsername = String(form.get("accountUsername") || ownedAccounts[0]?.username || "");
      const account = webdavAccounts[accountUsername];
      if (!account || account.owner !== adminUsername) return textResponse("无权修改该 WebDAV 账户", 403);
      const appId = String(form.get("appId") || "");
      const revokeError = await mutateAccountTable<WebdavAccount>(env, WEBDAV_ACCOUNTS_KEY, () => getWebdavAccounts(env), async (accounts) => {
        const target = accounts[accountUsername];
        if (!target) return "WebDAV 账户不存在";
        target.appPasswords = (target.appPasswords ?? []).filter((item) => item.id !== appId);
        return null;
      });
      return revokeError ? adminAccountPage(request, env, account, "", revokeError) : adminAccountPage(request, env, account);
    }
    if (action === "save-admin") {
      const username = String(form.get("adminUsername") || "").trim();
      const password = String(form.get("adminPassword") || "");
      if (!/^[A-Za-z0-9._-]{2,64}$/.test(username)) return await adminPage(request, env, "管理员账户须为 2-64 位字母、数字、点、下划线或短横线");
      const adminPasswordError = passwordPolicyError(env, password);
      if (adminPasswordError) return await adminPage(request, env, adminPasswordError);
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
      return new Response(null, { status: 303, headers: { Location: "/", "Set-Cookie": "cf_webdav_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0" } });
    }
    if (view === "files" && ["upload", "delete", "mkdir", "batch-delete", "batch-move", "create-share", "revoke-share", "copy-file"].includes(action)) {
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
      const logOperation = (method: string, operationPath: string) => logAccess(env, { method, path: operationPath, status: 200, clientIp, userAgent, user: adminUsername });
      if (action === "empty") {
        await emptyTrash(scopedEnv);
        await logOperation("DELETE", "__trash/*");
      } else if (action === "purge") {
        const paths = form.getAll("paths").map(String).filter(Boolean);
        for (const trashKey of paths) await purgeFromTrash(scopedEnv, trashKey);
        for (const trashKey of paths) await logOperation("DELETE", decodeTrashKeyName(trashKey));
      } else if (action === "restore") {
        const paths = form.getAll("paths").map(String).filter(Boolean);
        const restoredPaths = paths.length ? paths : [String(form.get("path") || "")].filter(Boolean);
        let conflictCount = 0;
        for (const trashKey of restoredPaths) {
          const result = await restoreFromTrash(scopedEnv, trashKey, selected, env);
          if (result.status !== 204) conflictCount++;
        }
        for (const trashKey of restoredPaths) await logOperation("PUT", decodeTrashKeyName(trashKey));
        return new Response(null, { status: 303, headers: { Location: `/?view=trash&account=${encodeURIComponent(selected.username)}${conflictCount ? "&warn=conflict" : ""}` } });
      }
      return new Response(null, { status: 303, headers: { Location: `/?view=trash&account=${encodeURIComponent(selected.username)}` } });
    }
  }
  // 文件在线预览：api=preview 返回原始内容（图片/文本内联，dl=1 下载）；view=preview 渲染预览页
  if (url.searchParams.get("api") === "preview" && request.method === "GET") {
    const previewAccount = (await getWebdavAccounts(env))[String(url.searchParams.get("account") || "")];
    if (!previewAccount || previewAccount.owner !== sessionUser_) return textResponse("Forbidden", 403);
    return servePreviewRaw(request, env, previewAccount, url);
  }
  // 数据可携带性：导出当前用户自己的元数据（资料、账户、访问日志、分享），不含文件内容与凭证
  if (url.searchParams.get("api") === "export-data" && request.method === "GET") return exportUserDataResponse(env, sessionUser_);
  // 心跳：已登录页面定时调用，刷新 lastSeen 以维持空闲超时计时（页面关闭后心跳停止，超时即吊销）
  if (url.searchParams.get("api") === "heartbeat" && request.method === "GET") return new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
  // 新增：访问日志页面
  if (url.pathname === "/__admin/logs") {
    if (request.method !== "GET") return textResponse("Method Not Allowed", 405);
    const ownedNames = Object.values(await getWebdavAccounts(env)).filter((account) => account.owner === sessionUser_).map((account) => account.username);
    return view === "logs" ? adminLogsPage(request, env, [sessionUser_, ...ownedNames], "/__admin/logs") : adminPage(request, env);
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
  const requestedAccount = url.searchParams.get("account") || (view === "account" || view === "files" || view === "logs" || view === "trash" || view === "preview" ? ownedAccountList[0]?.username : "");
  const selectedAccount = (await getWebdavAccounts(env))[requestedAccount || ""];
  if (selectedAccount && selectedAccount.owner !== sessionUser_) return textResponse("Forbidden", 403);
  if (view === "account") return selectedAccount ? adminAccountPage(request, env, selectedAccount) : adminPage(request, env, "请先选择 WebDAV 账户");
  if (view === "logs") return adminLogsPage(request, env, [sessionUser_, ...ownedAccountList.map((account) => account.username)], "/?", { view: "logs" });
  if (view === "preview") return selectedAccount ? adminPreviewPage(request, env, selectedAccount) : adminPage(request, env, "请先选择 WebDAV 账户");
  if (view === "files") return selectedAccount ? adminFilesPage(request, createScopedEnv(env, storageScope(selectedAccount)), selectedAccount, env) : adminPage(request, env, "请先选择 WebDAV 账户");
  if (view === "trash") return selectedAccount ? adminTrashPage(createScopedEnv(env, storageScope(selectedAccount)), selectedAccount.username) : adminPage(request, env, "请先选择 WebDAV 账户");
  if (view === "accounts") return adminPage(request, env);
  if (request.method !== "GET") return textResponse("Method Not Allowed", 405);
  return adminPage(request, env);
}

async function superAdminRequest(request: Request, env: Env, currentAdmin: AdminAccount): Promise<Response> {
  const url = new URL(request.url);
  // 审计日志：仅超管可查看与导出（CSV），普通用户不可见不可删
  if (request.method === "GET" && url.searchParams.get("view") === "audit") {
    if (url.searchParams.get("export") === "csv") return auditCsvResponse(env);
    return adminAuditPage(env, url);
  }
  // 超级管理员可查看全量访问日志
  if (request.method === "GET" && url.searchParams.get("view") === "logs") return adminLogsPage(request, env, [], "/__admin/logs", { view: "logs" });
  if (request.method !== "POST") return superAdminPage(env, "");
  const form = await request.formData();
  const action = String(form.get("action") || "");
  const accounts = await getAdminAccounts(env);
  if (action === "save-admin-password") {
    const password = String(form.get("adminPassword") || "");
    const adminPwError = passwordPolicyError(env, password);
    if (adminPwError) return superAdminPage(env, adminPwError);
    const saveError = await mutateAccountTable<AdminAccount>(env, ADMIN_ACCOUNTS_KEY, () => getAdminAccounts(env), async (accounts) => {
      const account = accounts[currentAdmin.username];
      if (!account) return "账户不存在";
      const salt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
      accounts[currentAdmin.username] = { ...account, salt, passwordHash: await hashPassword(password, salt), role: "admin" };
      return null;
    });
    if (saveError) return superAdminPage(env, saveError);
    await logAudit(env, { actor: currentAdmin.username, action: "save-admin-password", target: currentAdmin.username, clientIp: clientIpOf(request) });
    // 改密后吊销全部会话（含当前），要求用新密码重新登录
    await revokeUserSessions(env, currentAdmin.username);
    return new Response(null, { status: 303, headers: { Location: "/__admin/login", "Set-Cookie": "cf_webdav_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0" } });
  }
  if (action === "create-user") {
    const username = String(form.get("userUsername") || "").trim();
    const password = String(form.get("userPassword") || "");
    const confirmPassword = String(form.get("userPasswordConfirm") || "");
    const createUserPasswordError = passwordPolicyError(env, password);
    if (!isValidUsername(username) || createUserPasswordError) return superAdminPage(env, createUserPasswordError ?? "用户账户格式不正确");
    if (password !== confirmPassword) return superAdminPage(env, "两次输入的密码不一致");
    const createError = await mutateAccountTable<AdminAccount>(env, ADMIN_ACCOUNTS_KEY, () => getAdminAccounts(env), async (accounts) => {
      if (accounts[username]) return "用户账户已存在";
      if (Object.keys(accounts).length >= 10) return "账户最多创建 10 个";
      const salt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
      accounts[username] = { username, salt, passwordHash: await hashPassword(password, salt), role: "user" };
      return null;
    });
    if (createError) return superAdminPage(env, createError);
    await logAudit(env, { actor: currentAdmin.username, action: "create-user", target: username, clientIp: clientIpOf(request) });
    return superAdminPage(env, "用户账户已创建");
  }
  if (action === "create-webdav-admin") {
    return superAdminPage(env, "管理员无权为用户创建 WebDAV 账户");
  }
  if (action === "delete-webdav-admin") {
    const username = String(form.get("serviceUsername") || "");
    const webdavAccounts = await getWebdavAccounts(env);
    const account = webdavAccounts[username];
    // owner 不存在时视为孤儿账户，允许超管清理；owner 为管理员时拒绝
    const ownerRole = account ? accounts[account.owner]?.role : undefined;
    if (!account || ownerRole === "admin") return superAdminPage(env, "无权删除该 WebDAV 账户");
    await deleteWebdavAccountData(env, account);
    const deleteError = await mutateAccountTable<WebdavAccount>(env, WEBDAV_ACCOUNTS_KEY, () => getWebdavAccounts(env), async (accounts) => {
      delete accounts[username];
      return null;
    });
    if (deleteError) return superAdminPage(env, deleteError);
    await logAudit(env, { actor: currentAdmin.username, action: "delete-webdav-admin", target: username, clientIp: clientIpOf(request) });
    return superAdminPage(env, "WebDAV 账户及其文件已删除");
  }
  if (action === "delete-user") {
    const username = String(form.get("userUsername") || "");
    const user = accounts[username];
    if (!user || user.role === "admin" || username === currentAdmin.username) return superAdminPage(env, "只能删除普通用户账户");
    const webdavAccounts = await getWebdavAccounts(env);
    const deletedAccountNames: string[] = [];
    for (const account of Object.values(webdavAccounts)) {
      if (account.owner === username) {
        await deleteWebdavAccountData(env, account);
        delete webdavAccounts[account.username];
        deletedAccountNames.push(account.username);
      }
    }
    // 两个账户表分键存储无法原子级联，先删 WebDAV 表再删用户表，失败侧可重试
    const webdavError = await mutateAccountTable<WebdavAccount>(env, WEBDAV_ACCOUNTS_KEY, () => getWebdavAccounts(env), async (accounts) => {
      for (const account of Object.values(accounts)) {
        if (account.owner === username) delete accounts[account.username];
      }
      return null;
    });
    if (webdavError) return superAdminPage(env, webdavError);
    const userError = await mutateAccountTable<AdminAccount>(env, ADMIN_ACCOUNTS_KEY, () => getAdminAccounts(env), async (accounts) => {
      delete accounts[username];
      return null;
    });
    if (userError) return superAdminPage(env, userError);
    // 删除用户后吊销其全部会话，防止凭旧 cookie 继续操作
    await revokeUserSessions(env, username);
    // 数据最小化（GDPR/PIPL 被遗忘权）：可选彻底清除该用户及其账户的访问日志与审计记录
    const purgeLogs = String(form.get("purgeLogs") || "") === "1";
    if (purgeLogs) await purgeLogsForUsers(env, [username, ...deletedAccountNames]);
    await logAudit(env, { actor: currentAdmin.username, action: "delete-user", target: username, clientIp: clientIpOf(request), detail: purgeLogs ? "已同步清除访问日志与审计记录" : "" });
    return superAdminPage(env, "用户及其 WebDAV 账户已删除");
  }
  if (action === "reset-user-password") {
    const username = String(form.get("userUsername") || "");
    const target = accounts[username];
    if (!target || target.role === "admin") return superAdminPage(env, "只能为普通用户重置密码");
    // 生成 12 位随机临时密码（去除易混淆字符，必满足密码策略），仅在本次响应中展示一次
    const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
    const tempPassword = [...crypto.getRandomValues(new Uint8Array(12))].map((byte) => alphabet[byte % alphabet.length]).join("");
    const salt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
    const resetError = await mutateAccountTable<AdminAccount>(env, ADMIN_ACCOUNTS_KEY, () => getAdminAccounts(env), async (table) => {
      const account = table[username];
      if (!account) return "账户不存在";
      table[username] = { ...account, salt, passwordHash: await hashPassword(tempPassword, salt), mustChangePassword: true };
      return null;
    });
    if (resetError) return superAdminPage(env, resetError);
    await revokeUserSessions(env, username);
    await logAudit(env, { actor: currentAdmin.username, action: "reset-user-password", target: username, clientIp: clientIpOf(request) });
    return superAdminPage(env, `已重置 ${username} 的密码，临时密码：${tempPassword}（仅本次显示，请立即复制发给用户；该用户下次登录将被强制要求修改密码，且其全部会话已吊销）`);
  }
  if (action === "reset-totp") {
    const username = String(form.get("userUsername") || "");
    const target = accounts[username];
    if (!target || target.role === "admin") return superAdminPage(env, "只能重置普通用户的两步验证");
    if (!target.totpSecret) return superAdminPage(env, "该用户未启用两步验证");
    const resetError = await mutateAccountTable<AdminAccount>(env, ADMIN_ACCOUNTS_KEY, () => getAdminAccounts(env), async (table) => {
      const account = table[username];
      if (!account) return "账户不存在";
      table[username] = { ...account, totpSecret: undefined, recoveryCodes: undefined };
      return null;
    });
    if (resetError) return superAdminPage(env, resetError);
    await revokeUserSessions(env, username);
    await logAudit(env, { actor: currentAdmin.username, action: "reset-totp", target: username, clientIp: clientIpOf(request) });
    return superAdminPage(env, `已重置 ${username} 的两步验证：TOTP 令牌与恢复码已清除，其全部会话已吊销，用户重新登录后可重新绑定`);
  }
  if (action === "adjust-user-limit") {
    const username = String(form.get("userUsername") || "");
    const target = accounts[username];
    if (!target || target.role === "admin") return superAdminPage(env, "只能调节普通用户的容量上限");
    const limitGb = Number(form.get("limitGb"));
    if (!Number.isFinite(limitGb) || limitGb < 0 || limitGb > USER_LIMIT_MAX_GB) return superAdminPage(env, `容量上限必须介于 0（恢复默认 10 GB）与 ${USER_LIMIT_MAX_GB} GB 之间`);
    const limitError = await mutateAccountTable<AdminAccount>(env, ADMIN_ACCOUNTS_KEY, () => getAdminAccounts(env), async (items) => {
      const item = items[username];
      if (!item) return "账户不存在";
      items[username] = { ...item, storageLimitBytes: limitGb > 0 ? Math.round(limitGb * 1024 ** 3) : 0 };
      return null;
    });
    if (limitError) return superAdminPage(env, limitError);
    await logAudit(env, { actor: currentAdmin.username, action: "adjust-user-limit", target: username, clientIp: clientIpOf(request), detail: `${limitGb} GB` });
    return superAdminPage(env, `用户 ${username} 容量上限已更新`);
  }
  if (action === "adjust-dav-quota") {
    const serviceUsername = String(form.get("serviceUsername") || "");
    const webdavAccounts = await getWebdavAccounts(env);
    const account = webdavAccounts[serviceUsername];
    const ownerRole = account ? accounts[account.owner]?.role : undefined;
    if (!account || ownerRole === "admin") return superAdminPage(env, "无权调节该 WebDAV 账户的配额");
    const quotaGb = Number(form.get("quotaGb"));
    if (!Number.isFinite(quotaGb) || quotaGb < 0 || quotaGb > USER_LIMIT_MAX_GB) return superAdminPage(env, `配额必须介于 0（不限制）与 ${USER_LIMIT_MAX_GB} GB 之间`);
    const quotaError = await mutateAccountTable<WebdavAccount>(env, WEBDAV_ACCOUNTS_KEY, () => getWebdavAccounts(env), async (items) => {
      const item = items[serviceUsername];
      if (!item) return "账户不存在";
      item.quotaBytes = quotaGb > 0 ? Math.round(quotaGb * 1024 ** 3) : 0;
      return null;
    });
    if (quotaError) return superAdminPage(env, quotaError);
    await logAudit(env, { actor: currentAdmin.username, action: "adjust-dav-quota", target: serviceUsername, clientIp: clientIpOf(request), detail: `${quotaGb} GB` });
    return superAdminPage(env, `账户 ${serviceUsername} 存储配额已更新`);
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
  // 概览统计：用户数 / WebDAV 账户数 / 已分配上限 / 两步验证启用数
  const davCount = Object.keys(webdavAccounts).length;
  const allocatedGb = (users.reduce((total, user) => total + (user.storageLimitBytes || 0), 0) / 1024 ** 3).toFixed(1);
  const totpCount = users.filter((user) => user.totpSecret).length;
  const limitByOwner = new Map(await Promise.all(users.map(async (user) => [user.username, await getUserStorageLimit(env, user.username)] as const)));
  const userRows = users.map((user) => {
    const ownedAccounts = Object.values(webdavAccounts).filter((account) => account.owner === user.username);
    const accountRows = ownedAccounts.map((account) => `<div class="account-row"><span>${escapeHtml(account.username)} · ${escapeHtml(account.uuid || "------")} · 配额 ${account.quotaBytes && account.quotaBytes > 0 ? `${(account.quotaBytes / 1024 ** 3).toFixed(1)} GB` : "不限"}</span><form method="post" class="quota-form"><input type="hidden" name="action" value="adjust-dav-quota"><input type="hidden" name="serviceUsername" value="${escapeHtml(account.username)}"><input name="quotaGb" type="number" min="0" max="${USER_LIMIT_MAX_GB}" step="0.1" value="${account.quotaBytes && account.quotaBytes > 0 ? (account.quotaBytes / 1024 ** 3) : 0}" title="GB，0 为不限制" aria-label="配额 GB"><button class="secondary-button compact-button" type="submit">设配额</button></form><form method="post" style="display:inline" onsubmit="return confirm('确定删除此 WebDAV 账户及其全部文件吗？')"><input type="hidden" name="action" value="delete-webdav-admin"><input type="hidden" name="serviceUsername" value="${escapeHtml(account.username)}"><button class="danger-button compact-button" type="submit">删除</button></form></div>`).join("");
    const usageGb = usageByOwner.get(user.username) ?? "0.00";
    const limitBytes = limitByOwner.get(user.username) ?? 0;
    const usagePercent = limitBytes > 0 ? Math.min(100, Math.round((Number(usageGb) * 1024 ** 3 / limitBytes) * 100)) : 0;
    const usageClass = usagePercent >= 90 ? " full" : usagePercent >= 70 ? " warn" : "";
    const limitText = limitBytes > 0 ? `${(limitBytes / 1024 ** 3).toFixed(1).replace(/\.0$/, "")} GB` : "默认 10 GB";
    return `<tr class="user-row" data-search="${escapeHtml(`${user.username} ${ownedAccounts.map((account) => account.username).join(" ")}`.toLowerCase())}"><th scope="row"><div class="sa-user-cell"><span class="sa-avatar">${escapeHtml(user.username.slice(0, 1).toUpperCase())}</span><span><span class="sa-username">${escapeHtml(user.username)}</span><span class="sa-user-meta">${user.totpSecret ? '<span class="sa-2fa">2FA 已启用</span>' : '<span class="muted">未启用两步验证</span>'}<span class="muted">${ownedAccounts.length} 个 WebDAV 账户</span></span></span></div></th><td><div class="account-list">${accountRows || '<span class="muted">暂无 WebDAV 账户</span>'}</div></td><td><div class="sa-usage"><strong>${usageGb}<small> GB</small></strong><div class="sa-usage-bar${usageClass}"><span style="width:${usagePercent}%"></span></div><span class="muted">上限 ${limitText}</span></div></td><td><form method="post" class="limit-form"><input type="hidden" name="action" value="adjust-user-limit"><input type="hidden" name="userUsername" value="${escapeHtml(user.username)}"><input name="limitGb" type="number" min="0" max="${USER_LIMIT_MAX_GB}" step="0.1" value="${user.storageLimitBytes && user.storageLimitBytes > 0 ? (user.storageLimitBytes / 1024 ** 3) : 0}" title="GB，0 为默认 10 GB" aria-label="容量上限 GB">GB<button class="secondary-button compact-button" type="submit">设置</button></form><span class="muted limit-hint">0 = 默认 10 GB</span></td><td><div class="sa-actions"><form method="post" onsubmit="return confirm('确定重置该用户的密码吗？将生成一次性临时密码并吊销其全部会话。')"><input type="hidden" name="action" value="reset-user-password"><input type="hidden" name="userUsername" value="${escapeHtml(user.username)}"><button class="secondary-button compact-button" type="submit">重置密码</button></form><form method="post" onsubmit="return confirm('确定重置该用户的两步验证吗？将清除 TOTP 令牌与恢复码并吊销其全部会话。')"><input type="hidden" name="action" value="reset-totp"><input type="hidden" name="userUsername" value="${escapeHtml(user.username)}"><button class="secondary-button compact-button" type="submit">重置两步验证</button></form></div><div class="sa-danger-zone"><form method="post" onsubmit="return confirm('确定删除该用户及其全部 WebDAV 账户和文件吗？此操作不可恢复！')"><input type="hidden" name="action" value="delete-user"><input type="hidden" name="userUsername" value="${escapeHtml(user.username)}"><label class="sa-purge-label"><input type="checkbox" name="purgeLogs" value="1">同时清除其访问与审计日志</label><button class="danger-button" type="submit">删除用户</button></form></div></td></tr>`;
  }).join("");
  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>超级管理员</title><style>${ADMIN_CSS}${USER_TABLE_CSS}${FILES_CSS}${SUPER_ADMIN_CSS}</style><body>${topbarHtml("超级管理员", `<span class="status-dot">系统管理员</span><a class="text-link inverse" href="/?view=audit">审计日志</a>${env.ENABLE_ACCESS_LOG === "true" ? `<a class="text-link inverse" href="/__admin/logs">访问日志</a>` : ""}<a class="text-link inverse" href="/?action=logout">退出当前账户</a>`)}<main class="dashboard">${pageHeadingHtml("ADMINISTRATION", "用户与账户管理", "管理员只能管理用户和 WebDAV 账户信息，无法查看任何文件内容。", `<div class="storage-badge"><span>当前所有用户已用容量（GB）：<strong>${usedGb}</strong></span></div>`)}${message ? `<div class="notice success">${escapeHtml(message)}</div>` : ""}<section class="sa-stats"><article class="sa-stat"><span class="sa-stat-label">普通用户</span><strong>${users.length}<small> 人</small></strong><span class="sa-stat-meta">共 ${davCount} 个 WebDAV 账户</span></article><article class="sa-stat teal"><span class="sa-stat-label">全站已用容量</span><strong>${usedGb}<small> GB</small></strong><span class="sa-stat-meta">所有用户名下账户合计</span></article><article class="sa-stat green"><span class="sa-stat-label">已分配容量上限</span><strong>${allocatedGb}<small> GB</small></strong><span class="sa-stat-meta">0 表示按默认 10 GB / 用户</span></article><article class="sa-stat danger"><span class="sa-stat-label">两步验证启用</span><strong>${totpCount}<small> / ${users.length}</small></strong><span class="sa-stat-meta">建议所有用户启用 TOTP</span></article></section><section class="sa-grid"><article class="config-card"><div class="card-heading"><div><p class="eyebrow">NEW USER</p><h2>创建用户</h2></div><span class="icon-badge">01</span></div><form method="post" class="sa-create-form"><input type="hidden" name="action" value="create-user"><div class="sa-field full-row"><label for="su-username">用户账户</label><div class="sa-input-wrap"><span class="sa-input-icon"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></span><input id="su-username" name="userUsername" autocomplete="username" placeholder="例如 alice" required></div><span class="sa-field-hint">同时用于登录管理界面与 WebDAV 客户端</span></div><div class="sa-field"><label for="su-password">密码</label><div class="sa-input-wrap"><span class="sa-input-icon"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></span><input id="su-password" name="userPassword" type="password" autocomplete="new-password" minlength="8" placeholder="至少 8 位字符" required></div></div><div class="sa-field"><label for="su-password-confirm">确认密码</label><div class="sa-input-wrap"><span class="sa-input-icon"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg></span><input id="su-password-confirm" name="userPasswordConfirm" type="password" autocomplete="new-password" minlength="8" placeholder="再次输入密码" required></div></div><button class="primary-button" type="submit">创建用户<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"/><path d="M12 5l7 7-7 7"/></svg></button></form></article><article class="config-card sa-info-card"><div class="card-heading"><div><p class="eyebrow">GUIDELINES</p><h2>管理须知</h2></div><span class="icon-badge">02</span></div><ul><li><strong>容量上限：</strong>每个用户默认 10 GB，可随时调整；单个 WebDAV 账户还可单独限配额</li><li><strong>重置密码：</strong>生成一次性临时密码并吊销全部会话，该用户下次登录将被强制改密</li><li><strong>重置两步验证：</strong>用户验证器丢失时使用，清除令牌与恢复码后可重新绑定</li><li><strong>删除用户：</strong>连同其全部 WebDAV 账户与文件一并删除，可选同步清除日志</li><li><strong>隐私边界：</strong>管理员只能管理账户与配额，无法查看任何文件内容</li></ul></article></section><section class="config-card user-table-card"><div class="sa-list-heading"><div><p class="eyebrow">USER DIRECTORY</p><h2>用户列表</h2></div><span class="icon-badge">${users.length}</span></div><p class="muted">按用户或 WebDAV 账户名筛选；用量条达 70% 转金色、90% 转红色提醒。</p><label class="filter-label" for="user-filter">筛选用户或 WebDAV 账户<input id="user-filter" type="search" placeholder="输入名称筛选" oninput="filterUsers(this.value)"></label><div class="table-scroll"><table class="user-table"><thead><tr><th scope="col">用户</th><th scope="col">WebDAV 账户</th><th scope="col">当前已使用存储空间（GB）</th><th scope="col">容量上限（GB）</th><th scope="col">操作</th></tr></thead><tbody id="user-table-body">${userRows || '<tr><td colspan="5" class="muted empty-cell">暂无用户。</td></tr>'}</tbody></table></div><p id="user-filter-empty" class="muted empty-cell" hidden>没有匹配的用户。</p></section></main><script>function filterUsers(value){const query=value.trim().toLowerCase();let visible=0;document.querySelectorAll('.user-row').forEach((row)=>{const matched=!query||row.dataset.search.includes(query);row.hidden=!matched;if(matched)visible+=1;});document.getElementById('user-filter-empty').hidden=visible>0||!query;}setInterval(function(){fetch('/?api=heartbeat',{cache:'no-store'}).then(function(r){return r.json()}).then(function(d){if(!d.ok)location.reload()}).catch(function(){location.reload()})},300000);</script></body></html>`);
}

async function adminLandingPage(request: Request, env: Env, adminUsername: string, accounts: WebdavAccount[], nextUuid: string, message: string, usedStorage: number): Promise<Response> {
  const usedGb = (usedStorage / 1024 ** 3).toFixed(2);
  const totalGb = String((await getUserStorageLimit(env, adminUsername)) / 1024 ** 3);
  // 登录状态自选下拉：普通用户当前值取自账户设置（缺省 1 天）；超级管理员不渲染本页（强制关闭即注销）
  const sessionHours = (await getAdminAccounts(env))[adminUsername]?.sessionDurationHours ?? 24;
  const sessionOptions = (["168|7 天", "72|3 天", "24|1 天", "12|12 小时", "1|1 小时", "0|关闭浏览器后立即注销"] as const).map((item) => {
    const [value, label] = item.split("|");
    return `<option value="${value}"${Number(value) === sessionHours ? " selected" : ""}>${label}</option>`;
  }).join("");
  const accountCards = accounts.map((account) => `<a class="config-card account-card account-choice" href="/?view=account&account=${encodeURIComponent(account.username)}"><div class="card-heading"><div><p class="eyebrow">WEBDAV ACCOUNT</p><h2>${escapeHtml(account.username)}</h2></div><span class="icon-badge">${escapeHtml(account.uuid || "------")}</span></div><p class="muted">账户链接：${escapeHtml(webdavAccountUrl(request, account))}</p><span class="primary-button inline-button">进入账户管理</span></a>`).join("");
  const createForm = accounts.length < 2 ? `<article class="config-card account-card"><div class="card-heading"><div><p class="eyebrow">NEW ACCOUNT</p><h2>新建 WebDAV 账户</h2></div><span class="icon-badge">+</span></div><p class="muted">当前管理员最多拥有 2 个 WebDAV 账户。</p><form method="post" action="/?view=home" class="config-form"><input type="hidden" name="action" value="create-webdav"><label>账户<input name="serviceUsername" autocomplete="username" required></label><label>密码<input name="servicePassword" type="password" autocomplete="new-password" minlength="8" required></label><label>6 位 UUID<div class="uuid-row"><input name="accountUuid" value="${escapeHtml(nextUuid)}" inputmode="numeric" pattern="[0-9]{6}" minlength="6" maxlength="6" required><button type="button" class="secondary-button uuid-check-btn" onclick="return checkUuidAvailability(this)">检查 UUID</button></div><span id="uuid-check-result" class="uuid-result"></span></label><button class="primary-button" type="submit">创建 WebDAV 账户</button></form></article>` : "";
  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>用户管理</title><style>${ADMIN_CSS}${FILES_CSS}</style><body>${topbarHtml("用户管理", `<span class="status-dot">管理员：${escapeHtml(adminUsername)}</span><a class="text-link inverse" href="/?view=change-password">安全设置</a>${env.ENABLE_ACCESS_LOG === "true" ? `<a class="text-link inverse" href="/?view=logs">访问日志</a>` : ""}<a class="text-link inverse" href="/?api=export-data">导出我的数据</a><a class="text-link inverse" href="/?action=logout">退出登录</a>`)}<main class="dashboard">${pageHeadingHtml("USER MANAGEMENT", "用户管理", "进入账户后只能管理该账户自己的文件。", `<div class="storage-badge"><span>当前已用容量（GB）：<strong>${usedGb}</strong></span><span>总容量（GB）：<strong>${totalGb}</strong></span></div>`)}${message ? `<div class="notice success">${escapeHtml(message)}</div>` : ""}<section class="content-grid">${accountCards}${createForm}</section><p class="muted">${accounts.length}/2 个 WebDAV 账户</p><section class="config-card session-card"><div class="card-heading"><div><p class="eyebrow">SESSION</p><h2>登录状态</h2></div></div><p class="muted">选择登录状态保持时长，保存后立即对当前登录生效；选择“关闭浏览器后立即注销”时，关闭浏览器即自动退出。</p><form method="post" action="/" class="config-form session-form"><input type="hidden" name="action" value="set-session-duration"><label>保持时长<select name="sessionHours">${sessionOptions}</select></label><button class="primary-button" type="submit">保存登录状态</button></form></section></main><script>async function checkUuidAvailability(btn){var row=btn.closest('.uuid-row');var input=row.querySelector('input');var result=document.getElementById('uuid-check-result');var uuid=input.value.trim();result.className='uuid-result';result.textContent='检查中…';if(!/^[0-9]{6}$/.test(uuid)){result.textContent='UUID 必须是 6 位数字';result.className='uuid-result error';return false;}try{var res=await fetch('/?api=check-uuid&uuid='+encodeURIComponent(uuid));var data=await res.json();result.textContent=data.message;result.className='uuid-result '+(data.ok&&data.available?'success':'error');}catch(e){result.textContent='检查失败，请重试';result.className='uuid-result error';}return false;}</script></body></html>`);
}

async function adminAccountPage(request: Request, env: Env, account: WebdavAccount, newAppPassword = "", appPasswordError = ""): Promise<Response> {
  const scopedEnv = createScopedEnv(env, storageScope(account));
  const fileCount = (await listAllObjects(scopedEnv, "")).filter((item) => !item.key.startsWith("__trash/")).length;
  const accountUrl = webdavAccountUrl(request, account);
  // 配额上限跟随超管为本用户设置的容量上限（默认 10 GB）
  const quotaCeilingGb = (await getUserStorageLimit(env, account.owner)) / 1024 ** 3;
  const appPasswordRows = (account.appPasswords ?? []).map((entry) => `<div class="account-row"><span>${escapeHtml(entry.name)} · 创建于 ${formatDateTime(new Date(entry.createdAt))}</span><form method="post" action="/?view=account&account=${encodeURIComponent(account.username)}" style="display:inline" onsubmit="return confirm('确定吊销应用密码「${escapeHtml(entry.name)}」吗？使用该密码的客户端将立即无法访问。')"><input type="hidden" name="action" value="revoke-app-password"><input type="hidden" name="accountUsername" value="${escapeHtml(account.username)}"><input type="hidden" name="appId" value="${escapeHtml(entry.id)}"><button class="danger-button compact-button" type="submit">吊销</button></form></div>`).join("");
  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(account.username)} - WebDAV 管理</title><style>${ADMIN_CSS}${FILES_CSS}</style><body>${topbarHtml("账户管理", `<a class="text-link inverse" href="/">返回账户选择</a><a class="text-link inverse" href="/?action=logout">退出登录</a>`)}<main class="dashboard">${pageHeadingHtml("WEBDAV ACCOUNT", account.username, `当前账户包含 ${fileCount} 个文件，仅显示此账户的数据。`)}<section class="content-grid"><article class="config-card wide-card"><div class="card-heading"><div><p class="eyebrow">CONNECTION</p><h2>账户连接信息</h2></div><span class="icon-badge">${escapeHtml(account.uuid || "------")}</span></div><p class="muted">服务链接：${escapeHtml(accountUrl)}</p><form method="post" action="/?view=account&account=${encodeURIComponent(account.username)}" class="config-form"><input type="hidden" name="action" value="save-service"><input type="hidden" name="accountUsername" value="${escapeHtml(account.username)}"><label>账户<input name="serviceUsername" value="${escapeHtml(account.username)}" autocomplete="username" readonly title="账户名是存储路径标识，不可修改"></label><label>密码<input name="servicePassword" type="password" autocomplete="new-password" minlength="8" placeholder="输入新密码" required></label><label>6 位 UUID<input name="accountUuid" value="${escapeHtml(account.uuid || "")}" inputmode="numeric" pattern="[0-9]{6}" minlength="6" maxlength="6" required></label><label>存储配额（GB，0 表示不限制，上限 ${quotaCeilingGb} GB）<input name="quotaGb" type="number" min="0" max="${quotaCeilingGb}" step="0.1" value="${account.quotaBytes ? (account.quotaBytes / 1024 ** 3).toString() : "0"}"></label><button class="primary-button" type="submit">保存账户信息</button></form><a class="secondary-button inline-button" href="/?view=files&account=${encodeURIComponent(account.username)}">打开此账户文件</a></article><article class="config-card wide-card"><div class="card-heading"><div><p class="eyebrow">APP PASSWORDS</p><h2>应用专用密码</h2></div><span class="icon-badge">${(account.appPasswords ?? []).length}</span></div><p class="muted">为第三方客户端生成独立密码，主密码不外泄；应用密码可随时单独吊销，不影响主密码登录。</p>${newAppPassword ? `<p class="notice success">新应用密码已生成（仅显示这一次，请立即保存）：<code>${escapeHtml(newAppPassword)}</code></p>` : ""}${appPasswordError ? `<p class="error">${escapeHtml(appPasswordError)}</p>` : ""}<div class="account-list">${appPasswordRows || '<span class="muted">暂无应用密码。</span>'}</div><form method="post" action="/?view=account&account=${encodeURIComponent(account.username)}" class="config-form"><input type="hidden" name="action" value="create-app-password"><input type="hidden" name="accountUsername" value="${escapeHtml(account.username)}"><label>用途名称（如：RaiDrive、电脑备份）<input name="appName" maxlength="32" required></label><button class="primary-button" type="submit">生成应用密码</button></form></article></section></main></body></html>`);
}

async function adminAccountsPage(request: Request, env: Env, adminUsername: string): Promise<Response> {
  const accounts = Object.values(await getWebdavAccounts(env)).filter((account) => account.owner === adminUsername);
  const rows = accounts.map((account) => `<article class="config-card account-card"><div class="card-heading"><div><p class="eyebrow">WEBDAV ACCOUNT</p><h2>${escapeHtml(account.username)}</h2></div><span class="icon-badge">${escapeHtml(account.username.slice(0, 2).toUpperCase())}</span></div><p class="muted">服务链接：${escapeHtml(account.url)}</p><form method="post" action="/?view=accounts" class="config-form"><input type="hidden" name="action" value="save-service"><input type="hidden" name="accountUsername" value="${escapeHtml(account.username)}"><label>账户<input name="serviceUsername" value="${escapeHtml(account.username)}" readonly title="账户名是存储路径标识，不可修改"></label><label>密码<input name="servicePassword" type="password" minlength="8" placeholder="输入新密码" required></label><label>服务链接<input name="url" type="url" value="${escapeHtml(account.url)}" required></label><button class="primary-button" type="submit">保存 WebDAV 账户</button><a class="secondary-button inline-button" href="/?view=files&account=${encodeURIComponent(account.username)}">打开此账户文件</a></form></article>`).join("");
  const createForm = accounts.length < 2 ? `<article class="config-card account-card"><div class="card-heading"><div><p class="eyebrow">NEW ACCOUNT</p><h2>创建 WebDAV 账户</h2></div><span class="icon-badge">+</span></div><p class="muted">每个管理员最多拥有 2 个 WebDAV 账户。</p><form method="post" action="/?view=accounts" class="config-form"><input type="hidden" name="action" value="create-webdav"><label>账户<input name="serviceUsername" required></label><label>密码<input name="servicePassword" type="password" minlength="8" required></label><button class="primary-button" type="submit">创建账户</button></form></article>` : "";
  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>账号管理</title><style>${ADMIN_CSS}${FILES_CSS}</style><body>${topbarHtml("账号管理", `<a class="text-link inverse" href="/">返回管理中心</a><a class="text-link inverse" href="/?action=logout">退出登录</a>`)}<main class="dashboard">${pageHeadingHtml("ACCOUNT MANAGEMENT", "账号管理", `当前管理员：${adminUsername}。每个管理员最多拥有两个 WebDAV 账户。`)}<section class="content-grid">${rows}${createForm}</section><section class="config-card admin-account-card"><div class="card-heading"><div><p class="eyebrow">NEW ADMIN</p><h2>创建管理员账户</h2></div></div><form method="post" action="/?view=accounts" class="config-form"><input type="hidden" name="action" value="create-admin"><label>管理员账户<input name="adminUsername" required></label><label>管理员密码<input name="adminPassword" type="password" minlength="8" required></label><button class="primary-button" type="submit">创建管理员</button></form></section></main></body></html>`);
}

// 会话值兼容两种格式：旧版纯用户名字符串与新版 { user, lastSeen } JSON（支持空闲超时）
function sessionValueOf(raw: string | null): { user: string; lastSeen: number; exp?: number; role?: "admin" | "user" } | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as { user?: string; lastSeen?: number; exp?: number; role?: "admin" | "user" };
    if (parsed?.user && typeof parsed.lastSeen === "number") return { user: parsed.user, lastSeen: parsed.lastSeen, exp: typeof parsed.exp === "number" ? parsed.exp : undefined, role: parsed.role === "admin" ? "admin" : undefined };
  } catch { }
  // 旧格式会话（纯用户名字符串）无真实活跃时间：记 0（最旧），避免在会话限额排序中被
  // 误判为“刚刚活跃”而挤掉真实会话；后续访问会将其升级为新格式或被优先清理
  return { user: raw, lastSeen: 0 };
}

async function sessionUser(request: Request, env: Env): Promise<string | null> {
  const token = sessionToken(request);
  if (!token) return null;
  const session = sessionValueOf(await env.WEBDAV_KV.get(`${SESSION_PREFIX}${token}`));
  if (!session) return null;
  let idleSeconds = getSessionIdleSeconds(env);
  // 超级管理员强制空闲超时（心跳停止即倒数）：页面关闭后自动吊销，近似“关闭即注销”
  if (session.role === "admin") {
    const adminIdle = getAdminIdleSeconds(env);
    if (adminIdle > 0) idleSeconds = idleSeconds > 0 ? Math.min(idleSeconds, adminIdle) : adminIdle;
  }
  // 绝对过期：到达用户自选的保持时长后强制重新登录（旧格式会话无 exp 字段，按原有行为处理）
  if (session.exp && Date.now() > session.exp) {
    await env.WEBDAV_KV.delete(`${SESSION_PREFIX}${token}`);
    return null;
  }
  if (idleSeconds > 0) {
    if (Date.now() - session.lastSeen > idleSeconds * 1000) {
      // 空闲超时：吊销会话要求重新登录
      await env.WEBDAV_KV.delete(`${SESSION_PREFIX}${token}`);
      return null;
    }
    // 刷新活跃时间（节流写 KV，默认 30 分钟一次以省 KV 写入配额）；KV TTL 设为剩余秒数，不延长绝对过期。
    // 例外一：超管强制空闲超时依赖页面心跳（60 秒）刷新 lastSeen 判活，保持 1 分钟粒度，否则页面开着也会被吊销；
    // 例外二：配置了较短空闲超时的普通用户按超时窗口一半节流（lastSeen 最旧只滞后半个窗口），避免持续活跃却被误判空闲
    const refreshMs = session.role === "admin" && getAdminIdleSeconds(env) > 0
      ? 60_000
      : idleSeconds > 0 ? Math.min(1_800_000, idleSeconds * 500) : 1_800_000;
    if (Date.now() - session.lastSeen > refreshMs) {
      const remainSeconds = session.exp ? Math.max(60, Math.ceil((session.exp - Date.now()) / 1000)) : SESSION_TTL;
      await env.WEBDAV_KV.put(`${SESSION_PREFIX}${token}`, JSON.stringify({ user: session.user, lastSeen: Date.now(), exp: session.exp }), { expirationTtl: remainSeconds });
    }
  }
  return session.user;
}

function adminPath(value: string): string {
  // NFC 规范化：macOS Finder 以 NFD 分解形式上传文件名，与 Windows/Linux 的 NFC 不一致会产生"同名双文件"，统一入库前规范化
  const path = value.normalize("NFC").trim().replace(/^\/+|\/+$/g, "");
  if (!path) return "";
  // __trash 为回收站保留命名空间（与 WebDAV 层 requestPath 一致），管理端 mkdir/upload/移动一律拒绝写入
  if (path.split("/").some((segment) => !segment || segment === "." || segment === ".." || segment === "__trash" || /[\u0000-\u001f\u007f-\u009f]/.test(segment))) throw new Error("invalid path");
  return path;
}

// 批量操作：收集勾选路径并归一化（非法路径直接丢弃）
function normalizeBatchPaths(form: FormData): string[] {
  return form.getAll("paths").map(String).map((value) => {
    try { return adminPath(value); } catch { return ""; }
  }).filter(Boolean);
}

function filesPageRedirect(accountUsername: string, currentPath: string, extraQuery = ""): Response {
  return new Response(null, { status: 303, headers: { Location: `/?view=files&account=${encodeURIComponent(accountUsername)}${currentPath ? `&path=${encodeURIComponent(currentPath)}` : ""}${extraQuery}` } });
}

async function adminFilesAction(request: Request, env: Env, form: FormData, username: string, accountUsername: string, account: WebdavAccount): Promise<Response> {
  const scopedEnv = createScopedEnv(env, storageScope(account));
  const action = String(form.get("action") || "");
  let currentPath = "";
  try {
    currentPath = adminPath(String(form.get("currentPath") || ""));
  } catch {
    return textResponse("非法路径", 400);
  }
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
    } else if (action === "batch-delete") {
      // 批量删除：文件与目录统一走 deletePath 软删除，可在回收站恢复
      const paths = normalizeBatchPaths(form);
      if (!paths.length) return textResponse("请先勾选要删除的文件或目录", 400);
      operationMethod = "DELETE";
      let deletedCount = 0;
      for (const path of paths) {
        const response = await deletePath(scopedEnv, path);
        if (response.status >= 400) continue;
        deletedCount++;
        await logAccess(env, { method: "DELETE", path, status: response.status, clientIp: request.headers.get("CF-Connecting-IP") || "unknown", userAgent: request.headers.get("User-Agent") || "", user: username });
      }
      return filesPageRedirect(accountUsername, currentPath, `&deleted=${deletedCount}`);
    } else if (action === "batch-move") {
      // 批量移动：目标目录必须已存在（或根），目标已存在同名内容时跳过该项，回跳后提示统计结果
      const paths = normalizeBatchPaths(form);
      if (!paths.length) return textResponse("请先勾选要移动的文件或目录", 400);
      let targetDir = "";
      try { targetDir = adminPath(String(form.get("targetDir") || "")); } catch { return textResponse("目标目录路径不合法", 400); }
      if (targetDir && !(await scopedEnv.WEBDAV_KV.get(dirKey(targetDir))) && !(await hasChildren(scopedEnv, targetDir))) return textResponse("目标目录不存在，请先创建后再移动", 400);
      operationMethod = "MOVE";
      let movedCount = 0;
      let skippedCount = 0;
      let missingCount = 0;
      let failedCount = 0;
      for (const source of paths) {
        // 单项失败（复制回滚后 re-throw 等）不中断整批，统计后继续处理剩余项
        let result: "moved" | "conflict" | "missing";
        try {
          result = await moveEntryTo(scopedEnv, source, targetDir);
        } catch {
          failedCount++;
          continue;
        }
        if (result === "moved") {
          movedCount++;
          await logAccess(env, { method: "MOVE", path: source, status: 201, clientIp: request.headers.get("CF-Connecting-IP") || "unknown", userAgent: request.headers.get("User-Agent") || "", user: username });
        } else if (result === "missing") {
          missingCount++;
        } else {
          skippedCount++;
        }
      }
      return filesPageRedirect(accountUsername, currentPath, `&moved=${movedCount}&skipped=${skippedCount}&missing=${missingCount}&failed=${failedCount}`);
    } else if (action === "create-share") {
      // 创建限时分享链接：仅限已存在的文件；记录存全局 KV（/s/ 路由无账户上下文），TTL 到期自动失效
      const sharePath = adminPath(String(form.get("path") || ""));
      operationPath = sharePath;
      operationMethod = "SHARE";
      const hours = Number(form.get("expiresIn") || "24");
      if (![1, 24, 168, 720].includes(hours)) return textResponse("分享有效期不合法", 400);
      const shareObject = await scopedEnv.WEBDAV_BUCKET.head(r2Key(sharePath));
      if (!shareObject) return textResponse("仅支持分享已存在的文件", 404);
      const token = bytesToBase64(crypto.getRandomValues(new Uint8Array(24)));
      const shareRecord = { scope: storageScope(account), path: sharePath, name: sharePath.slice(sharePath.lastIndexOf("/") + 1), account: accountUsername, owner: username, createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + hours * 3600 * 1000).toISOString() };
      await env.WEBDAV_KV.put(`${SHARE_PREFIX}${token}`, JSON.stringify(shareRecord), { expirationTtl: Math.max(60, Math.round(hours * 3600)) });
      await logAccess(env, { method: "SHARE", path: sharePath, status: 201, clientIp: request.headers.get("CF-Connecting-IP") || "unknown", userAgent: request.headers.get("User-Agent") || "", user: username });
      return filesPageRedirect(accountUsername, currentPath, `&shared=${encodeURIComponent(token)}&sharedExpires=${encodeURIComponent(shareRecord.expiresAt)}`);
    } else if (action === "revoke-share") {
      const token = String(form.get("token") || "").replace(/[^A-Za-z0-9_-]/g, "");
      operationMethod = "SHARE";
      operationPath = currentPath;
      const revokeRecord = token ? await env.WEBDAV_KV.get(`${SHARE_PREFIX}${token}`, "json") as { owner?: string } | null : null;
      if (revokeRecord && revokeRecord.owner === username) await env.WEBDAV_KV.delete(`${SHARE_PREFIX}${token}`);
      return filesPageRedirect(accountUsername, currentPath, "&shareRevoked=1");
    } else if (action === "copy-file") {
      // 单文件复制（仅限文件）：副本保存在当前目录下，目标同名即拒绝（覆盖即不可逆丢失），走配额检查并回加用量
      const sourcePath = adminPath(String(form.get("path") || ""));
      operationPath = sourcePath;
      operationMethod = "COPY";
      const copyName = String(form.get("copyName") || "").trim();
      if (!copyName || copyName.includes("/") || copyName.includes("\\") || copyName.includes("..")) return textResponse("副本名称不合法", 400);
      const copyPath = adminPath(`${currentPath ? `${currentPath}/` : ""}${copyName}`);
      if (copyPath === sourcePath) return textResponse("副本名称不能与原文件相同", 400);
      const sourceObject = await scopedEnv.WEBDAV_BUCKET.head(r2Key(sourcePath));
      if (!sourceObject) return textResponse("仅支持复制已存在的文件", 404);
      if (await scopedEnv.WEBDAV_BUCKET.head(r2Key(copyPath))) return textResponse("目标名称已存在，请换一个名称", 400);
      const copyQuotaResponse = await ensureStorageCapacity(env, scopedEnv, account, copyPath, sourceObject.size);
      if (copyQuotaResponse) return copyQuotaResponse;
      const copyContent = await scopedEnv.WEBDAV_BUCKET.get(r2Key(sourcePath));
      if (!copyContent) return textResponse("文件不存在或已被删除", 404);
      await scopedEnv.WEBDAV_BUCKET.put(r2Key(copyPath), copyContent.body, { httpMetadata: copyContent.httpMetadata });
      const copyMeta = await scopedEnv.WEBDAV_KV.get(metaKey(sourcePath));
      if (copyMeta) await scopedEnv.WEBDAV_KV.put(metaKey(copyPath), copyMeta);
      await logAccess(env, { method: "COPY", path: copyPath, status: 201, clientIp: request.headers.get("CF-Connecting-IP") || "unknown", userAgent: request.headers.get("User-Agent") || "", user: username });
      return filesPageRedirect(accountUsername, currentPath, "&copied=1");
    }
  } catch (error) {
    return textResponse(error instanceof Error ? error.message : "文件操作失败", 400);
  }
  await logAccess(env, { method: operationMethod, path: operationPath, status: responseStatus, clientIp: request.headers.get("CF-Connecting-IP") || "unknown", userAgent: request.headers.get("User-Agent") || "", user: username });
  return new Response(null, { status: 303, headers: { Location: `/?view=files&account=${encodeURIComponent(accountUsername)}${currentPath ? `&path=${encodeURIComponent(currentPath)}` : ""}` } });
}

// 管理界面流式上传：请求体不经 formData 缓冲，直接管道到 R2，支持大文件与浏览器端进度条
async function adminUploadStream(request: Request, env: Env, account: WebdavAccount, url: URL): Promise<Response> {
  const clientIp = request.headers.get("CF-Connecting-IP") || "unknown";
  const userAgent = request.headers.get("User-Agent") || "";
  const filename = url.searchParams.get("name") || "";
  if (!filename || filename.includes("/") || filename.includes("\\") || filename.includes("..")) return textResponse("文件名不合法", 400);
  let currentPath = "";
  try {
    currentPath = adminPath(url.searchParams.get("path") || "");
  } catch {
    return textResponse("非法路径", 400);
  }
  const scopedEnv = createScopedEnv(env, storageScope(account));
  const path = adminPath(`${currentPath ? `${currentPath}/` : ""}${filename}`);
  const contentLength = Number(request.headers.get("Content-Length"));
  if (!Number.isSafeInteger(contentLength) || contentLength <= 0) return textResponse("Content-Length 缺失", 411);
  const quotaResponse = await ensureStorageCapacity(env, scopedEnv, account, path, contentLength);
  if (quotaResponse) return quotaResponse;
  const existingObject = await scopedEnv.WEBDAV_BUCKET.head(r2Key(path));
  const contentType = request.headers.get("Content-Type") || "application/octet-stream";
  await scopedEnv.WEBDAV_BUCKET.put(r2Key(path), request.body, { httpMetadata: { contentType } });
  await scopedEnv.WEBDAV_KV.put(metaKey(path), JSON.stringify({ type: "file", size: contentLength, contentType, updatedAt: new Date().toISOString() }));
  await logAccess(env, { method: "PUT", path, status: 201, clientIp, userAgent, user: account.owner });
  return textResponse("OK", 201);
}

// 公开分享下载：/s/{token}，记录存全局 KV（含 storageScope）；过期/取消/文件删除后失效
async function serveShare(request: Request, env: Env): Promise<Response> {
  const token = decodeURIComponent(new URL(request.url).pathname.slice(3));
  if (!/^[A-Za-z0-9_-]{8,64}$/.test(token)) return textResponse("分享链接无效", 404);
  const record = await env.WEBDAV_KV.get(`${SHARE_PREFIX}${token}`, "json") as { scope: string; path: string; name: string; account: string; expiresAt: string } | null;
  if (!record) return textResponse("分享链接不存在或已被取消", 404);
  if (Date.parse(record.expiresAt) <= Date.now()) {
    await env.WEBDAV_KV.delete(`${SHARE_PREFIX}${token}`);
    return textResponse("分享链接已过期", 410);
  }
  const scopedEnv = createScopedEnv(env, record.scope);
  const object = await scopedEnv.WEBDAV_BUCKET.get(r2Key(record.path));
  if (!object) return textResponse("文件不存在或已被删除", 404);
  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("Content-Length", String(object.size));
  headers.set("Content-Disposition", `attachment; filename*=UTF-8''${encodeURIComponent(record.name)}`);
  headers.set("Cache-Control", "no-store");
  await logAccess(env, { method: "SHARE", path: record.path, status: 200, clientIp: request.headers.get("CF-Connecting-IP") || "unknown", userAgent: request.headers.get("User-Agent") || "", user: record.account });
  return new Response(object.body, { status: 200, headers });
}

// 文件预览原始内容端点：图片/文本内联返回；dl=1 时强制附件下载。
// CSP sandbox 阻断内嵌脚本（如 SVG 内 <script>），nosniff 禁止类型嗅探，防止同源执行
async function servePreviewRaw(request: Request, env: Env, account: WebdavAccount, url: URL): Promise<Response> {
  let path = "";
  try {
    path = adminPath(url.searchParams.get("path") || "");
  } catch {
    return textResponse("非法路径", 400);
  }
  const scopedEnv = createScopedEnv(env, storageScope(account));
  const object = await scopedEnv.WEBDAV_BUCKET.get(r2Key(path));
  if (!object) return textResponse("文件不存在或已被删除", 404);
  const name = path.slice(path.lastIndexOf("/") + 1);
  const headers = new Headers();
  object.writeHttpMetadata(headers);
  if (!headers.get("Content-Type")) headers.set("Content-Type", "application/octet-stream");
  headers.set("Content-Disposition", `inline; filename*=UTF-8''${encodeURIComponent(name)}`);
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Content-Security-Policy", "sandbox");
  headers.set("Cache-Control", "no-store");
  // 上传时文本类常被存为 octet-stream，内联预览时按扩展名改为 text/plain，浏览器才能直接展示
  if (previewKindOf(name) === "text") headers.set("Content-Type", "text/plain; charset=utf-8");
  if (url.searchParams.get("dl") === "1") {
    headers.set("Content-Type", "application/octet-stream");
    headers.set("Content-Disposition", `attachment; filename*=UTF-8''${encodeURIComponent(name)}`);
  }
  headers.set("Content-Length", String(object.size));
  return new Response(object.body, { status: 200, headers });
}

// 文件在线预览页：图片直接展示，文本/Markdown 转义后展示，其余类型提示不支持并提供下载
async function adminPreviewPage(request: Request, env: Env, account: WebdavAccount): Promise<Response> {
  const url = new URL(request.url);
  let path = "";
  try {
    path = adminPath(url.searchParams.get("path") || "");
  } catch {
    return textResponse("非法路径", 400);
  }
  const name = path.slice(path.lastIndexOf("/") + 1);
  const kind = previewKindOf(name);
  const scopedEnv = createScopedEnv(env, storageScope(account));
  const previewUrl = `/?api=preview&account=${encodeURIComponent(account.username)}&path=${encodeURIComponent(path)}`;
  let previewBody = "";
  let sizeBytes = 0;
  let uploadedAt = "";
  if (kind === "image") {
    const object = await scopedEnv.WEBDAV_BUCKET.head(r2Key(path));
    if (!object) return textResponse("文件不存在或已被删除", 404);
    sizeBytes = object.size;
    uploadedAt = object.uploaded.toISOString();
    previewBody = `<div class="preview-media"><img src="${previewUrl}" alt="${escapeHtml(name)}"></div>`;
  } else if (kind === "text") {
    const object = await scopedEnv.WEBDAV_BUCKET.get(r2Key(path));
    if (!object) return textResponse("文件不存在或已被删除", 404);
    sizeBytes = object.size;
    uploadedAt = object.uploaded.toISOString();
    if (object.size > PREVIEW_TEXT_LIMIT) {
      previewBody = `<p class="muted">文本文件超过 ${formatBytes(PREVIEW_TEXT_LIMIT)}，暂不支持在线预览，请下载后查看。</p>`;
    } else {
      // 文本内容必须转义后展示，防止存储型 XSS
      previewBody = `<pre class="preview-text">${escapeHtml(await object.text())}</pre>`;
    }
  } else {
    const object = await scopedEnv.WEBDAV_BUCKET.head(r2Key(path));
    if (!object) return textResponse("文件不存在或已被删除", 404);
    sizeBytes = object.size;
    uploadedAt = object.uploaded.toISOString();
    previewBody = `<p class="muted">该文件类型不支持在线预览，可下载后查看。</p>`;
  }
  const parentPath = path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "";
  const typeLabel = kind === "image" ? "图片" : kind === "text" ? "文本" : "文件";
  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>文件预览 - ${escapeHtml(name)}</title><style>${ADMIN_CSS}${FILES_CSS}${PREVIEW_CSS}</style><body>${topbarHtml("文件预览", `<a class="text-link inverse" href="/?view=files&account=${encodeURIComponent(account.username)}${parentPath ? `&path=${encodeURIComponent(parentPath)}` : ""}">返回文件管理</a>`)}<main class="dashboard"><section class="file-table-wrap preview-shell"><div class="preview-heading"><div><strong>${escapeHtml(name)}</strong><span class="preview-meta">${typeLabel} · ${formatBytes(sizeBytes)} · ${formatDateTime(new Date(uploadedAt))}</span></div><div class="row-actions"><a class="secondary-button" href="${previewUrl}&dl=1">下载</a></div></div>${previewBody}</section></main></body></html>`);
}

async function adminFilesPage(request: Request, env: Env, account: WebdavAccount, rootEnv: Env): Promise<Response> {
  const accountUsername = account.username;
  const url = new URL(request.url);
  let currentPath = "";
  try {
    currentPath = adminPath(url.searchParams.get("path") || "");
  } catch {
    return textResponse("Invalid path", 400);
  }
  const prefix = currentPath ? `${currentPath}/` : "";
  // 游标循环取全量一级条目，避免单页上限静默截断
  const directorySet = new Set<string>();
  const files: R2Object[] = [];
  let listCursor: string | undefined;
  do {
    const listed = await env.WEBDAV_BUCKET.list({ prefix, delimiter: "/", cursor: listCursor });
    for (const item of listed.delimitedPrefixes) if (!item.startsWith("__trash/")) directorySet.add(item.slice(0, -1));
    files.push(...listed.objects.filter((item) => !item.key.startsWith("__trash/")));
    listCursor = listed.truncated ? listed.cursor : undefined;
  } while (listCursor);
  // 合并 KV dir: 标记，空目录（无 R2 子对象）也可见，与 PROPFIND 行为一致
  for (const key of await listAllKV(env, DIR_PREFIX)) {
    const directory = decodeURIComponent(key.slice(DIR_PREFIX.length));
    if (!directory.startsWith(prefix) || directory === currentPath) continue;
    const child = directory.slice(prefix.length).split("/")[0];
    if (child && child !== "__trash") directorySet.add(`${prefix}${child}`);
  }
  const directories = [...directorySet];
  const parent = currentPath.includes("/") ? currentPath.slice(0, currentPath.lastIndexOf("/")) : "";
  // 当前账户已用存储空间（读取账户作用域用量缓存，缺档时自动全量重建）
  const usedBytes = await getAccountStorageUsage(env);
  // 搜索 / 排序 / 分页：q 非空时递归搜索当前目录子树（上限 200 条），否则排序后按页切分
  const query = (url.searchParams.get("q") || "").trim().toLowerCase();
  const sortKey = ["name", "size", "time"].includes(url.searchParams.get("sort") || "") ? (url.searchParams.get("sort") as "name" | "size" | "time") : "name";
  const sortOrder = url.searchParams.get("order") === "desc" ? "desc" : "asc";
  const filesPageSize = 50;
  let currentPage = Math.max(1, Number(url.searchParams.get("page")) || 1);
  interface FileEntry { key: string; directory: boolean; size: number; uploaded: string; }
  const compareEntries = (a: FileEntry, b: FileEntry): number => {
    const factor = sortOrder === "desc" ? -1 : 1;
    if (sortKey === "size" && !a.directory && !b.directory) return factor * (a.size - b.size);
    if (sortKey === "time" && !a.directory && !b.directory) return factor * a.uploaded.localeCompare(b.uploaded);
    return factor * a.key.slice(prefix.length).localeCompare(b.key.slice(prefix.length), "zh-CN");
  };
  let searchCapped = false;
  let pageEntries: FileEntry[] = [];
  let totalPages = 1;
  let totalEntries = 0;
  if (query) {
    const matches: FileEntry[] = [];
    const matchedDirs = new Set<string>();
    for (const object of await listAllObjects(env, prefix)) {
      if (object.key.startsWith("__trash/")) continue;
      const relative = object.key.slice(prefix.length);
      if (relative.toLowerCase().includes(query)) matches.push({ key: object.key, directory: false, size: object.size, uploaded: object.uploaded.toISOString() });
      const segments = relative.split("/");
      segments.pop();
      let dir = "";
      for (const segment of segments) {
        dir = dir ? `${dir}/${segment}` : segment;
        if (`${prefix}${dir}`.toLowerCase().includes(query)) matchedDirs.add(`${prefix}${dir}`);
      }
    }
    for (const key of await listAllKV(env, DIR_PREFIX)) {
      const directory = decodeURIComponent(key.slice(DIR_PREFIX.length));
      if (directory.startsWith(prefix) && directory !== currentPath && directory.toLowerCase().includes(query)) matchedDirs.add(directory);
    }
    matches.push(...[...matchedDirs].map((directory) => ({ key: directory, directory: true, size: 0, uploaded: "" })));
    matches.sort(compareEntries);
    searchCapped = matches.length > 200;
    pageEntries = searchCapped ? matches.slice(0, 200) : matches;
    directories.length = 0;
    totalEntries = matches.length;
  } else {
    const entries: FileEntry[] = [
      ...directories.map((directory) => ({ key: directory, directory: true, size: 0, uploaded: "" })),
      ...files.map((file) => ({ key: file.key, directory: false, size: file.size, uploaded: file.uploaded.toISOString() })),
    ].sort(compareEntries);
    totalEntries = entries.length;
    totalPages = Math.max(1, Math.ceil(totalEntries / filesPageSize));
    currentPage = Math.min(currentPage, totalPages);
    pageEntries = entries.slice((currentPage - 1) * filesPageSize, currentPage * filesPageSize);
  }
  // 批量操作结果提示（重定向回跳参数）：仅接受纯数字计数，拒绝任意拼接值以防注入
  const countParam = (value: string | null): number | null => {
    if (value === null || !/^\d+$/.test(value)) return null;
    const count = Number(value);
    return Number.isSafeInteger(count) ? count : null;
  };
  const deletedCount = countParam(url.searchParams.get("deleted"));
  const movedCount = countParam(url.searchParams.get("moved"));
  const skippedCount = countParam(url.searchParams.get("skipped")) ?? 0;
  const missingCount = countParam(url.searchParams.get("missing")) ?? 0;
  const failedCount = countParam(url.searchParams.get("failed")) ?? 0;
  const copiedFlag = countParam(url.searchParams.get("copied"));
  const noticeParts: string[] = [];
  if (deletedCount !== null) noticeParts.push(deletedCount ? `成功删除 ${deletedCount} 项，内容已移入回收站` : "未删除任何项（可能已被删除或不存在）");
  if (movedCount !== null) {
    const detail = [skippedCount ? `，${skippedCount} 项因目标已存在同名内容被跳过` : "", missingCount ? `，${missingCount} 项已不存在` : "", failedCount ? `，${failedCount} 项处理失败` : ""].filter(Boolean).join("");
    noticeParts.push(`成功移动 ${movedCount} 项${detail}`);
  }
  const sharedToken = (url.searchParams.get("shared") || "").replace(/[^A-Za-z0-9_-]/g, "");
  const sharedExpires = url.searchParams.get("sharedExpires") || "";
  if (sharedToken) noticeParts.push(`分享链接已创建：<a href="/s/${sharedToken}">${escapeHtml(new URL(request.url).origin)}/s/${sharedToken}</a>${sharedExpires ? `（有效期至 ${escapeHtml(sharedExpires)}）` : ""}`);
  if (url.searchParams.get("shareRevoked") === "1") noticeParts.push("分享链接已取消");
  if (copiedFlag) noticeParts.push("文件复制成功");
  const batchNotice = noticeParts.length ? `<div class="batch-notice">${noticeParts.join("；")}</div>` : "";
  // 移动目标下拉：收集账户内全部目录（dir: 标记 + R2 对象父链推导），排除 __trash 与当前目录自身及其子目录（移入即冲突）
  const targetDirOptions = new Set<string>(directorySet);
  for (const object of await listAllObjects(env, "")) {
    const segments = object.key.split("/");
    if (segments.includes("__trash")) continue;
    segments.pop();
    let dir = "";
    for (const segment of segments) { dir = dir ? `${dir}/${segment}` : segment; targetDirOptions.add(dir); }
  }
  for (const key of await listAllKV(env, DIR_PREFIX)) {
    const dir = decodeURIComponent(key.slice(DIR_PREFIX.length));
    if (dir && !dir.split("/").includes("__trash")) targetDirOptions.add(dir);
  }
  const targetDirs = [...targetDirOptions].filter((dir) => !currentPath || (dir !== currentPath && !dir.startsWith(`${currentPath}/`))).sort();
  // 多级分组：按父目录分 optgroup，同一组内不会同时出现某目录与其子目录（如 b 与 b/sub 分属两级）
  const childrenByParent = new Map<string, string[]>();
  for (const dir of targetDirs) {
    const parent = dir.includes("/") ? dir.slice(0, dir.lastIndexOf("/")) : "";
    const siblings = childrenByParent.get(parent) ?? [];
    siblings.push(dir);
    childrenByParent.set(parent, siblings);
  }
  // 级联多级菜单（类 Windows 资源管理器）：有子目录的条目悬停时向右弹出子菜单列，点击条目即选中该目录
  const renderDirMenuItems = (parent: string): string => (childrenByParent.get(parent) ?? []).map((dir) => {
    const children = childrenByParent.get(dir);
    const name = escapeHtml(parent ? dir.slice(parent.length + 1) : dir);
    return `<div class="dir-menu-item${children ? " has-children" : ""}" data-path="${escapeHtml(dir)}"><span class="dir-menu-label">${name}</span>${children ? `<span class="dir-menu-arrow">▸</span><div class="dir-menu-submenu">${renderDirMenuItems(dir)}</div>` : ""}</div>`;
  }).join("");
  const dirMenuItems = renderDirMenuItems("");
  const batchToolbar = `<form id="files-batch-form" method="post" action="/?view=files" class="batch-toolbar"><input type="hidden" name="accountUsername" value="${escapeHtml(accountUsername)}"><input type="hidden" name="currentPath" value="${escapeHtml(currentPath)}"><span class="batch-hint">已选 <b id="batch-count">0</b> 项</span><div class="dir-menu" id="dir-menu"><button type="button" class="batch-target-input" id="dir-menu-button" aria-haspopup="true">根目录</button><input type="hidden" name="targetDir" id="target-dir-input" value=""><div class="dir-menu-panel" id="dir-menu-panel" hidden><div class="dir-menu-item" data-path=""><span class="dir-menu-label">根目录</span></div>${dirMenuItems}</div></div><button class="secondary-button" type="submit" name="action" value="batch-move" onclick="return confirmBatchMove()">移动选中</button><button class="danger-button" type="submit" name="action" value="batch-delete" onclick="return confirmBatchDelete()">删除选中</button></form><script>function checkedFileCount(){return document.querySelectorAll('.file-check:checked').length}function toggleFileSelect(checked){document.querySelectorAll('.file-check').forEach(function(c){c.checked=checked});updateBatchCount()}function updateBatchCount(){var el=document.getElementById('batch-count');if(el)el.textContent=checkedFileCount()}function confirmBatchDelete(){var n=checkedFileCount();if(!n){alert('请先勾选要操作的文件或目录');return false}return confirm('确定删除选中的 '+n+' 项吗？内容将移入回收站，可在 ${TRASH_RETENTION_DAYS} 天内恢复。')}function confirmBatchMove(){var n=checkedFileCount();if(!n){alert('请先勾选要操作的文件或目录');return false}var t=document.getElementById('target-dir-input').value||'根目录';return confirm('确定将选中的 '+n+' 项移动到「'+t+'」吗？目标已存在同名内容时将跳过。')}document.addEventListener('change',function(e){if(e.target&&e.target.classList&&e.target.classList.contains('file-check'))updateBatchCount()});var mb=document.getElementById('dir-menu-button'),mp=document.getElementById('dir-menu-panel');mb.addEventListener('click',function(e){e.stopPropagation();mp.hidden=!mp.hidden});document.addEventListener('click',function(e){if(!mp.hidden&&!document.getElementById('dir-menu').contains(e.target))mp.hidden=true});mp.addEventListener('click',function(e){if(e.target.classList&&e.target.classList.contains('dir-menu-arrow')){e.stopPropagation();e.target.parentElement.classList.toggle('open');return}var it=e.target.closest?e.target.closest('.dir-menu-item'):null;if(!it)return;document.getElementById('target-dir-input').value=it.getAttribute('data-path');mb.textContent=it.getAttribute('data-path')||'根目录';mp.hidden=true});mp.addEventListener('mouseover',function(e){var it=e.target.closest?e.target.closest('.dir-menu-item'):null;if(!it||!it.classList.contains('has-children'))return;it.classList.toggle('flip-left',it.getBoundingClientRect().right+210>window.innerWidth)})</script>`;
  // 生效中的分享链接（全局 KV 存储按账户过滤）
  const activeShares: { token: string; path: string; expiresAt: string }[] = [];
  for (const key of await listAllKV(rootEnv, SHARE_PREFIX)) {
    const shareRecord = await rootEnv.WEBDAV_KV.get(key, "json") as { account?: string; path?: string; expiresAt?: string } | null;
    if (shareRecord && shareRecord.account === accountUsername && shareRecord.expiresAt && Date.parse(shareRecord.expiresAt) > Date.now()) {
      activeShares.push({ token: key.slice(SHARE_PREFIX.length), path: shareRecord.path || "", expiresAt: shareRecord.expiresAt });
    }
  }
  activeShares.sort((a, b) => a.expiresAt.localeCompare(b.expiresAt));
  const sharesSection = activeShares.length ? `<section class="file-table-wrap shares-section"><div class="card-heading"><div><p class="eyebrow">ACTIVE SHARES</p><h2>生效中的分享链接</h2></div></div><table><thead><tr><th>文件</th><th>链接</th><th>有效期至</th><th>操作</th></tr></thead><tbody>${activeShares.map((share) => `<tr><td>${escapeHtml(share.path)}</td><td><a href="/s/${share.token}">/s/${share.token}</a></td><td>${formatDateTime(new Date(share.expiresAt))}</td><td><form method="post" action="/?view=files" onsubmit="return confirm('确定取消该分享链接吗？')"><input type="hidden" name="action" value="revoke-share"><input type="hidden" name="accountUsername" value="${escapeHtml(accountUsername)}"><input type="hidden" name="currentPath" value="${escapeHtml(currentPath)}"><input type="hidden" name="token" value="${escapeHtml(share.token)}"><button class="danger-button" type="submit">取消分享</button></form></td></tr>`).join("")}</tbody></table></section>` : "";
  const origin = new URL(request.url).origin;
  const pageUrl = (overrides: Record<string, string>): string => {
    const params = new URLSearchParams({ view: "files", account: accountUsername });
    if (currentPath) params.set("path", currentPath);
    if (query) params.set("q", query);
    if (sortKey !== "name") { params.set("sort", sortKey); params.set("order", sortOrder); }
    for (const [key, value] of Object.entries(overrides)) params.set(key, value);
    return `/?${params}`;
  };
  const sortLink = (key: "name" | "size" | "time", label: string): string => {
    const marker = sortKey === key ? (sortOrder === "asc" ? " ▲" : " ▼") : "";
    const nextOrder = sortKey === key && sortOrder === "asc" ? "desc" : "asc";
    return `<a class="sort-link" href="${pageUrl({ sort: key, order: nextOrder })}">${label}${marker}</a>`;
  };
  const pager = !query && totalPages > 1 ? `<nav class="files-pager">${currentPage > 1 ? `<a class="pager-link" href="${pageUrl({ page: String(currentPage - 1) })}">‹ 上一页</a>` : `<span class="pager-link disabled">‹ 上一页</span>`}<span class="pager-status">第 ${currentPage} / ${totalPages} 页（共 ${totalEntries} 项）</span>${currentPage < totalPages ? `<a class="pager-link" href="${pageUrl({ page: String(currentPage + 1) })}">下一页 ›</a>` : `<span class="pager-link disabled">下一页 ›</span>`}</nav>` : "";
  const searchHint = query ? `<p class="muted search-hint">${searchCapped ? `匹配项较多，仅显示前 200 条，请细化关键词（共 ${totalEntries} 项匹配）。` : `搜索“${escapeHtml(url.searchParams.get("q") || "")}”，共 ${totalEntries} 项匹配。`}</p>` : "";
  const shareExpirySelect = `<select name="expiresIn" class="share-expiry" title="有效期"><option value="1">1 小时</option><option value="24" selected>1 天</option><option value="168">7 天</option><option value="720">30 天</option></select>`;
  // 预览：图片文件行内直接展示缩略图，文件名可点击进入预览页；复制按钮的建议副本名服务端生成
  const previewUrl = (key: string): string => `/?api=preview&account=${encodeURIComponent(accountUsername)}&path=${encodeURIComponent(key)}`;
  const suggestedCopyName = (key: string): string => {
    const name = key.slice(key.lastIndexOf("/") + 1);
    const dot = name.lastIndexOf(".");
    return `${dot > 0 ? name.slice(0, dot) : name} - 副本${dot > 0 ? name.slice(dot) : ""}`;
  };
  const rows = [
    ...(currentPath && !query ? [`<tr><td class="check-col"></td><td class="file-name"><a href="/?view=files&account=${encodeURIComponent(accountUsername)}${parent ? `&path=${encodeURIComponent(parent)}` : ""}">↩ 返回上级目录</a></td><td>目录</td><td>-</td><td>-</td><td>-</td></tr>`] : []),
    ...pageEntries.map((entry) => entry.directory ? `<tr><td class="check-col"><input type="checkbox" class="file-check" form="files-batch-form" name="paths" value="${escapeHtml(entry.key)}"></td><td class="file-name"><span class="folder-icon">DIR</span><a href="/?view=files&account=${encodeURIComponent(accountUsername)}&path=${encodeURIComponent(entry.key)}">${escapeHtml(entry.key.slice(prefix.length))}/</a></td><td>目录</td><td>-</td><td>-</td><td><form method="post" action="/?view=files" onsubmit="return confirm('删除该目录及其内部所有文件吗？内容将移入回收站，可在 ${TRASH_RETENTION_DAYS} 天内恢复。')"><input type="hidden" name="action" value="delete"><input type="hidden" name="accountUsername" value="${escapeHtml(accountUsername)}"><input type="hidden" name="path" value="${escapeHtml(entry.key)}"><input type="hidden" name="currentPath" value="${escapeHtml(currentPath)}"><button class="danger-button" type="submit">删除</button></form></td></tr>` : `<tr><td class="check-col"><input type="checkbox" class="file-check" form="files-batch-form" name="paths" value="${escapeHtml(entry.key)}"></td><td class="file-name">${previewKindOf(entry.key.slice(entry.key.lastIndexOf("/") + 1)) === "image" ? `<img class="file-thumb" loading="lazy" src="${previewUrl(entry.key)}" alt="">` : `<span class="file-icon">FILE</span>`}<a href="/?view=preview&account=${encodeURIComponent(accountUsername)}&path=${encodeURIComponent(entry.key)}">${escapeHtml(entry.key.slice(prefix.length))}</a></td><td>文件</td><td>${formatBytes(entry.size)}</td><td>${formatDateTime(new Date(entry.uploaded))}</td><td><div class="row-actions"><form method="post" action="/?view=files" class="share-form" onsubmit="return confirm('创建该文件的公开分享链接吗？任何人在有效期内都可通过链接下载。')"><input type="hidden" name="action" value="create-share"><input type="hidden" name="accountUsername" value="${escapeHtml(accountUsername)}"><input type="hidden" name="currentPath" value="${escapeHtml(currentPath)}"><input type="hidden" name="path" value="${escapeHtml(entry.key)}">${shareExpirySelect}<button class="secondary-button" type="submit">分享</button></form><form method="post" action="/?view=files" class="copy-form"><input type="hidden" name="action" value="copy-file"><input type="hidden" name="accountUsername" value="${escapeHtml(accountUsername)}"><input type="hidden" name="currentPath" value="${escapeHtml(currentPath)}"><input type="hidden" name="path" value="${escapeHtml(entry.key)}"><input type="hidden" name="copyName"><button class="secondary-button" type="button" data-suggest="${escapeHtml(suggestedCopyName(entry.key))}" onclick="return promptCopy(this.form, this.getAttribute('data-suggest'))">复制</button></form><form method="post" action="/?view=files" onsubmit="return confirm('确认删除此文件吗？')"><input type="hidden" name="action" value="delete"><input type="hidden" name="accountUsername" value="${escapeHtml(accountUsername)}"><input type="hidden" name="path" value="${escapeHtml(entry.key)}"><input type="hidden" name="currentPath" value="${escapeHtml(currentPath)}"><button class="danger-button" type="submit">删除</button></form></div></td></tr>`),
  ].join("");
    return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>文件管理</title><style>${ADMIN_CSS}${FILES_CSS}</style><body>${topbarHtml("文件管理", `<a class="text-link inverse" href="/?view=account&account=${encodeURIComponent(accountUsername)}">返回账户管理</a><a class="text-link inverse" href="/">返回账户选择</a>`)}<main class="dashboard">${pageHeadingHtml("FILE MANAGER", "文件管理", `账户：${accountUsername}　当前位置：/${currentPath}`, `<div class="files-storage-stack"><div class="storage-badge"><span>当前账户已用空间${account.quotaBytes ? " / 配额" : ""}</span><strong>${formatStorageUsage(usedBytes)}${account.quotaBytes ? ` / ${formatStorageUsage(account.quotaBytes)}` : ""}</strong></div><a class="secondary-button" href="/?view=trash&account=${encodeURIComponent(accountUsername)}">回收站</a></div>`)}${batchNotice}<section class="files-search"><form method="get" action="/" class="files-search-form"><input type="hidden" name="view" value="files"><input type="hidden" name="account" value="${escapeHtml(accountUsername)}"><input type="hidden" name="path" value="${escapeHtml(currentPath)}"><input name="q" type="search" placeholder="搜索当前目录及子目录内的文件" value="${escapeHtml(url.searchParams.get("q") || "")}"><button class="secondary-button" type="submit">搜索</button>${query ? `<a class="text-link" href="${pageUrl({ q: "" })}">清除搜索</a>` : ""}</form></section><section class="file-actions"><article class="file-action-card upload-card" id="upload-card"><div class="file-action-heading"><strong>上传文件</strong><span>支持拖拽与多文件，大文件流式上传并显示进度</span></div><div class="upload-row"><input type="file" id="upload-file-input" multiple><button class="primary-button" type="button" onclick="return startUpload()">上传文件</button></div><div class="upload-queue" id="upload-queue"></div><span class="upload-status" id="upload-status"></span></article><article class="file-action-card"><div class="file-action-heading"><strong>新建目录</strong><span>在当前目录创建一个文件夹</span></div><form method="post" action="/?view=files" class="mkdir-form"><input type="hidden" name="action" value="mkdir"><input type="hidden" name="accountUsername" value="${escapeHtml(accountUsername)}"><input type="hidden" name="currentPath" value="${escapeHtml(currentPath)}"><input name="name" placeholder="目录名称" required><button class="secondary-button" type="submit">新建目录</button></form></article></section><section class="file-table-wrap"><table><thead><tr><th class="check-col"><input type="checkbox" id="files-select-all" onchange="toggleFileSelect(this.checked)" title="全选" aria-label="全选"></th><th>${sortLink("name", "名称")}</th><th>类型</th><th>${sortLink("size", "大小")}</th><th>${sortLink("time", "上传时间")}</th><th>操作</th></tr></thead><tbody>${rows || `<tr><td colspan="6" class="empty-state">${query ? "没有匹配的文件" : "当前目录为空"}</td></tr>`}</tbody></table></section>${pager}${batchToolbar}${sharesSection}<script>function startUpload(){var input=document.getElementById('upload-file-input');var files=input.files&&input.files.length?Array.prototype.slice.call(input.files):[];if(!files.length){alert('请先选择文件');return false}startUploadQueue(files);return false}function startUploadQueue(files){var queue=document.getElementById('upload-queue'),status=document.getElementById('upload-status');status.textContent='';var failed=0;var items=files.map(function(f){var row=document.createElement('div');row.className='upload-item';var nm=document.createElement('span');nm.className='upload-name';nm.textContent=f.name;var bar=document.createElement('div');bar.className='upload-progress';var inner=document.createElement('div');bar.appendChild(inner);var st=document.createElement('span');st.className='upload-item-status';st.textContent='等待中';row.appendChild(nm);row.appendChild(bar);row.appendChild(st);queue.appendChild(row);return {file:f,bar:inner,state:st}});function next(i){if(i>=items.length){status.textContent='全部完成：成功 '+(items.length-failed)+' 个'+(failed?'，失败 '+failed+' 个':'');document.getElementById('upload-file-input').value='';if(!failed)location.reload();return}var it=items[i];it.state.textContent='上传中';it.state.className='upload-item-status active';var xhr=new XMLHttpRequest();xhr.open('POST','/?view=files&action=upload-stream&account=${encodeURIComponent(accountUsername)}&path=${encodeURIComponent(currentPath)}&name='+encodeURIComponent(it.file.name));xhr.upload.onprogress=function(e){if(e.lengthComputable){var p=Math.round(e.loaded/e.total*100);it.bar.style.width=p+'%';it.state.textContent='上传中 '+p+'%'}};xhr.onload=function(){if(xhr.status===201){it.bar.style.width='100%';it.state.textContent='完成';it.state.className='upload-item-status ok';next(i+1)}else{it.state.textContent='失败：'+(xhr.responseText||('HTTP '+xhr.status));it.state.className='upload-item-status err';failed++;next(i+1)}};xhr.onerror=function(){it.state.textContent='失败，请重试';it.state.className='upload-item-status err';failed++;next(i+1)};xhr.send(it.file)}next(0)}function promptCopy(form,suggested){var name=prompt('复制为新名称（保存在当前目录）：',suggested||'');if(name===null)return false;name=name.trim();if(!name||name.indexOf('/')>=0||name.indexOf(String.fromCharCode(92))>=0||name.indexOf('..')>=0){alert('名称不合法');return false}form.elements['copyName'].value=name;form.submit();return false}(function(){var card=document.getElementById('upload-card');if(!card)return;['dragover','dragenter'].forEach(function(ev){card.addEventListener(ev,function(e){e.preventDefault();card.classList.add('drag-over')})});['dragleave','drop'].forEach(function(ev){card.addEventListener(ev,function(e){e.preventDefault();card.classList.remove('drag-over')})});card.addEventListener('drop',function(e){var files=e.dataTransfer&&e.dataTransfer.files;if(files&&files.length)startUploadQueue(Array.prototype.slice.call(files))})})()</script></main></body></html>`);
}

function adminLoginPage(error = ""): Response {
  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>WebDAV 管理登录</title><style>${ADMIN_CSS}</style><main class="login-shell"><section class="login-panel"><div class="brand-mark">WD</div><p class="eyebrow">CLOUD STORAGE</p><h1>WebDAV 管理</h1><p class="muted">登录后管理账号、访问日志和文件。</p>${error ? `<p class="notice success">${escapeXml(error)}</p>` : ""}<form method="post" action="/__admin/login"><label>用户名<input name="username" autocomplete="username" required></label><label>密码<input name="password" type="password" autocomplete="current-password" required></label><label>两步验证码（未启用可留空，支持恢复码）<input name="totpCode" inputmode="numeric" autocomplete="one-time-code" placeholder="6 位验证码或 8 位恢复码"></label><button class="primary-button" type="submit">登录管理后台</button></form><a class="secondary-button register-button" href="/__admin/register">注册新用户</a></section></main>`);
}

// 新增：用户级修改密码页面（需校验当前密码）；同时内嵌 TOTP 令牌管理卡片（新增/删除/打开两步验证设置）
async function adminChangePasswordPage(env: Env, sessionUser: string, message = "", error = "", pendingSecret = "", recoveryCodes: string[] = [], currentToken = ""): Promise<Response> {
  const account = (await getAdminAccounts(env))[sessionUser];
  const totpEnabled = Boolean(account?.totpSecret);
  if (!pendingSecret) pendingSecret = (await env.WEBDAV_KV.get(`${TOTP_PENDING_PREFIX}${sessionUser}`)) ?? "";
  // 活跃会话列表：按最后活跃时间倒序，标记当前会话
  const sessionList = await listUserSessions(env, sessionUser);
  const sessionItems = sessionList.map((session) => {
    const isCurrent = currentToken && session.name === `${SESSION_PREFIX}${currentToken}`;
    const remainingHours = session.exp ? Math.max(0, Math.round((session.exp - Date.now()) / 3600000)) : null;
    return `<li style="display:flex;flex-direction:column;gap:2px;padding:10px 12px;border:1px solid var(--card-border,#dfe7e4);border-radius:8px"><strong>${isCurrent ? "本会话（当前设备）" : "其他会话"}</strong><span class="muted">最后活跃：${new Date(session.lastSeen).toLocaleString("zh-CN")}${remainingHours !== null ? ` · 约 ${remainingHours} 小时后过期` : ""}</span></li>`;
  }).join("");
  const recoveryPanel = recoveryCodes.length ? `<section class="login-panel"><p class="eyebrow">RECOVERY CODES</p><h1>恢复码</h1><p class="muted">验证器不可用时，可在登录页的两步验证码输入框中输入任一恢复码登录。每个恢复码仅可使用一次，且<strong>仅本次显示</strong>，请立即保存到安全的地方。</p><div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:8px;font-size:16px;letter-spacing:1px">${recoveryCodes.map((code) => `<code>${code}</code>`).join("")}</div></section>` : "";
  const sessionsPanel = `<section class="login-panel"><p class="eyebrow">ACTIVE SESSIONS</p><h1>活跃会话</h1><p class="muted">当前共 ${sessionList.length} 个活跃会话（同一账户最多同时保留 5 个，超出时最早登录的会话会被自动吊销）。修改密码或退出会吊销全部会话。</p><ul style="list-style:none;padding:0;margin:0 0 14px;display:flex;flex-direction:column;gap:10px">${sessionItems}</ul><form method="post" action="/?view=change-password"><input type="hidden" name="action" value="logout-others"><button class="secondary-button" type="submit" onclick="return confirm('确定登出其他所有设备吗？当前设备保持登录。')">登出其他设备</button></form></section>`;
  const pwPanel = `<section class="login-panel"><div class="brand-mark">WD</div><p class="eyebrow">ACCOUNT SECURITY</p><h1>安全设置</h1><p class="muted">为保障账户安全，修改密码前需要先验证当前密码。</p>${message ? `<p class="notice success">${escapeXml(message)}</p>` : ""}${error ? `<p class="error">${escapeXml(error)}</p>` : ""}<form method="post" action="/?view=change-password"><input type="hidden" name="action" value="change-own-password"><label>当前密码<input name="currentPassword" type="password" autocomplete="current-password" required></label><label>新密码<input name="newPassword" type="password" autocomplete="new-password" minlength="8" placeholder="至少 8 位" required></label><label>确认新密码<input name="confirmPassword" type="password" autocomplete="new-password" minlength="8" required></label><button class="primary-button" type="submit">保存新密码</button></form></section>`;
  const totpPanel = `<section class="login-panel totp-panel"><p class="eyebrow">TWO-FACTOR</p><h1>TOTP 令牌</h1><p class="muted">新增令牌后，登录除密码外还需输入验证器动态码。支持 Google Authenticator、1Password 等标准验证器。当前状态：<strong>${totpEnabled ? "已启用" : "未启用"}</strong></p>${error ? `<p class="error">${escapeXml(error)}</p>` : ""}${message ? `<p class="notice success">${escapeXml(message)}</p>` : ""}${totpEnabled ? `<form method="post" action="/?view=change-password"><input type="hidden" name="action" value="totp-disable"><label>输入当前验证码以删除令牌<input name="totpCode" inputmode="numeric" autocomplete="one-time-code" placeholder="6 位数字" required></label><button class="danger-button totp-button" type="submit" onclick="return confirm('确定删除 TOTP 令牌吗？删除后登录仅需密码。')">删除 TOTP 令牌</button></form>` : pendingSecret ? `<p><strong>密钥（手动输入用）：</strong><code>${escapeXml(pendingSecret)}</code></p><p class="muted">或在验证器中添加以下 URI：</p><p class="totp-uri"><code>${escapeXml(`otpauth://totp/WebDAV:${encodeURIComponent(sessionUser)}?secret=${pendingSecret}&issuer=WebDAV`)}</code></p><form method="post" action="/?view=change-password"><input type="hidden" name="action" value="totp-setup-confirm"><label>输入验证器显示的 6 位动态码确认绑定<input name="totpCode" inputmode="numeric" autocomplete="one-time-code" placeholder="6 位数字" required></label><button class="primary-button" type="submit">确认绑定</button></form>` : `<form method="post" action="/?view=change-password"><input type="hidden" name="action" value="totp-setup-start"><button class="primary-button" type="submit">新增 TOTP 令牌</button></form>`}<a class="secondary-button inline-button totp-open" href="/?view=security">打开两步验证设置</a></section>`;
  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>安全设置</title><style>${ADMIN_CSS}${CHANGE_PW_CSS}</style><body>${topbarHtml("安全设置", `<a class="text-link inverse" href="/">返回首页</a>`)}<main class="login-shell"><div class="pw-grid">${pwPanel}${totpPanel}${recoveryPanel}${sessionsPanel}</div></main></body></html>`);
}

// 账户安全设置页：TOTP 两步验证（生成/确认/解绑）+ IP 白名单（登录与 WebDAV 共用）
async function securityPage(request: Request, env: Env, sessionUser: string, extra: { message?: string; error?: string; pendingSecret?: string; recoveryCodes?: string[] } = {}): Promise<Response> {
  const account = (await getAdminAccounts(env))[sessionUser];
  const totpEnabled = Boolean(account?.totpSecret);
  const pendingSecret = extra.pendingSecret ?? "";
  const allowlist = account?.ipAllowlist ?? [];
  const clientIp = clientIpOf(request);
  const textareaStyle = "display:block;width:100%;min-height:110px;margin-top:7px;padding:13px 14px;border:1px solid #cbd7d3;border-radius:2px;background:#fbfcfa;color:#17212b;font:inherit;outline:none";
  const totpCard = `<article class="config-card"><div class="card-heading"><div><p class="eyebrow">TWO-FACTOR</p><h2>TOTP 两步验证</h2></div><span class="icon-badge">${totpEnabled ? "ON" : "OFF"}</span></div><p class="muted">绑定后登录管理后台除密码外还需输入验证器动态码，防止密码泄露后被异地登录。支持 Google Authenticator、1Password 等标准验证器。</p>${extra.error ? `<p class="error">${escapeHtml(extra.error)}</p>` : ""}${extra.message ? `<p class="notice success">${escapeHtml(extra.message)}</p>` : ""}${totpEnabled ? `<form method="post" action="/?view=security" class="config-form"><input type="hidden" name="action" value="totp-disable"><label>输入当前验证码以解除绑定<input name="totpCode" inputmode="numeric" autocomplete="one-time-code" placeholder="6 位数字" required></label><button class="danger-button" type="submit" onclick="return confirm('确定解除两步验证吗？解除后登录仅需密码。')">解除绑定</button></form>` : pendingSecret ? `<div class="config-form"><p><strong>密钥（手动输入用）：</strong><code>${escapeHtml(pendingSecret)}</code></p><p class="muted">或在验证器中添加以下 URI：</p><p class="totp-uri"><code>${escapeHtml(`otpauth://totp/WebDAV:${encodeURIComponent(sessionUser)}?secret=${pendingSecret}&issuer=WebDAV`)}</code></p><form method="post" action="/?view=security"><input type="hidden" name="action" value="totp-setup-confirm"><label>输入验证器显示的 6 位动态码确认绑定<input name="totpCode" inputmode="numeric" autocomplete="one-time-code" placeholder="6 位数字" required></label><button class="primary-button" type="submit">确认绑定</button></form></div>` : `<form method="post" action="/?view=security" class="config-form"><input type="hidden" name="action" value="totp-setup-start"><button class="primary-button" type="submit">生成密钥并开始绑定</button></form>`}</article>`;
  const allowlistCard = `<article class="config-card"><div class="card-heading"><div><p class="eyebrow">IP ALLOWLIST</p><h2>IP 白名单</h2></div><span class="icon-badge">${allowlist.length || "∞"}</span></div><p class="muted">限制管理后台登录与 WebDAV 访问的来源 IP。每行一条，支持精确 IP（1.2.3.4）、IPv4 前缀（1.2.3. 或 1.2.）与 CIDR（1.2.3.0/24）。留空表示不限制。当前来源 IP：<code>${escapeHtml(clientIp)}</code>${clientIp === "unknown" ? "（本地开发环境无法获取真实 IP，配置后登录可能被拒绝）" : ""}</p>${allowlist.length ? `<p class="muted">当前规则：${allowlist.map((entry) => `<code>${escapeHtml(entry)}</code>`).join("、")}</p>` : ""}<form method="post" action="/?view=security" class="config-form"><input type="hidden" name="action" value="ip-allowlist-save"><label>白名单（每行一条，留空清空）<textarea name="allowlist" style="${textareaStyle}" spellcheck="false" placeholder="1.2.3.4&#10;1.2.3.&#10;1.2.3.0/24">${escapeHtml(allowlist.join("\n"))}</textarea></label><button class="primary-button" type="submit">保存白名单</button></form></article>`;
  const recoveryCard = extra.recoveryCodes?.length ? `<article class="config-card"><div class="card-heading"><div><p class="eyebrow">RECOVERY CODES</p><h2>恢复码</h2></div><span class="icon-badge">${extra.recoveryCodes.length}</span></div><p class="muted">验证器不可用时，可在登录页的两步验证码输入框中输入任一恢复码登录。每个恢复码仅可使用一次，且<strong>仅本次显示</strong>，请立即保存到安全的地方。</p><div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:8px;font-size:16px;letter-spacing:1px">${extra.recoveryCodes.map((code) => `<code>${escapeHtml(code)}</code>`).join("")}</div></article>` : "";
  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>两步验 证与 IP 白名单</title><style>${ADMIN_CSS}</style><body>${topbarHtml("两步验证与 IP 白名单", `<a class="text-link inverse" href="/">返回首页</a><a class="text-link inverse" href="/?action=logout">退出登录</a>`)}<main class="dashboard">${pageHeadingHtml("ACCOUNT SECURITY", "两步验证与 IP 白名单", "两步验证与来源 IP 限制 同时作用于管理后台登录与 WebDAV 客户端访问。")}<section class="content-grid">${totpCard}${allowlistCard}${recoveryCard}</section></main></body></html>`);
}

function adminRegisterPage(env: Env, error = ""): Response {
  const minLength = getMinPasswordLength(env);
  // Turnstile 组件：配置 TURNSTILE_SITE_KEY 后渲染人机验证（服务端配合 TURNSTILE_SECRET_KEY 强制校验）
  const turnstile = env.TURNSTILE_SITE_KEY ? `<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script><div class="cf-turnstile" data-sitekey="${escapeXml(env.TURNSTILE_SITE_KEY)}" data-theme="auto"></div>` : "";
  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>注册新用户</title><style>${ADMIN_CSS}</style><main class="login-shell"><section class="login-panel"><div class="brand-mark">WD</div><p class="eyebrow">NEW USER</p><h1>注册新用户</h1><p class="muted">创建用于登录管理界面的普通用户账户。</p>${error ? `<p class="error">${escapeXml(error)}</p>` : ""}<form method="post" action="/__admin/register"><label>用户名<input name="username" autocomplete="username" required></label><label>密码<input name="password" type="password" autocomplete="new-password" minlength="${minLength}" required></label><label>确认密码<input name="confirmPassword" type="password" autocomplete="new-password" minlength="${minLength}" required></label>${turnstile}<button class="primary-button" type="submit">注册新用户</button></form><a class="secondary-button inline-button" href="/">返回登录</a></section></main>`);
}

async function adminPage(request: Request, env: Env, message = ""): Promise<Response> {
  const adminUsername = await sessionUser(request, env) || DEFAULT_USERNAME;
  const allAccounts = await getWebdavAccounts(env);
  const ownedAccounts = Object.values(allAccounts).filter((account) => account.owner === adminUsername);
  const usedStorage = await getUserStorageUsage(env, adminUsername);
  return adminLandingPage(request, env, adminUsername, ownedAccounts, createAccountUuid(new Set(Object.values(allAccounts).map((account) => account.uuid).filter((uuid): uuid is string => Boolean(uuid)))), message, usedStorage);
}

const ADMIN_CSS = `:root{font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#17212b;background:#eef2f1}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:linear-gradient(135deg,#f6f8f5 0%,#e8efed 100%)}a{color:inherit;text-decoration:none}.topbar{background:#183b3f;color:#f4f8f5}.topbar-inner{max-width:1120px;margin:auto;padding:18px 28px;display:flex;align-items:center;justify-content:space-between}.brand{display:flex;align-items:center;gap:12px;font-weight:700;letter-spacing:.01em}.brand-mark{display:grid;place-items:center;width:42px;height:42px;background:#e8b35a;color:#183b3f;font-size:13px;font-weight:900;letter-spacing:-.06em}.brand-mark.small{width:30px;height:30px;font-size:10px}.status-dot{font-size:13px;color:#c4e3cf}.status-dot:before{content:"";display:inline-block;width:7px;height:7px;margin-right:7px;border-radius:50%;background:#6bc58d}.dashboard{max-width:1120px;margin:0 auto;padding:54px 28px 72px}.page-heading{display:flex;align-items:flex-end;justify-content:space-between;gap:24px;margin-bottom:32px}.eyebrow{margin:0 0 9px;color:#8a6940;font-size:11px;font-weight:800;letter-spacing:.16em}.page-heading h1{margin:0;font-size:clamp(30px,5vw,48px);letter-spacing:-.04em}.muted{color:#667578;line-height:1.6}.text-link{color:#32656a;font-size:14px;font-weight:700}.inverse{color:#f4f8f5}.summary-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:22px}.summary-card,.config-card{background:rgba(255,255,255,.82);border:1px solid #d7e0dc;box-shadow:0 12px 30px rgba(31,61,57,.06)}.summary-card{min-height:132px;padding:22px}.summary-card.accent{border-top:3px solid #d79b41}.card-label{display:block;margin-bottom:20px;color:#71807e;font-size:12px;font-weight:700}.summary-card strong{display:block;font-size:22px;letter-spacing:-.02em}.card-meta{display:block;margin-top:8px;color:#84918f;font-size:13px}.content-grid{display:grid;grid-template-columns:1fr 1fr;gap:22px}.config-card{padding:28px}.card-heading{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:8px}.card-heading h2{margin:0;font-size:22px;letter-spacing:-.03em}.icon-badge{display:grid;place-items:center;width:32px;height:32px;background:#eef3ee;color:#8a6940;font-size:11px;font-weight:800}.config-form{margin-top:25px}.config-form label{display:block;margin:17px 0 6px;font-size:13px;font-weight:700}.config-form input{display:block;width:100%;margin-top:7px;padding:13px 14px;border:1px solid #cbd7d3;border-radius:2px;background:#fbfcfa;color:#17212b;font:inherit;outline:none}.config-form input:focus{border-color:#4c8581;box-shadow:0 0 0 3px rgba(76,133,129,.14)}.primary-button{margin-top:20px;padding:12px 18px;border:0;border-radius:2px;background:#d79b41;color:#183b3f;font:inherit;font-weight:800;cursor:pointer}.primary-button:hover{background:#e5ae59}.tool-list{margin-top:17px;border-top:1px solid #e0e7e3}.tool-row{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:20px 0;border-bottom:1px solid #e0e7e3}.tool-row strong,.tool-row small{display:block}.tool-row small{margin-top:5px;color:#71807e;font-size:13px}.arrow{color:#397277;font-size:22px}.info-strip{display:flex;align-items:center;gap:11px;margin-top:22px;padding:16px 19px;background:#e7f0eb;color:#45625d;font-size:13px;line-height:1.5}.info-icon{display:grid;place-items:center;flex:none;width:20px;height:20px;border:1px solid #70968b;border-radius:50%;font-size:12px}.notice{margin:-12px 0 22px;padding:13px 16px;background:#e7f4eb;border-left:3px solid #3d9368}.success{color:#176b48}.error{margin:18px 0;padding:11px 13px;background:#fff0ee;color:#a43f35}.login-shell{display:grid;place-items:center;min-height:100vh;padding:24px}.login-panel{width:min(100%,420px);padding:42px;background:rgba(255,255,255,.9);border:1px solid #d7e0dc;box-shadow:0 18px 50px rgba(31,61,57,.12)}.login-panel h1{margin:0;font-size:32px;letter-spacing:-.04em}.login-panel .muted{margin:10px 0 28px}.login-panel label{display:block;margin:17px 0 6px;font-size:13px;font-weight:700}.login-panel input{display:block;width:100%;margin-top:7px;padding:13px 14px;border:1px solid #cbd7d3;border-radius:2px;background:#fbfcfa;color:#17212b;font:inherit}.login-panel .primary-button{width:100%;margin-top:25px}@media(max-width:720px){.topbar-inner,.dashboard{padding-left:20px;padding-right:20px}.dashboard{padding-top:36px}.page-heading{align-items:flex-start;flex-direction:column}.summary-grid,.content-grid{grid-template-columns:1fr}.config-card{padding:22px}}`;
const USER_TABLE_CSS = `.user-table-card{grid-column:1/-1;margin-top:22px}.filter-label{display:block;max-width:360px;margin:22px 0 16px;font-size:13px;font-weight:700}.filter-label input{display:block;width:100%;margin-top:7px;padding:11px 13px;border:1px solid #cbd7d3;border-radius:2px;background:#fff;color:#17212b;font:inherit}.table-scroll{overflow-x:auto}.user-table{width:100%;min-width:840px;border-collapse:collapse}.user-table th,.user-table td{padding:15px 12px;border-bottom:1px solid #dce5e1;text-align:left;vertical-align:top;font-size:13px}.user-table th{color:#66807a;font-size:11px;letter-spacing:.12em}.user-table tbody th{color:#17212b;font-size:14px;letter-spacing:0}.user-table th:last-child,.user-table td:last-child{width:1%;white-space:nowrap}.account-list{min-width:190px}.account-row{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:8px}.account-row:last-child{margin-bottom:0}.table-form{display:grid;grid-template-columns:repeat(3,minmax(90px,1fr));gap:7px;min-width:330px}.table-form input{width:100%;padding:9px 10px;border:1px solid #cbd7d3;border-radius:2px;background:#fff;color:#17212b;font:inherit}.table-form .primary-button{grid-column:1/-1}.compact-button{padding:8px 11px;font-size:12px}.limit-form,.quota-form{display:inline-flex;align-items:center;gap:8px;white-space:nowrap}.limit-form input,.quota-form input{width:76px;padding:8px 9px;border:1px solid #cbd7d3;border-radius:4px;background:#fff;color:#17212b;font:inherit;text-align:right}.limit-hint{display:block;margin-top:6px;font-size:12px}`;

// 超级管理员界面专属设计：概览统计、双栏操作区、用户卡片式列表（全部颜色走主题变量，自动适配暗色）
const SUPER_ADMIN_CSS = `
.sa-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
.sa-stat{position:relative;overflow:hidden;padding:20px 22px;background:var(--card-bg);border:1px solid var(--card-border);border-radius:12px;box-shadow:var(--card-shadow);transition:transform .2s ease,box-shadow .2s ease}
.sa-stat:hover{transform:translateY(-2px);box-shadow:0 18px 38px rgba(31,61,57,.12)}
.sa-stat:before{content:"";position:absolute;top:0;left:0;right:0;height:3px;background:var(--accent-gold)}
.sa-stat.teal:before{background:var(--accent-teal)}
.sa-stat.green:before{background:#3d9368}
.sa-stat.danger:before{background:var(--danger-border)}
.sa-stat-label{display:block;margin-bottom:12px;color:var(--text-secondary);font-size:12px;font-weight:800;letter-spacing:.08em}
.sa-stat strong{display:block;font-size:30px;letter-spacing:-.03em;color:var(--text-primary);font-variant-numeric:tabular-nums}
.sa-stat strong small{font-size:14px;font-weight:700;color:var(--text-secondary);margin-left:2px}
.sa-stat-meta{display:block;margin-top:6px;color:var(--text-secondary);font-size:12px}
.sa-grid{display:grid;grid-template-columns:5fr 4fr;gap:22px;margin-bottom:24px;align-items:stretch}
.sa-grid>.config-card{position:relative;overflow:hidden;border-radius:12px}
.sa-grid>.config-card:before{content:"";position:absolute;top:0;left:0;right:0;height:3px;background:var(--accent-teal)}
.sa-grid>.config-card:first-child:before{background:var(--accent-gold)}
.sa-grid .icon-badge{border-radius:8px}
.sa-create-form{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:22px}
.sa-field{display:flex;flex-direction:column}
.sa-field.full-row{grid-column:1/-1}
.sa-field label{margin-bottom:8px;font-size:12px;font-weight:800;letter-spacing:.08em;color:var(--text-secondary)}
.sa-input-wrap{position:relative;display:flex}
.sa-input-icon{position:absolute;left:13px;top:50%;transform:translateY(-50%);display:grid;place-items:center;color:var(--text-secondary);pointer-events:none}
.sa-input-wrap input{width:100%;padding:12px 14px 12px 41px;border:1px solid var(--input-border);border-radius:10px;background:var(--input-bg);color:var(--text-primary);font:inherit;outline:none;transition:border-color .15s ease,box-shadow .15s ease}
.sa-input-wrap input::placeholder{color:var(--text-secondary);opacity:.55}
.sa-input-wrap input:focus{border-color:var(--accent-teal);box-shadow:0 0 0 3px rgba(76,133,129,.16)}
.sa-field-hint{margin-top:7px;font-size:12px;line-height:1.5;color:var(--text-secondary)}
.sa-create-form .primary-button{grid-column:1/-1;display:flex;align-items:center;justify-content:center;gap:8px;margin-top:6px;width:100%;border-radius:10px;padding:13px 18px;letter-spacing:.04em}
.sa-create-form .primary-button svg{transition:transform .15s ease}
.sa-create-form .primary-button:hover svg{transform:translateX(3px)}
.sa-info-card ul{margin:16px 0 0;padding-left:18px;color:var(--text-secondary);font-size:13px;line-height:2}
.sa-info-card li strong{color:var(--text-primary)}
.user-table-card{padding:26px 28px;border-radius:12px}
.sa-list-heading{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;flex-wrap:wrap}
.filter-label{margin:18px 0 14px}
.filter-label input{border-radius:8px}
.user-table{min-width:920px}
.user-table th,.user-table td{padding:16px 14px}
.user-table tbody tr{transition:background .15s ease}
.user-table tbody tr:hover{background:rgba(57,114,119,.055)}
[data-theme="dark"] .user-table tbody tr:hover{background:rgba(127,214,216,.07)}
.sa-user-cell{display:flex;align-items:center;gap:12px;min-width:150px}
.sa-avatar{display:inline-grid;place-items:center;flex:none;width:36px;height:36px;border-radius:50%;background:linear-gradient(135deg,var(--accent-teal),#285d5d);color:#f4f8f5;font-weight:800;font-size:15px}
.sa-username{display:block;font-size:15px;font-weight:700;color:var(--text-primary)}
.sa-user-meta{display:flex;align-items:center;gap:7px;margin-top:3px;font-size:12px}
.sa-2fa{padding:1px 7px;border-radius:99px;background:rgba(61,147,104,.14);color:#176b48;font-size:11px;font-weight:800;letter-spacing:.02em}
[data-theme="dark"] .sa-2fa{background:rgba(61,147,104,.22);color:#7fd6a8}
.sa-usage strong{font-size:16px;font-variant-numeric:tabular-nums;color:var(--text-primary)}
.sa-usage strong small{font-size:12px;font-weight:700;color:var(--text-secondary)}
.sa-usage-bar{height:6px;max-width:150px;margin:7px 0 5px;border-radius:99px;background:var(--table-border);overflow:hidden}
.sa-usage-bar span{display:block;height:100%;border-radius:99px;background:var(--accent-teal)}
.sa-usage-bar.warn span{background:var(--accent-gold)}
.sa-usage-bar.full span{background:var(--danger-text)}
.sa-actions{display:flex;flex-wrap:wrap;gap:8px}
.sa-actions form{margin:0}
.sa-actions .danger-button{margin:0}
.sa-danger-zone{margin-top:8px;padding-top:10px;border-top:1px dashed var(--table-border)}
.sa-purge-label{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--text-secondary);white-space:nowrap;margin-bottom:8px}
@media(max-width:980px){.sa-stats{grid-template-columns:repeat(2,1fr)}.sa-grid{grid-template-columns:1fr}}
@media(max-width:640px){.sa-stats{grid-template-columns:1fr}.sa-create-form{grid-template-columns:1fr}}
`;

// 修改密码页双卡布局：改密码面板与 TOTP 令牌面板并排，窄屏堆叠
const CHANGE_PW_CSS = `.pw-grid{display:grid;grid-template-columns:1fr 1fr;gap:24px;align-items:start;max-width:980px;width:100%}.pw-grid .login-panel{width:100%}.totp-panel h1{font-size:26px;margin:0 0 10px}.totp-panel .muted{margin-bottom:18px}.totp-panel form{margin-top:18px}.totp-panel code{display:inline-block;max-width:100%;padding:2px 6px;background:#eef3ee;border-radius:4px;font-size:13px;word-break:break-all}.totp-uri code{font-size:12px}.totp-button{margin-top:14px}.totp-open{margin-top:16px}.totp-panel .danger-button{padding:12px 18px;border:0;background:#c0564a;color:#fff;font-weight:800;cursor:pointer;border-radius:4px}.totp-panel .secondary-button{display:inline-flex;align-items:center;gap:6px;padding:11px 16px;border:1px solid #cbd7d3;border-radius:4px;background:#fff;color:#32656a;font:inherit;font-weight:700;cursor:pointer;text-decoration:none}@media(max-width:820px){.pw-grid{grid-template-columns:1fr}}`;

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
  // NFC 规范化 + 控制字符拒绝：与 adminPath 保持一致，避免跨平台文件名规范不一致与不可见字符注入
  const normalized = relative.normalize("NFC");
  const normalizedSegments = normalized ? normalized.split("/") : [];
  if (normalizedSegments.some((segment) => !segment || segment === "." || segment === ".." || segment === "__trash" || /[\u0000-\u001f\u007f-\u009f]/.test(segment))) throw new Error("invalid path");
  return normalizedSegments.join("/");
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
  // 必须返回 200：部分客户端（如 webdav_client 系 App）写入前用 OPTIONS 探测并严格要求 200，
  // RFC 4918 允许 200/204，主流 WebDAV 服务器（Apache/nginx）均返回 200
  return new Response(null, {
    status: 200,
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
  if (!object) {
    // 目录集合不可下载：返回 405 并列出可用方法（RFC 4918 未定义集合 GET，主流服务器均拒绝）
    if (path && await env.WEBDAV_KV.get(dirKey(path))) return textResponse("Cannot GET a collection", 405, { Allow: "OPTIONS, PROPFIND, HEAD" });
    return textResponse("Not Found", 404);
  }
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
  // 单次上传上限（MAX_UPLOAD_BYTES）：提前拦截并给出友好提示，避免平台层报错难排查
  const maxUploadBytes = getMaxUploadBytes(rootEnv);
  if (maxUploadBytes > 0 && contentLength > maxUploadBytes) return textResponse(`上传内容超过单次上限（${formatBytes(maxUploadBytes)}），请分块或压缩后重试`, 413, { "X-Upload-Limit": String(maxUploadBytes) });
  const quotaResponse = await ensureStorageCapacity(rootEnv, env, account, path, contentLength);
  if (quotaResponse) return quotaResponse;
  const contentType = request.headers.get("Content-Type") ?? "application/octet-stream";
  const object = await env.WEBDAV_BUCKET.put(r2Key(path), request.body, { httpMetadata: { contentType } });
  const metadata: FileMeta = { type: "file", size: object.size, etag: object.httpEtag, contentType, updatedAt: new Date().toISOString() };
  await env.WEBDAV_KV.put(metaKey(path), JSON.stringify(metadata));
  await recordSyncChange(env, path, "modified");
  return new Response(null, { status: 201, headers: { ETag: object.httpEtag } });
}

async function makeCollection(env: Env, path: string, request?: Request): Promise<Response> {
  if (!path) return textResponse("The root collection already exists", 405);
  if (request) {
    // RFC 4918 §9.3.3：MKCOL 携带请求体时返回 415（不支持扩展创建语义）
    if (Number(request.headers.get("Content-Length") || "0") > 0) return textResponse("MKCOL with a request body is not supported", 415);
    const lockResponse = await assertUnlocked(env, path, request, true);
    if (lockResponse) return lockResponse;
  }
  if (await env.WEBDAV_KV.get(dirKey(path)) || await env.WEBDAV_BUCKET.head(r2Key(path))) return textResponse("Collection already exists", 405);
  await env.WEBDAV_KV.put(dirKey(path), new Date().toISOString());
  await recordSyncChange(env, path, "modified");
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
    // 软删除：移动到回收站。KV/R2 统一使用 {时间戳}_{编码路径} 版本键，同名多次删除互不覆盖
    const deletedAtMs = Date.now();
    const versionKey = `${TRASH_PREFIX}${deletedAtMs}_${encodeURIComponent(path)}`;
    const deletedAt = new Date().toISOString();
    const trashMeta = {
      originalPath: path,
      deletedAt,
      size: object.size,
      contentType: object.httpMetadata?.contentType,
    };

    // 复制文件到回收站位置；复制失败必须中断并保留原文件，避免产生无内容的幽灵回收站条目
    const fileContent = await env.WEBDAV_BUCKET.get(r2Key(path));
    if (!fileContent) return textResponse("Failed to copy to trash, please retry", 500);
    await env.WEBDAV_BUCKET.put(`__trash/${versionKey}`, fileContent.body, {
      httpMetadata: fileContent.httpMetadata,
      customMetadata: { originalPath: path, deletedAt },
    });

    // 删除原文件
    await env.WEBDAV_BUCKET.delete(r2Key(path));
    await env.WEBDAV_KV.delete(metaKey(path));
    await env.WEBDAV_KV.delete(propKey(path));
    await recordSyncChange(env, path, "deleted");

    // 记录删除信息到 KV（用于管理界面显示，30 天过期）
    await env.WEBDAV_KV.put(versionKey, JSON.stringify(trashMeta), {
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
  const deletedAtMs = Date.now();
  const deletedAt = new Date().toISOString();
  const versionKey = `${TRASH_PREFIX}${deletedAtMs}_${encodeURIComponent(path)}`;

  // 移动文件到回收站：子对象统一使用目录条目的同一时间戳，恢复/清理时按键前缀精确匹配本批次版本；
  // 单个对象复制失败则整体中断（未删除部分可重试），避免幽灵条目与用量错账
  for (let index = 0; index < objects.length; index += 1000) {
    const batch = objects.slice(index, index + 1000);
    for (const item of batch) {
      const fileContent = await env.WEBDAV_BUCKET.get(item.key);
      if (!fileContent) return textResponse("Failed to copy to trash, please retry", 500);
      await env.WEBDAV_BUCKET.put(`__trash/${TRASH_PREFIX}${deletedAtMs}_${encodeURIComponent(item.key)}`, fileContent.body, {
        httpMetadata: fileContent.httpMetadata,
        customMetadata: { originalPath: item.key, deletedAt },
      });
      await env.WEBDAV_BUCKET.delete(item.key);
    }
  }

  // 删除元数据
  await deleteMetadataUnder(env, path);

  // 记录目录删除信息
  await env.WEBDAV_KV.put(versionKey, JSON.stringify({
    originalPath: path,
    deletedAt,
    isDirectory: true,
    fileCount: objects.length,
  }), { expirationTtl: TRASH_RETENTION_DAYS * 24 * 60 * 60 });
  // sync-collection：目录自身与全部子成员记为已删除（子成员仅记录前 100 条，避免大量 KV 写入）
  await recordSyncChange(env, path, "deleted");
  for (const item of objects.slice(0, 100)) await recordSyncChange(env, item.key, "deleted");

  return new Response(null, { status: 204 });
}

// 解码回收站键名中的路径：新格式为 {13 位时间戳}_{编码路径}；旧格式为未编码原始路径，需容错
function decodeTrashKeyName(keySuffix: string): string {
  const encoded = /^(\d{13})_(.+)$/.exec(keySuffix)?.[2] ?? keySuffix;
  try {
    return decodeURIComponent(encoded);
  } catch {
    return encoded;
  }
}

// 按 KV 版本键收集回收站 R2 对象（新格式：文件精确匹配、目录按版本前缀匹配本批次；旧格式回退按 originalPath 扫描）
async function collectTrashObjects(env: Env, trashKey: string, meta: { originalPath: string; isDirectory?: boolean }): Promise<R2Object[]> {
  const versionPrefix = `__trash/${TRASH_PREFIX}${trashKey}`;
  const matched = meta.isDirectory
    ? (await listAllObjects(env, versionPrefix)).filter((obj) => obj.key === versionPrefix || obj.key.startsWith(`${versionPrefix}/`))
    : (await listAllObjects(env, versionPrefix)).filter((obj) => obj.key === versionPrefix);
  if (matched.length) return matched;
  return (await listAllObjects(env, `__trash/${TRASH_PREFIX}`)).filter((obj) => {
    const originalPath = obj.customMetadata?.originalPath;
    return originalPath === meta.originalPath || originalPath?.startsWith(`${meta.originalPath}/`);
  });
}

// 恢复文件后重建父目录的 dir: 标记（空目录条目也需重建自身，否则 PROPFIND 中不可见）
async function ensureDirectoryMarkers(env: Env, entries: string[]): Promise<void> {
  const dirs = new Set<string>();
  for (const entry of entries) {
    const segments = entry.split("/");
    segments.pop();
    let current = "";
    for (const segment of segments) {
      current = current ? `${current}/${segment}` : segment;
      dirs.add(current);
    }
  }
  for (const dir of dirs) {
    if (!(await env.WEBDAV_KV.get(dirKey(dir)))) await env.WEBDAV_KV.put(dirKey(dir), new Date().toISOString());
  }
}

// 从回收站恢复（trashKey 为 KV 键去掉 TRASH_PREFIX 的版本后缀）。
// 目标路径已存在同名文件时跳过该对象（覆盖即不可逆丢失）；全部冲突时返回 409 且保留回收站条目以便重试。
async function restoreFromTrash(env: Env, trashKey: string, account?: WebdavAccount, rootEnv?: Env): Promise<Response> {
  const trashMeta = await env.WEBDAV_KV.get(`${TRASH_PREFIX}${trashKey}`, "json") as { originalPath: string; deletedAt: string; isDirectory?: boolean } | null;
  if (!trashMeta) return textResponse("Not Found in Trash", 404);

  const trashObjects = await collectTrashObjects(env, trashKey, trashMeta);

  // 恢复前做配额校验（回收站对象不计入用量，恢复将重新计入）
  const plannedBytes = trashObjects.reduce((total, obj) => total + obj.size, 0);
  if (account && rootEnv) {
    const quotaResponse = await ensureStorageCapacity(rootEnv, env, account, trashMeta.originalPath, plannedBytes);
    if (quotaResponse) return quotaResponse;
  }

  const restoredEntries: string[] = trashMeta.isDirectory ? [trashMeta.originalPath] : [];
  let restoredBytes = 0;
  let conflicts = 0;
  for (const obj of trashObjects) {
    const originalPath = obj.customMetadata?.originalPath;
    if (!originalPath) {
      await env.WEBDAV_BUCKET.delete(obj.key);
      continue;
    }
    if (await env.WEBDAV_BUCKET.head(r2Key(originalPath))) {
      conflicts++;
      continue;
    }
    const content = await env.WEBDAV_BUCKET.get(obj.key);
    if (content) {
      await env.WEBDAV_BUCKET.put(originalPath, content.body, {
        httpMetadata: content.httpMetadata,
      });
      restoredBytes += content.size;
    }
    restoredEntries.push(originalPath);
    await env.WEBDAV_BUCKET.delete(obj.key);
  }
  if (conflicts && !restoredBytes) return textResponse("恢复冲突：目标路径已存在同名文件，已跳过", 409);

  // 回收站对象不计入用量，恢复后重新计入
  await ensureDirectoryMarkers(env, restoredEntries);

  // 部分冲突时保留回收站条目，剩余对象可重试恢复
  if (!conflicts) await env.WEBDAV_KV.delete(`${TRASH_PREFIX}${trashKey}`);

  return new Response(null, { status: 204 });
}

// 从回收站永久删除（trashKey 为 KV 键去掉 TRASH_PREFIX 的版本后缀；目录含子树对象）
async function purgeFromTrash(env: Env, trashKey: string): Promise<void> {
  const trashMeta = await env.WEBDAV_KV.get(`${TRASH_PREFIX}${trashKey}`, "json") as { originalPath: string; deletedAt: string; isDirectory?: boolean } | null;
  if (!trashMeta) return;

  const trashObjects = await collectTrashObjects(env, trashKey, trashMeta);
  for (let index = 0; index < trashObjects.length; index += 1000) {
    await env.WEBDAV_BUCKET.delete(trashObjects.slice(index, index + 1000).map((obj) => obj.key));
  }

  // 删除回收站元数据
  await env.WEBDAV_KV.delete(`${TRASH_PREFIX}${trashKey}`);
}

// 新增：清空回收站（两阶段删除与并发写存在理论竞态，残留漂移由定时任务按实际 R2 重算用量兼底）
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
    if (move) await recordSyncChange(env, source, "deleted");
    await recordSyncChange(env, destination, "modified");
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
  await env.WEBDAV_KV.put(dirKey(destination), new Date().toISOString());
  await recordSyncChange(env, destination, "modified");
  return new Response(null, { status: 201 });
}

// 管理界面批量移动：将文件或目录（含全部子内容）移动到目标目录下。
// 目标已存在同名内容时跳过（覆盖即不可逆丢失）；目录复制阶段全部成功后才清理源，失败即回滚已写入部分并保留源。
// 同一账户内移动字节数不变，不调整用量缓存。
async function moveEntryTo(env: Env, source: string, targetDir: string): Promise<"moved" | "conflict" | "missing"> {
  const name = source.slice(source.lastIndexOf("/") + 1);
  const destination = targetDir ? `${targetDir}/${name}` : name;
  if (destination === source || destination.startsWith(`${source}/`)) return "conflict";

  const sourceObject = await env.WEBDAV_BUCKET.head(r2Key(source));
  const isDirectory = !sourceObject;
  if (isDirectory && !(await env.WEBDAV_KV.get(dirKey(source))) && !(await hasChildren(env, source))) return "missing";

  // 目标位置只要已有内容（文件对象 / dir: 标记 / 子内容）即冲突跳过；文件移到同名目录同样拒绝，避免同一路径既是文件又是目录
  const destinationObject = await env.WEBDAV_BUCKET.head(r2Key(destination));
  if (destinationObject || (await env.WEBDAV_KV.get(dirKey(destination))) || (await hasChildren(env, destination))) return "conflict";

  if (isDirectory) {
    const objects = await listAllObjects(env, `${source}/`);
    const written: string[] = [];
    try {
      for (const item of objects) {
        const body = await env.WEBDAV_BUCKET.get(item.key);
        if (!body) throw new Error(`failed to read ${item.key}`);
        const target = `${destination}/${item.key.slice(source.length + 1)}`;
        await env.WEBDAV_BUCKET.put(target, body.body, { httpMetadata: body.httpMetadata });
        written.push(target);
      }
    } catch (error) {
      for (const key of written) await env.WEBDAV_BUCKET.delete(key);
      throw error;
    }
    // 搬移源目录及其子目录的 dir: 标记（含目录自身，否则 PROPFIND 不可见）
    for (const key of await listAllKV(env, DIR_PREFIX)) {
      const directory = decodeURIComponent(key.slice(DIR_PREFIX.length));
      if (directory === source || directory.startsWith(`${source}/`)) {
        await env.WEBDAV_KV.put(dirKey(`${destination}${directory.slice(source.length)}`), new Date().toISOString());
      }
    }
    for (let index = 0; index < objects.length; index += 1000) {
      await env.WEBDAV_BUCKET.delete(objects.slice(index, index + 1000).map((item) => item.key));
    }
    await deleteMetadataUnder(env, source);
    // sync-collection：源目录的子成员记为已删除（仅记录前 100 条，避免大量 KV 写入）
    for (const item of objects.slice(0, 100)) await recordSyncChange(env, item.key, "deleted");
  } else {
    const content = await env.WEBDAV_BUCKET.get(r2Key(source));
    if (!content) return "missing";
    await env.WEBDAV_BUCKET.put(r2Key(destination), content.body, { httpMetadata: content.httpMetadata });
    const sourceMeta = await env.WEBDAV_KV.get(metaKey(source));
    if (sourceMeta) await env.WEBDAV_KV.put(metaKey(destination), sourceMeta);
    await env.WEBDAV_BUCKET.delete(r2Key(source));
    await env.WEBDAV_KV.delete(metaKey(source));
  }

  // 目标父链目录标记不存在时补建，保证移动后可正常浏览
  await ensureDirectoryMarkers(env, [destination]);
  // sync-collection：目标记为新增/修改，源记为已删除
  await recordSyncChange(env, destination, "modified");
  await recordSyncChange(env, source, "deleted");
  return "moved";
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
    // 用户级上限：超管可单独调节；无账户上下文时退回系统默认
    const userLimit = account && rootEnv ? await getUserStorageLimit(rootEnv, account.owner) : USER_STORAGE_LIMIT;
    let available = Math.max(0, userLimit - used);
    // 账户级配额生效时，可用空间取用户级余量与账户级余量的较小者
    if (account?.quotaBytes && account.quotaBytes > 0) available = Math.min(available, Math.max(0, account.quotaBytes - await getAccountStorageUsage(env)));
    quotaXml = `<d:quota-used-bytes>${used}</d:quota-used-bytes><d:quota-available-bytes>${available}</d:quota-available-bytes>`;
  }
  const entries = [{ path, directory: rootIsDirectory }];
  const lockMap = await loadLockMap(env);
  if (depth === "1" && rootIsDirectory) entries.push(...await listChildren(env, path));
  if (depth === "infinity" && rootIsDirectory) entries.push(...await listDescendants(env, path));
  // 死属性（PROPPATCH 写入的自定义属性）：逐条目读取并返回
  const deadPropsXml = async (entryPath: string): Promise<string> => {
    const props = await env.WEBDAV_KV.get(propKey(entryPath), "json") as Record<string, DeadProperty> | null;
    if (!props) return "";
    return Object.values(props).map((item) => {
      const prefix = item.name.split(":")[0];
      const openTag = item.xmlns ? `<${item.name} xmlns:${prefix}="${item.xmlns}">` : `<${item.name}>`;
      return `${openTag}${item.value ? escapeXml(item.value) : ""}</${item.name}>`;
    }).join("");
  };
  const xml = (await Promise.all(entries.map(async (entry) => propResponse(request, env, entry.path, entry.directory, account, entry.directory ? quotaXml : "", lockMap, await deadPropsXml(entry.path))))).join("");
  return new Response(`<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:">${xml}</d:multistatus>`, { status: 207, headers: { "Content-Type": "text/xml; charset=utf-8", DAV: "1, 2", "Cache-Control": "no-store" } });
}

async function propResponse(request: Request, env: Env, path: string, directory: boolean, account?: WebdavAccount, quotaXml = "", lockMap: Map<string, LockInfo[]> = new Map(), deadPropsXml = ""): Promise<string> {
  const object = directory ? null : await env.WEBDAV_BUCKET.head(r2Key(path));
  const displayName = path ? path.slice(path.lastIndexOf("/") + 1) : "WebDAV";
  // creationdate：目录取 dir: 标记的创建时间，文件取 R2 上传时间（RFC 4918 定义为资源创建时刻）
  const created = directory ? (await env.WEBDAV_KV.get(dirKey(path)) || new Date().toISOString()) : (object?.uploaded?.toISOString() ?? new Date().toISOString());
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
  return `<d:response><d:href>${escapeXml(href)}</d:href><d:propstat><d:prop><d:displayname>${escapeXml(displayName)}</d:displayname><d:creationdate>${created}</d:creationdate><d:resourcetype>${directory ? "<d:collection/>" : ""}</d:resourcetype><d:getcontentlength>${size}</d:getcontentlength><d:getlastmodified>${modified}</d:getlastmodified><d:getcontenttype>${directory ? "httpd/unix-directory" : escapeXml(object?.httpMetadata?.contentType ?? "application/octet-stream")}</d:getcontenttype>${object?.httpEtag ? `<d:getetag>${escapeXml(object.httpEtag)}</d:getetag>` : ""}${quotaXml}${SUPPORTEDLOCK_XML}${lockXml ? `<d:lockdiscovery>${lockXml}</d:lockdiscovery>` : ""}${deadPropsXml}</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>`;
}

interface DeadProperty {
  name: string;
  value: string;
  xmlns: string;
}

// PROPPATCH 死属性：解析 set/remove 并存入 KV（键 prop:{编码路径}），全部成功返回 207 多状态。
// 客户端（如 Windows 映射驱动器、某些同步工具）会发送自定义属性写入，此前直接 405 导致这些客户端不可用
async function proppatch(request: Request, env: Env, path: string, account?: WebdavAccount): Promise<Response> {
  if (!path) return textResponse("Cannot modify properties of the root collection", 403);
  const body = await request.text();
  if (!body) return textResponse("Bad Request", 400);
  const xmlns = new Map<string, string>();
  for (const match of body.matchAll(/xmlns:([\w.-]+)="([^"]*)"/g)) xmlns.set(match[1], match[2]);
  const sets: DeadProperty[] = [];
  const removes: string[] = [];
  const extractSet = (section: string): void => {
    const propBlock = section.match(/<(?:[\w.-]+:)?prop\b[^>]*>([\s\S]*?)<\/(?:[\w.-]+:)?prop>/i);
    if (!propBlock) return;
    for (const match of propBlock[1].matchAll(/<([\w.-]+:[\w.-]+)([^>]*)>([\s\S]*?)<\/\1>|<([\w.-]+:[\w.-]+)([^>]*)\/>/g)) {
      const name = match[1] || match[4];
      if (!name) continue;
      const value = match[3] !== undefined ? match[3].replace(/<[^>]*>/g, "").trim() : "";
      sets.push({ name, value, xmlns: xmlns.get(name.split(":")[0]) ?? "" });
    }
  };
  for (const match of body.matchAll(/<(?:[\w.-]+:)?set\b[^>]*>([\s\S]*?)<\/(?:[\w.-]+:)?set>/gi)) extractSet(match[1]);
  for (const match of body.matchAll(/<(?:[\w.-]+:)?remove\b[^>]*>([\s\S]*?)<\/(?:[\w.-]+:)?remove>/gi)) {
    const propBlock = match[1].match(/<(?:[\w.-]+:)?prop\b[^>]*>([\s\S]*?)<\/(?:[\w.-]+:)?prop>/i);
    if (propBlock) for (const removed of propBlock[1].matchAll(/<([\w.-]+:[\w.-]+)[\s/>]/g)) removes.push(removed[1]);
  }
  if (!sets.length && !removes.length) return textResponse("Bad Request", 400);
  const current = await env.WEBDAV_KV.get(propKey(path), "json") as Record<string, DeadProperty> | null;
  const props: Record<string, DeadProperty> = { ...(current ?? {}) };
  for (const name of removes) delete props[name];
  for (const item of sets) props[item.name] = item;
  if (Object.keys(props).length) await env.WEBDAV_KV.put(propKey(path), JSON.stringify(props));
  else await env.WEBDAV_KV.delete(propKey(path));
  // RFC 4918：逐属性返回 propstat；本实现全部接受，统一 200 OK
  const listed = [...new Set([...removes, ...sets.map((item) => item.name)])].map((name) => `<${escapeXml(name)}/>`).join("");
  const href = `${new URL(request.url).origin}${urlPath(env, path, account)}`;
  return new Response(`<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>${escapeXml(href)}</d:href><d:propstat><d:prop>${listed}</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`, { status: 207, headers: { "Content-Type": "text/xml; charset=utf-8", "Cache-Control": "no-store" } });
}

// —— RFC 6578 sync-collection REPORT：按 sync-token 返回增量变更（新增/修改 200，删除 404）——
async function reportMethod(request: Request, env: Env, path: string, account?: WebdavAccount): Promise<Response> {
  const body = await request.text();
  if (!body) return textResponse("Bad Request", 400);
  if (!/sync-collection/i.test(body)) return textResponse("Unsupported REPORT type", 422);
  const tokenMatch = body.match(/<(?:[\w.-]+:)?sync-token[^>]*>([^<]*)</i);
  const rawToken = (tokenMatch?.[1] ?? "").trim();
  // token 支持纯数字或 URI 形式（取末段数字）；缺失/非法按 0 处理即首次全量同步
  const tokenNumber = Number(rawToken.split("/").pop());
  const token = Number.isFinite(tokenNumber) ? tokenNumber : 0;
  const state = await readSyncState(env);
  // 懒激活：首次收到 sync-token REPORT 即开始记录后续变更（一次性 1 次 KV 写入）
  if (!state.activated) {
    state.activated = true;
    try { await env.WEBDAV_KV.put(SYNC_STATE_KEY, JSON.stringify(state)); } catch { }
  }
  const changed = Object.entries(state.changes).filter(([, change]) => change.seq > token).sort((a, b) => a[1].seq - b[1].seq);
  const limit = 500;
  const truncated = changed.length > limit;
  const responses = (await Promise.all(changed.slice(0, limit).map(async ([entryPath, change]) => {
    const deleted = change.kind === "deleted";
    const href = `${new URL(request.url).origin}${urlPath(env, entryPath, account)}`;
    const statusLine = deleted ? "HTTP/1.1 404 Not Found" : "HTTP/1.1 200 OK";
    const propXml = deleted ? "" : (await propResponse(request, env, entryPath, false, account)).match(/<d:propstat><d:prop>([\s\S]*?)<\/d:prop>/)?.[1] ?? "";
    return `<d:response><d:href>${escapeXml(href)}</d:href><d:propstat><d:prop>${propXml}</d:prop><d:status>${statusLine}</d:status></d:propstat></d:response>`;
  }))).join("");
  const limitXml = truncated ? `<d:limit><d:nresults>${limit}</d:nresults></d:limit>` : "";
  return new Response(`<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:">${responses}${limitXml}<d:sync-token>https://cf-webdav/sync/${state.seq}</d:sync-token></d:multistatus>`, { status: 207, headers: { "Content-Type": "text/xml; charset=utf-8", DAV: "1, 2", "Cache-Control": "no-store" } });
}

// —— RFC 5323 SEARCH：轻量文件名匹配（支持 SQL 式 LIKE '%kw%' 或引号关键词），结果上限 200 ——
async function searchMethod(request: Request, env: Env, path: string, account?: WebdavAccount): Promise<Response> {
  const body = await request.text();
  // 关键词来源优先级：SQL 风格 like '%kw%' -> RFC 5323 <d:like> 内的 <d:literal> -> 单独 <d:literal> -> 引号关键词（最后才考虑，避免误抓 XML 属性值）
  const sqlLike = body.match(/like\s+'%([^%']*)%'/i) ?? body.match(/like\s+"%([^%"]*)%"/i);
  const likeLiteral = body.match(/<(?:[\w-]+:)?like[^>]*>[\s\S]*?<(?:[\w-]+:)?literal>([^<]*)<\/(?:[\w-]+:)?literal>/i);
  const literal = likeLiteral ? null : body.match(/<(?:[\w-]+:)?literal>([^<]*)<\/(?:[\w-]+:)?literal>/i);
  const quoted = literal ? null : body.includes("<") ? null : body.match(/'([^']{1,64})'/) ?? body.match(/"([^"]{1,64})"/);
  const keyword = (sqlLike?.[1] ?? likeLiteral?.[1] ?? literal?.[1] ?? quoted?.[1] ?? "").replace(/^%+|%+$/g, "").trim().toLowerCase();
  if (!keyword) return textResponse("Bad Request: no search keyword found", 400);
  const base = path ? `${path}/` : "";
  const matches: Array<{ path: string; directory: boolean }> = [];
  for (const object of await listAllObjects(env, base)) {
    if (object.key.startsWith("__trash/")) continue;
    if (object.key.slice(object.key.lastIndexOf("/") + 1).toLowerCase().includes(keyword)) matches.push({ path: object.key, directory: false });
    if (matches.length >= 200) break;
  }
  if (matches.length < 200) {
    for (const key of await listAllKV(env, DIR_PREFIX)) {
      const directory = decodeURIComponent(key.slice(DIR_PREFIX.length));
      if ((base && !directory.startsWith(base)) || directory.split("/").includes("__trash")) continue;
      if (directory.slice(directory.lastIndexOf("/") + 1).toLowerCase().includes(keyword)) {
        matches.push({ path: directory, directory: true });
        if (matches.length >= 200) break;
      }
    }
  }
  const xml = (await Promise.all(matches.map((entry) => propResponse(request, env, entry.path, entry.directory, account)))).join("");
  return new Response(`<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:">${xml}</d:multistatus>`, { status: 207, headers: { "Content-Type": "text/xml; charset=utf-8", DAV: "1, 2", "Cache-Control": "no-store" } });
}

function urlPath(env: Env, path: string, account?: WebdavAccount): string {
  const prefix = normalizePrefix(env.DAV_PREFIX ?? "");
  const accountPrefix = account ? `${account.owner}/${account.uuid}` : "";
  return `/${[prefix, accountPrefix, path].filter(Boolean).join("/").split("/").map(encodeURIComponent).join("/")}`;
}

async function listChildren(env: Env, path: string): Promise<Array<{ path: string; directory: boolean }>> {
  const prefix = path ? `${path}/` : "";
  const listed = await env.WEBDAV_BUCKET.list({ prefix, delimiter: "/" });
  // __trash 为保留命名空间：requestPath 已拒绝访问，列举时同样不可见
  const result = listed.delimitedPrefixes.filter((item) => !item.slice(0, -1).split("/").includes("__trash")).map((item) => ({ path: item.slice(0, -1), directory: true }));
  for (const object of listed.objects) {
    if (object.key.split("/").includes("__trash")) continue;
    result.push({ path: object.key, directory: false });
  }
  const dirs = await listAllKV(env, `${DIR_PREFIX}${encodeURIComponent(prefix)}`);
  for (const key of dirs) {
    const child = decodeURIComponent(key.slice((DIR_PREFIX + encodeURIComponent(prefix)).length));
    if (child && !child.includes("/") && child !== "__trash") result.push({ path: `${prefix}${child}`, directory: true });
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

// 用量缓存有效期：过期后才全量扫描 R2 重建（每操作增量更新已移除以省 KV 写入，精度以小时为界）
const STORAGE_USAGE_TTL_MS = 60 * 60 * 1000;

// 读取账户存储用量 KV 缓存（不含 __trash/ 回收站对象）；缓存缺失或过期时全量扫描 R2 重建
async function getAccountStorageUsage(env: Env): Promise<number> {
  const cached = await env.WEBDAV_KV.get(STORAGE_USAGE_KEY, "json") as { bytes: number; updatedAt?: string } | null;
  if (cached && Number.isFinite(cached.bytes) && cached.updatedAt && Date.now() - new Date(cached.updatedAt).getTime() < STORAGE_USAGE_TTL_MS) return cached.bytes;
  const objects = await listAllObjects(env, "");
  const bytes = objects.filter((item) => !item.key.startsWith("__trash/")).reduce((total, item) => total + item.size, 0);
  await env.WEBDAV_KV.put(STORAGE_USAGE_KEY, JSON.stringify({ bytes, updatedAt: new Date().toISOString() }));
  return bytes;
}

async function getUserStorageUsage(env: Env, owner: string): Promise<number> {
  const accounts = Object.values(await getWebdavAccounts(env)).filter((account) => account.owner === owner);
  const sizes = await Promise.all(accounts.map((account) => getAccountStorageUsage(createScopedEnv(env, storageScope(account)))));
  return sizes.reduce((total, size) => total + size, 0);
}

async function ensureStorageCapacity(rootEnv: Env, accountEnv: Env, account: WebdavAccount, path: string, incomingSize: number): Promise<Response | null> {
  const currentObject = await accountEnv.WEBDAV_BUCKET.head(r2Key(path));
  // 账户级配额优先校验：超出返回 507（WebDAV 惯例的 Insufficient Storage）
  if (account.quotaBytes && account.quotaBytes > 0) {
    const accountUsage = await getAccountStorageUsage(accountEnv);
    const projectedAccount = accountUsage - (currentObject?.size || 0) + incomingSize;
    if (projectedAccount > account.quotaBytes) return textResponse("超出该账户的存储配额", 507, {
      "X-Account-Quota": String(account.quotaBytes),
      "X-Account-Used": String(accountUsage),
    });
  }
  const currentUsage = await getUserStorageUsage(rootEnv, account.owner);
  const projectedUsage = currentUsage - (currentObject?.size || 0) + incomingSize;
  // 用户级容量上限：超管可为普通用户单独调节，未设置时用系统默认
  const userLimit = await getUserStorageLimit(rootEnv, account.owner);
  if (projectedUsage <= userLimit) return null;
  return textResponse(`用户所有 WebDAV 账户的文件总量不能超过 ${(userLimit / 1024 ** 3).toFixed(0)} GB`, 413, {
    "X-Storage-Limit": String(userLimit),
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
  const [files, dirs, props] = await Promise.all([listAllKV(env, META_PREFIX), listAllKV(env, DIR_PREFIX), listAllKV(env, PROP_PREFIX)]);
  const prefix = `${path}/`;
  await Promise.all([...files, ...dirs, ...props].filter((key) => {
    const marker = key.startsWith(META_PREFIX) ? META_PREFIX : key.startsWith(PROP_PREFIX) ? PROP_PREFIX : DIR_PREFIX;
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
  // 每分钟请求数：官方 Rate Limiting binding（不占 KV 配额，也无 KV 读改写非原子问题）；读取与修改请求都限流
  const minute = await env.RATE_LIMITER.limit({ key: clientIp });
  if (!minute.success) return { allowed: false, retryAfter: 60 };

  // 每小时上传流量（仅 PUT）：需累计字节数，binding 无法表达，保留 KV 计数（每次 PUT 1 写）
  if (method !== "PUT") return { allowed: true };
  const now = Date.now();
  const hourKey = `${RATE_LIMIT_PREFIX}${clientIp}:hour:${Math.floor(now / 3600000)}`;
  const hourBytes = parseInt(await env.WEBDAV_KV.get(hourKey) || "0");
  if (hourBytes + contentLength > DEFAULT_RATE_LIMIT.maxUploadBytesPerHour) {
    return { allowed: false, retryAfter: 3600 - (Math.floor(now / 1000) % 3600) };
  }
  await env.WEBDAV_KV.put(hourKey, String(hourBytes + contentLength), { expirationTtl: 3700 });
  return { allowed: true };
}

// 新增：访问日志页面
async function adminLogsPage(request: Request, env: Env, filterUsers: string[] = [], formAction = "/?", hiddenFields: Record<string, string> = {}): Promise<Response> {
  // 筛选参数：方法精确匹配，状态按类别（2/3/4/5），用户/IP/路径为子串匹配
  const params = new URL(request.url).searchParams;
  const LOG_METHODS = ["GET", "PUT", "DELETE", "PROPFIND", "HEAD", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "SHARE"];
  const filterMethod = LOG_METHODS.includes(params.get("f_method") || "") ? String(params.get("f_method")) : "";
  const filterStatus = /^[2345]$/.test(params.get("f_status") || "") ? Number(params.get("f_status")) : 0;
  const filterUser = (params.get("f_user") || "").trim().toLowerCase();
  const filterIp = (params.get("f_ip") || "").trim().toLowerCase();
  const filterPath = (params.get("f_path") || "").trim().toLowerCase();
  const hasFilter = Boolean(filterMethod || filterStatus || filterUser || filterIp || filterPath);
  const logs: AccessLog[] = [];
  let cursor: string | undefined;
  // 日志键为倒序时间戳，list 升序即最新在前：全量视图只需首页，按用户过滤时最多读取 10 页
  let pagesLeft = filterUsers.length ? 10 : 1;
  do {
    const page = await env.WEBDAV_KV.list({ prefix: LOG_PREFIX, cursor, limit: 100 });
    const pageLogs = await Promise.all(page.keys.map(async (key) => await env.WEBDAV_KV.get(key.name, "json") as AccessLog | null));
    for (const log of pageLogs) if (log) logs.push(log);
    cursor = page.list_complete ? undefined : page.cursor;
    pagesLeft -= 1;
  } while (cursor && pagesLeft > 0);

  logs.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  // 普通用户视图展示自己及名下 WebDAV 账户的操作日志（WebDAV 客户端操作的 user 为账户名）；超级管理员/管理入口展示全部
  const accountScopedLogs = filterUsers.length ? logs.filter((log) => filterUsers.includes(log.user)) : logs;
  const visibleLogs = accountScopedLogs.filter((log) => {
    if (filterMethod && log.method !== filterMethod) return false;
    if (filterStatus && Math.floor(log.status / 100) !== filterStatus) return false;
    if (filterUser && !(log.user || "").toLowerCase().includes(filterUser)) return false;
    if (filterIp && !(log.clientIp || "").toLowerCase().includes(filterIp)) return false;
    if (filterPath && !(log.path || "").toLowerCase().includes(filterPath)) return false;
    return true;
  });
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

  const hiddenInputs = Object.entries(hiddenFields).map(([key, value]) => `<input type="hidden" name="${escapeHtml(key)}" value="${escapeHtml(value)}">`).join("");
  const hiddenQuery = new URLSearchParams(hiddenFields).toString();
  const filterForm = `<section class="logs-filter"><form method="get" action="${escapeHtml(formAction)}" class="logs-filter-form">${hiddenInputs}<select name="f_method" aria-label="按方法筛选"><option value="">全部方法</option>${LOG_METHODS.map((method) => `<option value="${method}"${method === filterMethod ? " selected" : ""}>${method}</option>`).join("")}</select><select name="f_status" aria-label="按状态筛选"><option value="">全部状态</option>${[2, 3, 4, 5].map((status) => `<option value="${status}"${status === filterStatus ? " selected" : ""}>${status}xx</option>`).join("")}</select><input name="f_user" placeholder="用户" value="${escapeHtml(params.get("f_user") || "")}"><input name="f_ip" placeholder="IP" value="${escapeHtml(params.get("f_ip") || "")}"><input name="f_path" placeholder="路径包含" value="${escapeHtml(params.get("f_path") || "")}"><button class="secondary-button" type="submit">筛选</button>${hasFilter ? `<a class="text-link" href="${escapeHtml(formAction)}${hiddenQuery ? `?${hiddenQuery}` : ""}">清除筛选</a>` : ""}</form></section>`;
  const retentionDays = getLogRetentionDays(env);
  const logSummary = hasFilter ? `筛选后 ${visibleLogs.length} 条（原始 ${accountScopedLogs.length} 条，保留 ${retentionDays} 天）` : `最近 ${recentLogs.length} 条记录（保留 ${retentionDays} 天）`;
  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>访问日志</title><style>${ADMIN_CSS}${LOGS_CSS}</style><body>${topbarHtml("访问日志", `<a class="text-link inverse" href="/">返回管理中心</a>`)}<main class="dashboard">${pageHeadingHtml("ACCESS LOG", "访问日志", logSummary)}${filterForm}<section class="data-table-wrap"><table class="data-table"><thead><tr><th>时间</th><th>方法</th><th>路径</th><th>状态</th><th>大小</th><th>IP</th><th>用户</th></tr></thead><tbody>${logRows || `<tr><td colspan="7">${hasFilter ? "没有符合条件的日志" : "暂无日志"}</td></tr>`}</tbody></table></section></main></body></html>`);
}

// 审计日志页：敏感操作流水（登录、改密、TOTP/白名单变更、账户增删、配额调整），仅超级管理员可见，支持筛选与 CSV 导出
async function adminAuditPage(env: Env, url: URL): Promise<Response> {
  const params = url.searchParams;
  const filterActor = (params.get("f_actor") || "").trim().toLowerCase();
  const filterAction = (params.get("f_action") || "").trim().toLowerCase();
  const allLogs = await listAuditLogs(env);
  const visibleLogs = allLogs.filter((log) => (!filterActor || (log.actor || "").toLowerCase().includes(filterActor)) && (!filterAction || (log.action || "").toLowerCase().includes(filterAction)));
  const rows = visibleLogs.slice(0, 200).map((log) => `<tr><td>${formatDateTime(new Date(log.timestamp))}</td><td>${escapeXml(log.actor || "-")}</td><td>${escapeXml(log.action)}</td><td class="path">${escapeXml(log.target || "-")}</td><td>${escapeXml(log.clientIp || "-")}</td><td class="path">${escapeXml(log.detail || "")}</td></tr>`).join("");
  const filterForm = `<section class="logs-filter"><form method="get" action="/?view=audit" class="logs-filter-form"><input name="f_actor" placeholder="操作者" value="${escapeHtml(params.get("f_actor") || "")}"><input name="f_action" placeholder="动作" value="${escapeHtml(params.get("f_action") || "")}"><button class="secondary-button" type="submit">筛选</button>${filterActor || filterAction ? `<a class="text-link" href="/?view=audit">清除筛选</a>` : ""}<a class="text-link" href="/?view=audit&export=csv">导出 CSV</a></form></section>`;
  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>审计日志</title><style>${ADMIN_CSS}${LOGS_CSS}</style><body>${topbarHtml("审计日志", `<a class="text-link inverse" href="/">返回管理中心</a>`)}<main class="dashboard">${pageHeadingHtml("AUDIT LOG", "审计日志", `共 ${visibleLogs.length} 条敏感操作记录（保留 ${AUDIT_RETENTION_DAYS} 天，展示前 200 条）`)}${filterForm}<section class="data-table-wrap"><table class="data-table"><thead><tr><th>时间</th><th>操作者</th><th>动作</th><th>对象</th><th>IP</th><th>详情</th></tr></thead><tbody>${rows || `<tr><td colspan="6">暂无审计记录</td></tr>`}</tbody></table></section></main></body></html>`);
}

async function auditCsvResponse(env: Env): Promise<Response> {
  const logs = await listAuditLogs(env);
  const header = "timestamp,actor,action,target,clientIp,detail";
  const rows = logs.map((log) => [log.timestamp, log.actor, log.action, log.target, log.clientIp, log.detail ?? ""].map((value) => `"${String(value).replace(/"/g, '""')}"`).join(","));
  return new Response([header, ...rows].join("\n"), { headers: { "Content-Type": "text/csv; charset=utf-8", "Content-Disposition": `attachment; filename="audit-log-${new Date().toISOString().slice(0, 10)}.csv"`, "Cache-Control": "no-store" } });
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + " MB";
  return (bytes / (1024 * 1024 * 1024)).toFixed(1) + " GB";
}

// 存储用量徽标：最小单位 MB，达 1 GB 后切换为 GB（不足 0.01 MB 按 0.0 MB 显示）
function formatStorageUsage(bytes: number): string {
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
  return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
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
.method.HEAD{background:#ede7f6;color:#4527a0}
.method.LOCK{background:#fff8e1;color:#a67c00}
.method.UNLOCK{background:#eceff1;color:#455a64}
.status{padding:2px 6px;border-radius:3px;font-size:12px;font-weight:500}
.status.success{background:#e8f5e9;color:#2e7d32}
.status.warn{background:#fff3e0;color:#e65100}
.status.error{background:#ffebee;color:#c62828}
a{color:#1769aa;text-decoration:none}[data-theme="dark"] a{color:var(--link-color)}
a:hover{text-decoration:underline}
.logs-filter{margin:0 0 6px}
.logs-filter-form{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.logs-filter-form select,.logs-filter-form input{height:40px;padding:0 10px;border:1px solid var(--input-border);border-radius:4px;background:var(--input-bg);color:var(--text-primary);font:inherit}
.logs-filter-form input{width:150px}
.logs-filter-form .secondary-button{margin:0;min-height:40px;height:40px;padding:0 16px}
`;

// 预览页专用样式（与 FILES_CSS 搭配使用）
const PREVIEW_CSS = `[data-theme="dark"] .preview-text{background:#122326}[data-theme="dark"] .preview-media img{border-color:#2d484b}`;

// 新增：回收站管理页面
async function adminTrashPage(env: Env, accountUsername: string, warn = ""): Promise<Response> {
  const trashItems: Array<{ key: string; originalPath: string; deletedAt: string; size?: number; isDirectory?: boolean }> = [];
  let cursor: string | undefined;
  do {
    const page = await env.WEBDAV_KV.list({ prefix: TRASH_PREFIX, cursor, limit: 100 });
    for (const key of page.keys) {
      const meta = await env.WEBDAV_KV.get(key.name, "json") as { originalPath: string; deletedAt: string; size?: number; isDirectory?: boolean } | null;
      if (meta) {
        // 表单操作传回完整键后缀（含时间戳版本），避免旧格式数据解码后无法定位原键
        trashItems.push({ key: key.name.slice(TRASH_PREFIX.length), ...meta });
      }
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);

  trashItems.sort((a, b) => b.deletedAt.localeCompare(a.deletedAt));

  // 剩余保留天数：不足 7 天的条目高亮提醒，并在页头汇总即将过期数量
  const daysLeftOf = (item: { deletedAt: string }): number => {
    const deletedMs = Date.parse(item.deletedAt);
    return Number.isFinite(deletedMs) ? Math.min(TRASH_RETENTION_DAYS, Math.max(0, TRASH_RETENTION_DAYS - Math.floor((Date.now() - deletedMs) / 86400000))) : TRASH_RETENTION_DAYS;
  };
  const expiringSoonCount = trashItems.filter((item) => daysLeftOf(item) <= 7).length;
  const trashRows = trashItems.map(item => {
    const time = formatDateTime(item.deletedAt);
    const path = escapeXml(item.originalPath);
    const type = item.isDirectory ? "目录" : "文件";
    const size = item.size ? formatBytes(item.size) : "-";
    const daysLeft = daysLeftOf(item);
    const daysLeftHtml = `<span class="days-left${daysLeft <= 7 ? " urgent" : ""}">${daysLeft <= 0 ? "不足 1 天，即将清理" : `剩余 ${daysLeft} 天`}</span>`;
    return `<tr><td class="check-col"><input type="checkbox" class="trash-check" form="trash-toolbar-form" name="paths" value="${escapeXml(item.key)}"></td><td>${path}</td><td>${type}</td><td>${size}</td><td>${time}${daysLeftHtml}</td><td><div class="row-actions"><form method="post" action="/?view=trash&account=${encodeURIComponent(accountUsername)}"><input type="hidden" name="action" value="restore"><input type="hidden" name="accountUsername" value="${escapeHtml(accountUsername)}"><input type="hidden" name="path" value="${escapeXml(item.key)}"><button type="submit" class="restore-btn">恢复</button></form><form method="post" action="/?view=trash&account=${encodeURIComponent(accountUsername)}" onsubmit="return confirm('确定 要永久删除此项吗？此操作不可恢复！')"><input type="hidden" name="action" value="purge"><input type="hidden" name="accountUsername" value="${escapeHtml(accountUsername)}"><input type="hidden" name="paths" value="${escapeXml(item.key)}"><button type="submit" class="purge-btn">永久删除</button></form></div></td></tr>`;
  }).join("");

  const warnBanner = `${warn === "conflict" ? `<div class="trash-warn">部分条目未能恢复：目标路径已存在同名文件，已跳过；对应条目已保留在回收站</div>` : ""}${expiringSoonCount ? `<div class="trash-warn">${expiringSoonCount} 项将在 7 天内到期并被自动清理，需要保留请尽快恢复</div>` : ""}`;
  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>回收站</title><style>${ADMIN_CSS}${FILES_CSS}${TRASH_CSS}</style><body>${topbarHtml("回收站", `<a class="text-link inverse" href="/?view=account&account=${encodeURIComponent(accountUsername)}">返回账户管理</a>`)}<main class="dashboard">${warnBanner}${pageHeadingHtml("TRASH", "回收站", `账户：${accountUsername}。已删除的文件将在 ${TRASH_RETENTION_DAYS} 天后自动清理`, `<a class="secondary-button" href="/?view=files&account=${encodeURIComponent(accountUsername)}">回到文件管理</a>`)}<section class="data-table-wrap"><table class="data-table"><thead><tr><th class="check-col"><input type="checkbox" id="trash-select-all" onchange="toggleTrashSelect(this.checked)" title="全选" aria-label="全选"></th><th>原路径</th><th>类型</th><th>大小</th><th>删除时间</th><th>操作</th></tr></thead><tbody>${trashRows || '<tr><td colspan="6">回收站为空</td></tr>'}</tbody></table></section>${trashItems.length > 0 ? `<form id="trash-toolbar-form" method="post" action="/?view=trash&account=${encodeURIComponent(accountUsername)}" class="trash-toolbar"><input type="hidden" name="accountUsername" value="${escapeHtml(accountUsername)}"><button type="submit" name="action" value="restore" class="restore-btn" onclick="return confirmTrashRestore()">恢复选中</button><button type="submit" name="action" value="purge" class="empty-btn" onclick="return confirmTrashPurge()">永久删除选中</button><button type="submit" name="action" value="empty" class="empty-btn" onclick="return confirm('确定要清空回收站吗？此操作不可恢复！')">清空回收站</button></form><script>function toggleTrashSelect(checked){document.querySelectorAll('.trash-check').forEach(function(c){c.checked=checked});}function confirmTrashPurge(){var n=document.querySelectorAll('.trash-check:checked').length;if(!n){alert('请先勾选要操作的文件');return false;}return confirm('确定要永久删除选中的 '+n+' 项吗？此操作不可恢复！');}function confirmTrashRestore(){var n=document.querySelectorAll('.trash-check:checked').length;if(!n){alert('请先勾选要恢复的文件');return false;}return confirm('确定要恢复选中的 '+n+' 项吗？');}</script>` : ""}</main></body></html>`);
}

const TRASH_CSS = `
.trash-warn{margin:16px 0;padding:10px 14px;border:1px solid #f0c36d;background:#fdf6e3;color:#8a6d3b;border-radius:6px;font-size:14px}table{width:100%;border-collapse:collapse;margin:20px 0;font-size:14px}
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
.days-left{display:block;margin-top:3px;font-size:12px;color:var(--text-secondary)}
.days-left.urgent{color:#c62828;font-weight:700}
a{color:#1769aa;text-decoration:none}[data-theme="dark"] a{color:var(--link-color)}
a:hover{text-decoration:underline}
`;
var DARK_MODE_CSS = `:root{--bg-gradient:linear-gradient(135deg,#f6f8f5 0%,#e8efed 100%);--text-primary:#17212b;--text-secondary:#667578;--card-bg:rgba(255,255,255,.82);--card-border:#d7e0dc;--card-shadow:0 12px 30px rgba(31,61,57,.06);--input-bg:#fbfcfa;--input-border:#cbd7d3;--topbar-bg:#183b3f;--topbar-text:#f4f8f5;--table-header-bg:#f2f6f3;--table-header-text:#60716d;--table-border:#e0e7e3;--accent-gold:#d79b41;--accent-gold-hover:#e5ae59;--accent-gold-text:#183b3f;--accent-teal:#397277;--danger-bg:#fff5f3;--danger-border:#c76c61;--danger-text:#a43f35;--secondary-bg:#fff;--secondary-border:#397277;--secondary-text:#285b60;--link-color:#32656a}[data-theme="dark"]{--bg-gradient:linear-gradient(135deg,#0f1a1c 0%,#162628 100%);--text-primary:#c7d7d3;--text-secondary:#91aaa4;--card-bg:rgba(28,46,49,.82);--card-border:#2d484b;--card-shadow:0 12px 30px rgba(0,0,0,.25);--input-bg:#1a2e31;--input-border:#3a5558;--topbar-bg:#0c1618;--topbar-text:#c7d7d3;--table-header-bg:#1a2e31;--table-header-text:#a5bcb7;--table-border:#2d484b;--accent-gold:#e5ae59;--accent-gold-hover:#f0be70;--accent-gold-text:#0f1a1c;--accent-teal:#7ab8b0;--danger-bg:#2a1515;--danger-border:#a43f35;--danger-text:#e88078;--secondary-bg:transparent;--secondary-border:#5a9a9e;--secondary-text:#8fd4d8;--link-color:#7ab8b0}body{background:var(--bg-gradient);color:var(--text-primary)}.muted{color:var(--text-secondary)!important}.topbar{background:var(--topbar-bg);color:var(--topbar-text)}.topbar .text-link,.inverse{color:var(--topbar-text)}.summary-card,.config-card,.file-table-wrap,.data-table-wrap{background:var(--card-bg);border-color:var(--card-border);box-shadow:var(--card-shadow)}.config-form input,.filter-label input,.table-form input,.file-actions input,.mkdir-form input{background:var(--input-bg);border-color:var(--input-border);color:var(--text-primary)}.primary-button{background:var(--accent-gold);color:var(--accent-gold-text)}.primary-button:hover{background:var(--accent-gold-hover)}.secondary-button{background:var(--secondary-bg);border-color:var(--secondary-border);color:var(--secondary-text)}.danger-button{background:var(--danger-bg);border-color:var(--danger-border);color:var(--danger-text)}.data-table th,.user-table th,.file-table-wrap th{background:var(--table-header-bg);color:var(--table-header-text)}.data-table th,.data-table td,.user-table th,.user-table td,.file-table-wrap th,.file-table-wrap td{border-bottom-color:var(--table-border)}th,td{color:var(--text-primary)}.text-link{color:var(--link-color)}.method.GET{background:#152535;color:#6ab0e8}.method.PUT{background:#2a2015;color:#e8a555}.method.DELETE{background:#2a1515;color:#e88078}.method.MKCOL{background:#152a22;color:#5ec98f}.method.HEAD{background:#1c1a2e;color:#9d8cf0}.method.LOCK{background:#2a2315;color:#e0b74f}.method.UNLOCK{background:#1e2629;color:#90b8c4}.status.success{background:#152a22;color:#5ec98f}.status.warn{background:#2a2015;color:#e8a555}.status.error{background:#2a1515;color:#e88078}.restore-btn{background:#5ec98f;color:#fff}.empty-btn{background:var(--danger-text)}[data-theme="dark"] h1,[data-theme="dark"] h2,[data-theme="dark"] h3,[data-theme="dark"] label{color:var(--text-primary)}[data-theme="dark"] .card-meta,[data-theme="dark"] .card-label{color:var(--text-secondary)!important}[data-theme="dark"] .user-table tbody th{color:var(--text-primary)}`;
var TABLE_POLISH_CSS = `.data-table-wrap{overflow-x:auto;background:var(--card-bg);border:1px solid var(--card-border);border-radius:7px;box-shadow:var(--card-shadow)}.data-table,.user-table,.file-table-wrap table{width:100%;border-collapse:collapse}.data-table th,.data-table td,.user-table th,.user-table td,.file-table-wrap th,.file-table-wrap td{padding:14px 16px;text-align:left;vertical-align:middle;border-bottom:1px solid var(--table-border)}.data-table th,.user-table th,.file-table-wrap th{background:var(--table-header-bg);color:var(--table-header-text);font-size:12px;font-weight:800;letter-spacing:.04em}.data-table tbody tr:last-child td,.user-table tbody tr:last-child td,.file-table-wrap tbody tr:last-child td{border-bottom:0}.data-table .path{max-width:320px}.primary-button,.secondary-button,.danger-button,.restore-btn,.empty-btn{min-height:40px;display:inline-flex;align-items:center;justify-content:center;line-height:1.2}.data-table form{margin:0}.method,.status{display:inline-flex;align-items:center;min-height:26px;padding:3px 8px}.empty-form{display:flex;justify-content:flex-end;gap:10px}.empty-btn{margin-top:18px}`;
const FILES_CSS = `
.secondary-button{padding:12px 18px;border:1px solid #397277;border-radius:2px;background:#fff;color:#285b60;font:inherit;font-weight:800;cursor:pointer}.inline-button{display:inline-block;margin:12px 0 18px}.file-table-wrap{overflow-x:auto;background:rgba(255,255,255,.82);border:1px solid #d7e0dc}.file-table-wrap table{width:100%;border-collapse:collapse;min-width:640px}.file-table-wrap th,.file-table-wrap td{padding:15px 18px;text-align:left;border-bottom:1px solid #e0e7e3}.file-table-wrap th{background:#f2f6f3;color:#60716d;font-size:12px}.file-name{font-weight:700}.file-name a{color:#285b60}.folder-icon,.file-icon{display:inline-block;width:34px;margin-right:8px;color:#a47735;font-size:9px;font-weight:900}.file-icon{color:#51817c}.danger-button{padding:7px 11px;border:1px solid #c76c61;border-radius:2px;background:#fff5f3;color:#a43f35;font:inherit;font-size:12px;cursor:pointer}.empty-state{text-align:center;color:#71807e;padding:36px!important}
.check-col{width:44px;text-align:center}
td.check-col{text-align:center}
.file-check{width:16px;height:16px;cursor:pointer;vertical-align:middle}
.batch-notice{margin:0 0 18px;padding:12px 16px;background:#e7f4eb;border-left:3px solid #3d9368;border-radius:0 4px 4px 0;color:#176b48;font-size:14px}
[data-theme="dark"] .batch-notice{background:#152a22;color:#5ec98f}
.batch-toolbar{display:flex;flex-wrap:wrap;align-items:center;justify-content:flex-end;gap:10px;margin:16px 0 0}
.batch-hint{margin-right:auto;font-size:13px;color:var(--text-secondary)}
.batch-toolbar .batch-target-input{flex:1;min-width:200px;max-width:320px;height:40px;padding:0 10px;border:1px solid var(--input-border);border-radius:4px;background:var(--input-bg);color:var(--text-primary);font:inherit;cursor:pointer}
.dir-menu{position:relative}
.dir-menu .batch-target-input{flex:0 0 auto;width:260px;text-align:left;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dir-menu-panel{position:absolute;bottom:calc(100% + 6px);left:0;min-width:220px;background:var(--input-bg);border:1px solid var(--input-border);border-radius:6px;box-shadow:0 8px 24px rgba(0,0,0,.25);padding:6px;z-index:50}
.dir-menu-item{position:relative;display:flex;align-items:center;justify-content:space-between;gap:12px;padding:8px 12px;border-radius:4px;cursor:pointer;font-size:14px;color:var(--text-primary);white-space:nowrap}
.dir-menu-item:hover,.dir-menu-item.open{background:rgba(127,127,127,.15)}
.dir-menu-arrow{color:var(--text-secondary);font-size:12px}
.dir-menu-submenu{display:none;position:absolute;left:100%;top:-6px;min-width:200px;background:var(--input-bg);border:1px solid var(--input-border);border-radius:6px;box-shadow:0 8px 24px rgba(0,0,0,.25);padding:6px;z-index:60}
.dir-menu-item:hover>.dir-menu-submenu,.dir-menu-item.open>.dir-menu-submenu{display:block}
.dir-menu-item.flip-left>.dir-menu-submenu{left:auto;right:100%}
.batch-toolbar .secondary-button,.batch-toolbar .danger-button{margin:0;height:40px;min-height:40px;padding:0 16px}
.files-storage-stack{display:flex;flex-direction:column;align-items:flex-end;gap:10px}
.files-storage-stack .storage-badge{align-items:flex-end;text-align:right}
.files-search{margin:0 0 18px}
.files-search-form{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.files-search-form input[type="search"]{flex:1;min-width:200px;max-width:360px;height:40px;padding:0 12px;border:1px solid var(--input-border);border-radius:4px;background:var(--input-bg);color:var(--text-primary);font:inherit}
.search-hint{margin:0 0 12px;font-size:13px}
.sort-link{color:inherit;text-decoration:none}
.sort-link:hover{color:var(--text-primary)}
.row-actions{display:flex;align-items:center;justify-content:flex-end;gap:8px}
.share-form{display:flex;align-items:center;gap:6px;margin:0}
.share-expiry{height:34px;padding:0 6px;border:1px solid var(--input-border);border-radius:4px;background:var(--input-bg);color:var(--text-primary);font:inherit;font-size:13px}
.upload-row{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.upload-card.drag-over{border-color:#3d9368;box-shadow:0 0 0 2px rgba(61,147,104,.25)}
.upload-queue{margin-top:10px;display:flex;flex-direction:column;gap:8px}
.upload-item{display:flex;align-items:center;gap:10px;font-size:13px}
.upload-item .upload-name{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:600}
.upload-item .upload-progress{flex:2;height:6px;margin-top:0}
.upload-item-status{min-width:72px;text-align:right;color:var(--text-secondary)}
.upload-item-status.active{color:var(--text-primary)}
.upload-item-status.ok{color:#176b48}
.upload-item-status.err{color:#a43f35}
.upload-progress{height:8px;border-radius:4px;background:rgba(127,127,127,.2);margin-top:10px;overflow:hidden}
.upload-progress div{height:100%;width:0;border-radius:4px;background:#3d9368;transition:width .2s}
.upload-progress #upload-progress-bar{height:100%;width:0;border-radius:4px;background:#3d9368;transition:width .2s}
.upload-status{display:block;margin-top:6px;font-size:13px;color:var(--text-secondary);min-height:18px}
.file-thumb{width:34px;height:34px;object-fit:cover;border-radius:4px;margin-right:8px;vertical-align:middle;border:1px solid var(--card-border);flex:none}
.copy-form{margin:0}
.preview-shell{display:block;margin:0 auto;max-width:900px;padding:20px 24px}
.preview-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;margin-bottom:16px}
.preview-heading strong{font-size:16px;word-break:break-all}
.preview-meta{display:block;margin-top:4px;color:var(--text-secondary);font-size:12px}
.preview-media img{max-width:100%;border-radius:6px;border:1px solid var(--card-border)}
.preview-text{max-height:70vh;overflow:auto;background:var(--input-bg);border:1px solid var(--card-border);border-radius:6px;padding:14px;font-size:13px;line-height:1.6;white-space:pre-wrap;word-break:break-all;color:var(--text-primary)}
.files-pager{display:flex;align-items:center;justify-content:center;gap:16px;margin:16px 0 0;font-size:14px}
.pager-link{color:var(--text-primary);text-decoration:none;padding:6px 12px;border:1px solid var(--input-border);border-radius:4px;background:var(--input-bg)}
.pager-link:hover:not(.disabled){border-color:var(--text-secondary)}
.pager-link.disabled{opacity:.45;cursor:default}
.pager-status{color:var(--text-secondary)}
.shares-section{margin-top:24px}
.shares-section .card-heading{margin-bottom:12px}
`;

var FORM_LAYOUT_CSS = `.icon-badge{width:auto;min-width:32px;padding:0 8px;white-space:nowrap;overflow:visible}.uuid-row{display:flex;gap:8px;align-items:center}.uuid-row input{flex:1;min-width:0;margin-top:0}.uuid-check-btn{margin:0;white-space:nowrap;height:44px;min-height:44px;display:inline-flex;align-items:center;justify-content:center;padding:0 16px;line-height:1}.uuid-result{display:block;margin-top:6px;font-size:12px}.uuid-result.error{color:#a43f35}.uuid-result.success{color:#176b48}.account-actions{display:flex;flex-wrap:wrap;align-items:center;gap:12px;margin-top:18px}.account-actions .inline-button{display:inline-flex;align-items:center;justify-content:center;margin:0;height:44px;padding:0 18px;line-height:1}.account-actions .delete-account-form{margin:0}.account-actions .danger-button{display:inline-flex;align-items:center;justify-content:center;height:44px;padding:0 18px;font-size:13px;font-weight:800;border-radius:4px}.storage-badge{display:flex;flex-direction:column;gap:5px;padding:12px 18px;background:var(--card-bg);border:1px solid var(--card-border);border-radius:7px;box-shadow:var(--card-shadow);font-size:13px;color:var(--text-secondary);white-space:nowrap}.storage-badge strong{color:var(--text-primary);font-size:15px;letter-spacing:-.02em}.page-heading>.storage-badge{align-self:flex-start;margin-top:24px}.session-card{margin-top:22px;padding:28px}.session-card .config-form{margin-top:18px;max-width:420px}.config-form select{display:block;width:100%;margin-top:7px;padding:13px 14px;border:1px solid var(--input-border);border-radius:2px;background:var(--input-bg);color:var(--text-primary);font:inherit;outline:none}.config-form select:focus{border-color:#4c8581;box-shadow:0 0 0 3px rgba(76,133,129,.14)}`;
var TOPBAR_LAYOUT_CSS = `.topbar-inner{display:flex;align-items:center;justify-content:flex-start;gap:16px}.topbar-inner>.topbar-right,.topbar-inner>div:not(.brand):last-child,.topbar-inner>.text-link{margin-left:auto}.topbar-right{display:flex;align-items:center;justify-content:flex-end;gap:16px;flex-wrap:wrap}@media(max-width:720px){.topbar-right{gap:10px}}`;
var LOGIN_DARK_CSS = `[data-theme="dark"] .login-panel{background:#182b2e;border-color:#345052;color:#c7d7d3}[data-theme="dark"] .login-panel h1,[data-theme="dark"] .login-panel label{color:#c7d7d3}[data-theme="dark"] .login-panel .muted{color:#91aaa4!important}[data-theme="dark"] .login-panel input{background:#122326;border-color:#3a5558;color:#c7d7d3}`;
var THEME_TOGGLE_CSS = `.theme-toggle{appearance:none;-webkit-appearance:none;width:36px;height:36px;padding:0;border:0;border-radius:50%;background:transparent;box-shadow:none;color:currentColor;display:grid;place-items:center;cursor:pointer;font-size:17px;line-height:1;opacity:.86}.theme-toggle:hover{background:transparent;box-shadow:none;opacity:1;transform:scale(1.08)}.theme-toggle:focus-visible{outline:2px solid currentColor;outline-offset:3px}.login-shell>.theme-toggle{position:absolute;top:16px;right:20px;margin:0;z-index:10}`;
var FILE_ACTION_ALIGNMENT_CSS = `.file-actions{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;align-items:stretch;margin-bottom:22px}.file-action-card{min-width:0;padding:18px;background:var(--card-bg);border:1px solid var(--card-border);border-radius:7px;box-shadow:var(--card-shadow)}.file-action-heading{display:flex;flex-direction:column;gap:5px;margin-bottom:14px;color:var(--text-primary)}.file-action-heading span{color:var(--text-secondary);font-size:12px}.file-action-card form{display:grid;grid-template-columns:minmax(0,1fr) 116px;align-items:center;gap:8px;width:100%;min-width:0;min-height:44px;overflow:hidden}.file-action-card input[type=file],.file-action-card input[name=name]{display:block;width:100%;min-width:0;height:44px;line-height:42px;padding:0 10px;overflow:hidden;text-overflow:ellipsis;border:1px solid #cbd7d3;background:#fff;font:inherit}.file-action-card input[type=file]::file-selector-button{height:42px;margin-right:8px;padding:0 10px;border:0;border-right:1px solid var(--input-border);background:var(--table-header-bg);color:var(--text-primary);font:inherit}.file-action-card button{width:116px;min-width:116px;height:44px;min-height:44px;padding:0 10px;margin:0;white-space:nowrap}@media(max-width:720px){.file-actions{grid-template-columns:1fr}.file-action-card form{grid-template-columns:minmax(0,1fr) 116px}}.upload-row{flex-wrap:nowrap}.upload-row input[type=file]{flex:1;min-width:0;width:auto}`;


const THEME_INIT_SCRIPT = `<script>(function(){try{var s=localStorage.getItem('cf-webdav-theme');if(s==='dark'||(!s&&window.matchMedia('(prefers-color-scheme:dark)').matches))document.documentElement.setAttribute('data-theme','dark');}catch(e){}})();</script>`;
const THEME_SCRIPT = `<script>(function(){var dark=document.documentElement.getAttribute('data-theme')==='dark';var t=document.querySelectorAll('.theme-toggle');for(var i=0;i<t.length;i++)t[i].textContent=dark?'\u2600\uFE0F':'\u{1F319}';})();function toggleTheme(){var h=document.documentElement;var dark=h.getAttribute('data-theme')==='dark';if(dark){h.removeAttribute('data-theme');localStorage.setItem('cf-webdav-theme','light')}else{h.setAttribute('data-theme','dark');localStorage.setItem('cf-webdav-theme','dark')}var t=document.querySelectorAll('.theme-toggle');for(var i=0;i<t.length;i++)t[i].textContent=dark?'\u{1F319}':'\u2600\uFE0F'}</script>`;


