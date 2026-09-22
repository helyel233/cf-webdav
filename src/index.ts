interface Env {
  WEBDAV_BUCKET: R2Bucket;
  WEBDAV_KV: KVNamespace;
  ADMIN_USERNAME?: string;
  ADMIN_PASSWORD?: string;
  DAV_PREFIX?: string;
}

interface FileMeta {
  type: "file";
  size: number;
  etag?: string;
  contentType?: string;
  updatedAt: string;
}

const METHODS = ["OPTIONS", "PROPFIND", "GET", "PUT", "DELETE", "MKCOL", "COPY", "MOVE", "HEAD"];
const META_PREFIX = "meta:";
const DIR_PREFIX = "dir:";
const CREDENTIALS_KEY = "config:credentials";
const SESSION_PREFIX = "session:";
const DEFAULT_USERNAME = "admin";
const DEFAULT_PASSWORD = "admin123456";
const SESSION_TTL = 60 * 60 * 24 * 7;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const pathname = new URL(request.url).pathname;
    if (pathname === "/__admin" || pathname.startsWith("/__admin/")) return adminRequest(request, env);
    if (request.method === "OPTIONS") return optionsResponse();
    if (!(await authenticate(request, env))) {
      return new Response("Unauthorized", {
        status: 401,
        headers: { "WWW-Authenticate": 'Basic realm="Cloudflare WebDAV"' },
      });
    }

    let path: string;
    try {
      path = requestPath(request, env);
    } catch {
      return textResponse("Bad Request", 400);
    }

    try {
      switch (request.method) {
        case "PROPFIND": return await propfind(request, env, path);
        case "GET": return await getObject(env, path, false, request);
        case "HEAD": return await getObject(env, path, true, request);
        case "PUT": return await putObject(request, env, path);
        case "DELETE": return await deletePath(env, path);
        case "MKCOL": return await makeCollection(env, path);
        case "COPY": return await copyOrMove(request, env, path, false);
        case "MOVE": return await copyOrMove(request, env, path, true);
        default: return textResponse("Method Not Allowed", 405, { Allow: METHODS.join(", ") });
      }
    } catch (error) {
      console.error("WebDAV request failed", { method: request.method, path, error });
      return textResponse("Internal Server Error", 500);
    }
  },
};

async function authenticate(request: Request, env: Env): Promise<boolean> {
  const credentials = await getCredentials(env);
  const header = request.headers.get("Authorization");
  if (!header?.startsWith("Basic ")) return false;
  try {
    const decoded = atob(header.slice(6));
    const separator = decoded.indexOf(":");
    return separator >= 0 && decoded.slice(0, separator) === credentials.username
      && await verifyPassword(decoded.slice(separator + 1), credentials.passwordHash);
  } catch {
    return false;
  }
}

interface Credentials {
  username: string;
  passwordHash: string;
  salt: string;
}

async function getCredentials(env: Env): Promise<Credentials> {
  const saved = await env.WEBDAV_KV.get(CREDENTIALS_KEY, "json") as Credentials | null;
  if (saved?.username && saved.passwordHash && saved.salt) return saved;
  return {
    username: env.ADMIN_USERNAME || DEFAULT_USERNAME,
    passwordHash: await hashPassword(env.ADMIN_PASSWORD || DEFAULT_PASSWORD, "default-salt"),
    salt: "default-salt",
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
  if (url.pathname === "/__admin/login" && request.method === "POST") {
    const form = await request.formData();
    const credentials = await getCredentials(env);
    const username = String(form.get("username") ?? "");
    const password = String(form.get("password") ?? "");
    if (username !== credentials.username || !(await verifyPassword(password, credentials.passwordHash, credentials.salt))) return adminLoginPage("用户名或密码错误");
    const token = bytesToBase64(crypto.getRandomValues(new Uint8Array(32)));
    await env.WEBDAV_KV.put(`${SESSION_PREFIX}${token}`, username, { expirationTtl: SESSION_TTL });
    return new Response(null, { status: 303, headers: { Location: "/__admin", "Set-Cookie": `cf_webdav_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL}` } });
  }
  if (!(await sessionUser(request, env))) return adminLoginPage();
  if (url.pathname === "/__admin/account" && request.method === "POST") {
    const form = await request.formData();
    const username = String(form.get("username") ?? "").trim();
    const password = String(form.get("password") ?? "");
    if (!/^[A-Za-z0-9._-]{2,64}$/.test(username)) return adminPage("用户名须为 2-64 位字母、数字、点、下划线或短横线");
    if (password.length < 8) return adminPage("密码至少需要 8 位");
    const salt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
    await env.WEBDAV_KV.put(CREDENTIALS_KEY, JSON.stringify({ username, salt, passwordHash: await hashPassword(password, salt) }));
    return adminPage("账号已更新，新的 WebDAV 凭证已生效");
  }
  if (request.method !== "GET") return textResponse("Method Not Allowed", 405);
  return adminPage();
}

async function sessionUser(request: Request, env: Env): Promise<string | null> {
  const cookie = request.headers.get("Cookie")?.match(/(?:^|; )cf_webdav_session=([^;]+)/)?.[1];
  return cookie ? env.WEBDAV_KV.get(`${SESSION_PREFIX}${cookie}`) : null;
}

function adminLoginPage(error = ""): Response {
  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>WebDAV 管理登录</title><style>${ADMIN_CSS}</style><main><h1>WebDAV 管理</h1>${error ? `<p class="error">${escapeXml(error)}</p>` : ""}<form method="post" action="/__admin/login"><label>用户名<input name="username" autocomplete="username" required></label><label>密码<input name="password" type="password" autocomplete="current-password" required></label><button>登录</button></form></main>`);
}

function adminPage(message = ""): Response {
  return htmlResponse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>WebDAV 账号设置</title><style>${ADMIN_CSS}</style><main><h1>WebDAV 账号设置</h1>${message ? `<p class="success">${escapeXml(message)}</p>` : ""}<p>修改后，WebDAV 客户端需要使用新的用户名和密码重新连接。</p><form method="post" action="/__admin/account"><label>新用户名<input name="username" autocomplete="username" required></label><label>新密码<input name="password" type="password" autocomplete="new-password" minlength="8" required></label><button>保存账号</button></form></main>`);
}

const ADMIN_CSS = "body{font:16px system-ui,sans-serif;background:#f3f5f7;color:#18212b;margin:0}main{max-width:420px;margin:10vh auto;padding:32px;background:white;border:1px solid #d9e0e6;border-radius:8px;box-shadow:0 8px 30px #18212b14}h1{font-size:24px;margin-top:0}label{display:block;margin:18px 0 6px}input{box-sizing:border-box;width:100%;padding:11px;margin-top:6px;border:1px solid #aeb8c2;border-radius:5px;font-size:16px}button{margin-top:20px;padding:11px 18px;border:0;border-radius:5px;background:#1769aa;color:white;font-size:16px;cursor:pointer}.error{color:#b42318}.success{color:#067647}";

function htmlResponse(body: string): Response {
  return new Response(body, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
}

function requestPath(request: Request, env: Env): string {
  const pathname = new URL(request.url).pathname;
  const prefix = normalizePrefix(env.DAV_PREFIX ?? "");
  const path = decodeURIComponent(pathname).replace(/^\/+|\/+$/g, "");
  if (prefix && path !== prefix && !path.startsWith(`${prefix}/`)) throw new Error("outside prefix");
  const relative = prefix ? path.slice(prefix.length).replace(/^\/+/, "") : path;
  const segments = relative ? relative.split("/") : [];
  if (segments.some((segment) => !segment || segment === "." || segment === "..")) throw new Error("invalid path");
  return segments.join("/");
}

function destinationPath(request: Request, env: Env): string {
  const destination = request.headers.get("Destination");
  if (!destination) throw new Error("missing destination");
  return requestPath(new Request(new URL(destination, request.url), request), env);
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
    await env.WEBDAV_BUCKET.delete(r2Key(path));
    await env.WEBDAV_KV.delete(metaKey(path));
    return new Response(null, { status: 204 });
  }
  if (!(await env.WEBDAV_KV.get(dirKey(path))) && !(await hasChildren(env, path))) return textResponse("Not Found", 404);
  const objects = await listAllObjects(env, `${path}/`);
  for (let index = 0; index < objects.length; index += 1000) {
    await env.WEBDAV_BUCKET.delete(objects.slice(index, index + 1000).map((item) => item.key));
  }
  await deleteMetadataUnder(env, path);
  return new Response(null, { status: 204 });
}

async function copyOrMove(request: Request, env: Env, source: string, move: boolean): Promise<Response> {
  if (!source) return textResponse("The root collection cannot be moved", 403);
  const destination = destinationPath(request, env);
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

async function propfind(request: Request, env: Env, path: string): Promise<Response> {
  const depth = request.headers.get("Depth") ?? "infinity";
  if (depth === "infinity") return textResponse("Depth infinity is not supported", 403);
  const rootObject = path ? await env.WEBDAV_BUCKET.head(r2Key(path)) : null;
  const rootIsDirectory = !rootObject;
  if (path && !rootObject && !(await env.WEBDAV_KV.get(dirKey(path))) && !(await hasChildren(env, path))) return textResponse("Not Found", 404);
  const entries = [{ path, directory: rootIsDirectory }];
  if (depth !== "0" && rootIsDirectory) entries.push(...await listChildren(env, path));
  const xml = entries.map((entry) => propResponse(request, env, entry.path, entry.directory)).join("");
  return new Response(`<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:">${xml}</d:multistatus>`, { status: 207, headers: { "Content-Type": "application/xml; charset=utf-8" } });
}

async function propResponse(request: Request, env: Env, path: string, directory: boolean): Promise<string> {
  const object = directory ? null : await env.WEBDAV_BUCKET.head(r2Key(path));
  const href = `${new URL(request.url).origin}${urlPath(env, path)}${directory ? "/" : ""}`;
  const size = object?.size ?? 0;
  const modified = object?.uploaded?.toUTCString() ?? new Date().toUTCString();
  return `<d:response><d:href>${escapeXml(href)}</d:href><d:propstat><d:prop><d:resourcetype>${directory ? "<d:collection/>" : ""}</d:resourcetype><d:getcontentlength>${size}</d:getcontentlength><d:getlastmodified>${modified}</d:getlastmodified><d:getcontenttype>${directory ? "httpd/unix-directory" : escapeXml(object?.httpMetadata?.contentType ?? "application/octet-stream")}</d:getcontenttype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>`;
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

function textResponse(body: string, status: number, extraHeaders: Record<string, string> = {}): Response {
  return new Response(body, { status, headers: { "Content-Type": "text/plain; charset=utf-8", ...extraHeaders } });
}