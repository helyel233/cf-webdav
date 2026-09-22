import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const kvTitle = process.env.WEBDAV_KV_TITLE || "cf-webdav-kv";
const bucketName = process.env.WEBDAV_R2_BUCKET || "cf-webdav-files";
const wrangler = process.platform === "win32" ? "npx.cmd" : "npx";

function run(args) {
  return execFileSync(wrangler, ["wrangler", ...args], {
    encoding: "utf8",
    stdio: ["inherit", "pipe", "inherit"],
  });
}

function jsonCommand(args) {
  try {
    return JSON.parse(run([...args, "--json"]));
  } catch {
    return null;
  }
}

const namespaces = jsonCommand(["kv", "namespace", "list"]) || [];
let namespace = namespaces.find((item) => item.title === kvTitle);
if (!namespace) namespace = jsonCommand(["kv", "namespace", "create", kvTitle]);
const namespaceId = namespace?.id || namespace?.namespace_id;
if (!namespaceId) throw new Error(`无法获取 KV namespace ID，请检查 API Token 权限：${kvTitle}`);

const buckets = jsonCommand(["r2", "bucket", "list"]) || [];
if (!buckets.some((item) => item.name === bucketName)) run(["r2", "bucket", "create", bucketName]);

const configPath = "wrangler.toml";
const config = readFileSync(configPath, "utf8")
  .replace(/(binding = "WEBDAV_KV"[\s\S]*?id = )"[^"]+"/, `$1"${namespaceId}"`)
  .replace(/(bucket_name = )"[^"]+"/, `$1"${bucketName}"`);
writeFileSync(configPath, config);
console.log(`WebDAV 资源已就绪：KV ${kvTitle} (${namespaceId})，R2 ${bucketName}`);
