import { readFile } from "node:fs/promises";

const config = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");

if (config.includes('id = "replace-during-setup"')) {
  console.error(
    "Deployment stopped: replace wrangler.toml's KV namespace id with the real namespace ID, or run npm run deploy:setup first.",
  );
  process.exit(1);
}