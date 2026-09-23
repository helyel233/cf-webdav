import { readFile } from "node:fs/promises";

const config = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");

if (config.includes('id = "replace-during-setup"')) {
  console.error(
    "Deployment stopped: replace wrangler.toml's KV namespace id with the real namespace ID before using GitHub deployment, or use the Dashboard Deploy button instead. For local automatic setup, run npm run deploy:setup.",
  );
  process.exit(1);
}