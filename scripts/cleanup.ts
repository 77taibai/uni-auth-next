import { closePool } from "../src/db/pool.js";
import { loadDotenv } from "../src/config/dotenv.js";
import { loadConfig } from "../src/config/env.js";
import { cleanupExpired } from "../src/db/cleanup.js";

/** 定期清理过期的会话、授权请求、授权码、access token、挑战与限速行 */
async function main(): Promise<void> {
  loadDotenv();
  loadConfig();
  await cleanupExpired();
  console.log("expired rows cleaned");
}

main()
  .catch((err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exitCode = 1;
  })
  .finally(() => closePool());
