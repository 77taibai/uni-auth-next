import { existsSync } from "node:fs";
import { join } from "node:path";

/** 本地开发/脚本/测试时加载 .env；Vercel 由平台注入，无 .env 时静默跳过 */
export function loadDotenv(): void {
  const file = join(process.cwd(), ".env");
  if (!existsSync(file)) return;
  if (typeof process.loadEnvFile === "function") {
    try {
      process.loadEnvFile(file);
      return;
    } catch {
      /* fall through */
    }
  }
  const { readFileSync } = require("node:fs") as typeof import("node:fs");
  for (const line of readFileSync(file, "utf8").split(/\r?\n/)) {
    const match = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/.exec(line);
    if (!match) continue;
    const [, key, rawValue] = match;
    if (process.env[key] !== undefined) continue;
    process.env[key] = rawValue.replace(/^["']|["']$/g, "");
  }
}

/** 仅迁移所需：连接串。迁移不依赖 PUBLIC_ORIGIN / MASTER_KEY。 */
export function databaseUrlFromEnv(): string {
  const value = process.env.DATABASE_URL;
  if (!value) throw new Error("DATABASE_URL is required to run migrations");
  return value;
}
