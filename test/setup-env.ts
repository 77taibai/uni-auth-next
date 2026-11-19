import { readFileSync } from "node:fs";
import { join } from "node:path";

/** 测试环境变量：只设置基础设施配置；身份资料由 /setup 写入数据库 */
function applyTestEnv(): void {
  const env = process.env;
  env.NODE_ENV = "test";
  env.PUBLIC_ORIGIN ??= "http://localhost:3000";
  env.MASTER_KEY ??= "uNV5kh/JJGLrtAkw7NBt1yeYN7zi6Vh2HgC65fkGcvc=";
  env.PBKDF2_ITERATIONS ??= "1000";
  env.DATABASE_URL ??= loadDatabaseUrlFromEnvFile();
}

function loadDatabaseUrlFromEnvFile(): string {
  try {
    const raw = readFileSync(join(process.cwd(), ".env"), "utf8");
    const line = raw.split(/\r?\n/).find((l) => l.startsWith("DATABASE_URL="));
    if (line) return line.slice("DATABASE_URL=".length).trim();
  } catch {
    /* no .env */
  }
  return "postgresql://postgres:cNzb04kGjTNx4Xss@db.ejdgwgljzzjhvwgiirnq.supabase.co:5432/postgres";
}

applyTestEnv();
