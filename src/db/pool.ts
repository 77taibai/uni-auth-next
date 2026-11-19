import pg from "pg";
import { getConfig } from "../config/env.js";
import { databaseUrlFromEnv } from "../config/dotenv.js";

const { Pool } = pg;

/**
 * 模块顶层创建并复用连接池（Vercel 实例复用），不能每次请求新建。
 * 连接串可使用数据库提供商的 pooled URL。
 */
let pool: pg.Pool | null = null;

function resolveDatabaseUrl(): string {
  // 迁移/清理脚本只提供 DATABASE_URL 时也能工作
  try {
    return getConfig().databaseUrl;
  } catch {
    return databaseUrlFromEnv();
  }
}

export function getPool(): pg.Pool {
  if (pool) return pool;
  const databaseUrl = resolveDatabaseUrl();
  pool = new Pool({
    connectionString: databaseUrl,
    max: 5,
    idleTimeoutMillis: 10_000,
    connectionTimeoutMillis: 10_000,
    ssl: shouldUseSsl(databaseUrl) ? { rejectUnauthorized: false } : undefined,
  });
  pool.on("error", (err) => {
    console.error(JSON.stringify({ level: "error", msg: "pg pool idle error", error: err.message }));
  });
  return pool;
}

export async function query<T extends pg.QueryResultRow = pg.QueryResultRow>(
  text: string,
  values: unknown[] = []
): Promise<pg.QueryResult<T>> {
  return getPool().query<T>(text, values);
}

/** 在单个连接上执行事务；异常自动回滚并释放连接 */
export async function withTransaction<T>(fn: (client: pg.PoolClient) => Promise<T>): Promise<T> {
  const client = await getPool().connect();
  try {
    await client.query("BEGIN");
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch {
      /* ignore rollback failure */
    }
    throw err;
  } finally {
    client.release();
  }
}

export async function closePool(): Promise<void> {
  if (!pool) return;
  const current = pool;
  pool = null;
  await current.end();
}

/**
 * TLS 策略：显式 opt-in，避免对不支持 TLS 的数据库造成 ECONNRESET。
 * - DATABASE_SSL=require 时启用（生产推荐）
 * - 连接串带 sslmode=require 时启用；sslmode=disable 时禁用
 * - 其他情况默认禁用
 */
function shouldUseSsl(url: string): boolean {
  const explicit = process.env.DATABASE_SSL?.toLowerCase();
  if (explicit === "require" || explicit === "true") return true;
  if (explicit === "disable" || explicit === "false") return false;
  try {
    const sslmode = new URL(url).searchParams.get("sslmode");
    if (sslmode === "disable") return false;
    return sslmode === "require" || sslmode === "verify-ca" || sslmode === "verify-full";
  } catch {
    return false;
  }
}
