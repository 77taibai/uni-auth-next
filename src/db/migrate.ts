import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { getPool } from "./pool.js";

const MIGRATIONS_DIR = fileURLToPath(new URL("./migrations", import.meta.url));

export type MigrationResult = { applied: string[]; skipped: string[] };

/**
 * 按文件名顺序执行 src/db/migrations/*.sql，记录在 schema_migrations 中保证幂等。
 * CI/发布阶段执行，不在 Function 请求中执行。
 */
export async function runMigrations(log: (msg: string) => void = () => {}): Promise<MigrationResult> {
  const pool = getPool();
  await pool.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      name text PRIMARY KEY,
      applied_at timestamptz NOT NULL DEFAULT now()
    )
  `);
  const appliedSet = new Set(
    (await pool.query<{ name: string }>("SELECT name FROM schema_migrations")).rows.map((r) => r.name)
  );

  const result: MigrationResult = { applied: [], skipped: [] };
  const files = readdirSync(MIGRATIONS_DIR)
    .filter((f) => f.endsWith(".sql"))
    .sort();

  for (const file of files) {
    if (appliedSet.has(file)) {
      result.skipped.push(file);
      log(`skip ${file} (already applied)`);
      continue;
    }
    const sql = readFileSync(join(MIGRATIONS_DIR, file), "utf8");
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(sql);
      await client.query("INSERT INTO schema_migrations (name) VALUES ($1)", [file]);
      await client.query("COMMIT");
      result.applied.push(file);
      log(`applied ${file}`);
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  }
  return result;
}

/** 测试辅助：清空所有业务表（保留 schema_migrations） */
export async function truncateAll(): Promise<void> {
  await getPool().query(`
    TRUNCATE TABLE
      admin_profile,
      passkey_credentials,
      totp_credentials,
      clients,
      auth_sessions,
      oidc_auth_requests,
      oidc_authorization_codes,
      oidc_access_tokens,
      webauthn_challenges,
      login_rate_limits,
      oidc_signing_keys
    RESTART IDENTITY CASCADE
  `);
}

