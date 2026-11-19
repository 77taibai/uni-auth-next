import { closePool } from "../src/db/pool.js";
import { loadDotenv } from "../src/config/dotenv.js";
import { runMigrations } from "../src/db/migrate.js";

/** 只依赖 DATABASE_URL；可在 CI / Vercel 构建期执行 */
async function main(): Promise<void> {
  loadDotenv();
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required to run migrations");
  const result = await runMigrations((msg) => console.log(msg));
  console.log(
    result.applied.length
      ? `migrations applied: ${result.applied.join(", ")}`
      : "migrations up to date"
  );
}

main()
  .catch((err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exitCode = 1;
  })
  .finally(() => closePool());
