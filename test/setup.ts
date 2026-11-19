import { beforeAll, afterAll } from "vitest";
import { closePool } from "../src/db/pool";
import { runMigrations, truncateAll } from "../src/db/migrate";
import { ensureProfile } from "./helpers";

/**
 * 每个测试文件都从干净数据库开始，并预置一份管理员身份
 * （等价于 /setup 完成后的状态）。
 */
beforeAll(async () => {
  await runMigrations();
  await truncateAll();
  await ensureProfile();
});

afterAll(async () => {
  await closePool();
});
