import { query } from "../pool";

/** 连续失败 MAX_FAILURES 次 → 锁定 LOCK_SECONDS 秒；失败即续期 */
const MAX_FAILURES = 5;
const LOCK_SECONDS = 900;

export async function isLocked(ip: string): Promise<boolean> {
  const { rows } = await query<{ failures: number }>(
    "SELECT failures FROM login_rate_limits WHERE ip = $1 AND expires_at > now()",
    [ip]
  );
  return (rows[0]?.failures ?? 0) >= MAX_FAILURES;
}

/** 原子累加：不存在则插入，存在则递增并续期 */
export async function recordFailure(ip: string): Promise<void> {
  await query(
    `INSERT INTO login_rate_limits (ip, failures, expires_at)
     VALUES ($1, 1, now() + ($2 || ' seconds')::interval)
     ON CONFLICT (ip) DO UPDATE
       SET failures = login_rate_limits.failures + 1,
           expires_at = now() + ($2 || ' seconds')::interval`,
    [ip, LOCK_SECONDS]
  );
}

export async function clearFailures(ip: string): Promise<void> {
  await query("DELETE FROM login_rate_limits WHERE ip = $1", [ip]);
}

export { MAX_FAILURES, LOCK_SECONDS };
