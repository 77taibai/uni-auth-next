import { query } from "../pool";

export type SessionRow = {
  sid: string;
  created_at: Date;
  expires_at: Date | null;
  persistent: boolean;
  password_ok: boolean;
  authenticated: boolean;
  auth_time: Date | null;
};

/** 单次登录的兜底过期：24 小时；永久登录不设过期 */
export const SESSION_TTL_SECONDS = 86400;

export async function createSession(input: {
  sid: string;
  persistent: boolean;
  passwordOk?: boolean;
  authenticated?: boolean;
  authTime?: Date | null;
}): Promise<void> {
  const expiresAt = input.persistent ? null : new Date(Date.now() + SESSION_TTL_SECONDS * 1000);
  await query(
    `INSERT INTO auth_sessions (sid, expires_at, persistent, password_ok, authenticated, auth_time)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [
      input.sid,
      expiresAt,
      input.persistent,
      input.passwordOk ?? false,
      input.authenticated ?? false,
      input.authTime ?? null,
    ]
  );
}

/** 读取时同时判断过期 */
export async function getSession(sid: string): Promise<SessionRow | null> {
  const { rows } = await query<SessionRow>(
    `SELECT * FROM auth_sessions WHERE sid = $1 AND (expires_at IS NULL OR expires_at > now())`,
    [sid]
  );
  return rows[0] ?? null;
}

export async function updateSession(
  sid: string,
  patch: {
    persistent?: boolean;
    passwordOk?: boolean;
    authenticated?: boolean;
    authTime?: Date | null;
    expiresAt?: Date | null;
  }
): Promise<void> {
  const sets: string[] = [];
  const values: unknown[] = [];
  const push = (col: string, value: unknown) => {
    values.push(value);
    sets.push(`${col} = $${values.length}`);
  };
  if (patch.persistent !== undefined) push("persistent", patch.persistent);
  if (patch.passwordOk !== undefined) push("password_ok", patch.passwordOk);
  if (patch.authenticated !== undefined) push("authenticated", patch.authenticated);
  if (patch.authTime !== undefined) push("auth_time", patch.authTime);
  if (patch.expiresAt !== undefined) push("expires_at", patch.expiresAt);
  if (sets.length === 0) return;
  values.push(sid);
  await query(`UPDATE auth_sessions SET ${sets.join(", ")} WHERE sid = $${values.length}`, values);
}

/** 调整登录持久性：永久登录不设过期，单次登录回归 24 小时兜底 */
export async function setSessionPersistence(sid: string, persistent: boolean): Promise<void> {
  const expiresAt = persistent ? null : new Date(Date.now() + SESSION_TTL_SECONDS * 1000);
  await query("UPDATE auth_sessions SET persistent = $2, expires_at = $3 WHERE sid = $1", [
    sid,
    persistent,
    expiresAt,
  ]);
}

export async function deleteSession(sid: string): Promise<void> {
  await query("DELETE FROM auth_sessions WHERE sid = $1", [sid]);
}

export async function deleteExpiredSessions(): Promise<void> {
  await query("DELETE FROM auth_sessions WHERE expires_at IS NOT NULL AND expires_at <= now()");
}
