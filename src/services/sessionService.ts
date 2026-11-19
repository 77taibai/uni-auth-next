import { randomToken } from "../security/crypto.js";
import {
  createSession,
  deleteSession,
  getSession,
  setSessionPersistence,
  updateSession,
  type SessionRow,
} from "../db/repositories/sessionRepository.js";
import { cleanupExpired } from "../db/cleanup.js";

export const SESSION_COOKIE = "uni_auth_sid";
/** 永久登录 Cookie 有效期：一年 */
export const PERSISTENT_COOKIE_MAX_AGE_MS = 365 * 24 * 60 * 60 * 1000;

export type LoginSession = SessionRow;

export async function findSession(sid: string | undefined): Promise<LoginSession | null> {
  if (!sid) return null;
  return getSession(sid);
}

export async function startSession(persistent: boolean): Promise<LoginSession> {
  const sid = randomToken();
  await createSession({ sid, persistent });
  // 机会式清理过期行，避免依赖常驻定时任务
  if (Math.random() < 0.02) cleanupExpired().catch(() => {});
  const row = await getSession(sid);
  if (!row) throw new Error("failed to create session");
  return row;
}

/** 完成认证时轮换 sid，避免 session fixation */
export async function rotateSession(session: LoginSession, persistent: boolean): Promise<LoginSession> {
  const sid = randomToken();
  await createSession({ sid, persistent });
  await deleteSession(session.sid);
  const row = await getSession(sid);
  if (!row) throw new Error("failed to rotate session");
  return row;
}

export async function markPasswordOk(session: LoginSession): Promise<void> {
  await updateSession(session.sid, { passwordOk: true, authenticated: false });
}

/** 认证完成：轮换 sid、写入 auth_time、清除 password_ok */
export async function markAuthenticated(session: LoginSession): Promise<LoginSession> {
  const rotated = await rotateSession(session, session.persistent);
  await updateSession(rotated.sid, { passwordOk: false, authenticated: true, authTime: new Date() });
  const row = await getSession(rotated.sid);
  if (!row) throw new Error("failed to load rotated session");
  return row;
}

export async function setPersistence(session: LoginSession, persistent: boolean): Promise<void> {
  await setSessionPersistence(session.sid, persistent);
  session.persistent = persistent;
}

export async function destroySession(session: LoginSession): Promise<void> {
  await deleteSession(session.sid);
}
