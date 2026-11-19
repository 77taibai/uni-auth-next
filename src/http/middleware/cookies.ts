import type { AppConfig } from "../../config/env";
import { SESSION_COOKIE, PERSISTENT_COOKIE_MAX_AGE_MS } from "../../services/sessionService";
import type { Response } from "express";

/** 按登录方式写入会话 Cookie：永久登录带 maxAge，单次登录为浏览器会话级 */
export function setSessionCookie(config: AppConfig, res: Response, sid: string, persistent: boolean): void {
  res.cookie(SESSION_COOKIE, sid, {
    httpOnly: true,
    sameSite: "lax",
    secure: config.isProduction,
    path: "/",
    ...(persistent ? { maxAge: PERSISTENT_COOKIE_MAX_AGE_MS } : {}),
  });
}

export function clearSessionCookie(res: Response): void {
  res.clearCookie(SESSION_COOKIE, { path: "/" });
}
