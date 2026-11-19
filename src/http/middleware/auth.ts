import type { NextFunction, Request, Response } from "express";
import type { AppConfig } from "../../config/env.js";
import { SESSION_COOKIE, findSession, type LoginSession } from "../../services/sessionService.js";

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      session?: LoginSession | null;
      clientIp?: string;
      authContext?: { session: LoginSession };
      id?: string;
    }
  }
}

/** 读取 Cookie 对应的会话；过期判断在仓储层完成 */
export function loadSession() {
  return async (req: Request, _res: Response, next: NextFunction) => {
    try {
      req.session = await findSession(req.cookies?.[SESSION_COOKIE]);
      next();
    } catch (err) {
      next(err);
    }
  };
}

/** 可信代理：Vercel 只在自身代理层注入 x-forwarded-for，取首个客户端地址 */
export function resolveClientIp(trustProxy: boolean) {
  return (req: Request, _res: Response, next: NextFunction) => {
    let ip: string | undefined;
    if (trustProxy) {
      const header = req.headers["x-forwarded-for"];
      const raw = Array.isArray(header) ? header[0] : header;
      ip = raw?.split(",")[0]?.trim();
    }
    req.clientIp = ip || req.ip || req.socket.remoteAddress || "local";
    next();
  };
}

/** 要求完全认证的会话：API 返回 401，页面重定向 /login */
export function requireAuthApi() {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.session?.authenticated) return res.status(401).json({ error: "unauthorized" });
    next();
  };
}

export function requireAuthPage() {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.session?.authenticated) return res.redirect("/login");
    next();
  };
}

/** 所有 POST/PATCH/DELETE /api/* 保留 Origin 校验（叠加 SameSite=Lax） */
export function requireOrigin(config: AppConfig) {
  const expected = new URL(config.publicOrigin).origin;
  return (req: Request, res: Response, next: NextFunction) => {
    if (req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS") return next();
    const origin = req.headers.origin;
    if (!origin || typeof origin !== "string") return res.status(403).json({ error: "bad_origin" });
    try {
      if (new URL(origin).origin !== expected) return res.status(403).json({ error: "bad_origin" });
    } catch {
      return res.status(403).json({ error: "bad_origin" });
    }
    next();
  };
}
