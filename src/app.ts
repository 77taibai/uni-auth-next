import express, { type NextFunction, type Request, type Response } from "express";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import { randomUUID } from "node:crypto";
import type { AppConfig } from "./config/env.js";
import { PUBLIC_DIR } from "./config/assets.js";
import { loadSession, requireAuthPage, resolveClientIp } from "./http/middleware/auth.js";
import { requestLogger } from "./http/middleware/logging.js";
import { healthRoutes } from "./http/routes/healthRoutes.js";
import { oauthRoutes, legacyOidcRoutes } from "./http/routes/oauthRoutes.js";
import { setupRoutes } from "./http/routes/setupRoutes.js";
import { sessionRoutes } from "./http/routes/sessionRoutes.js";
import { adminRoutes } from "./http/routes/adminRoutes.js";
import { pageRoutes } from "./http/routes/pageRoutes.js";
import { errorPage } from "./views/pages.js";

export function createApp(config: AppConfig): express.Express {
  const app = express();

  // Vercel 在边缘代理注入 x-forwarded-for；不信任客户端自带的同名头
  app.set("trust proxy", config.isProduction);
  app.disable("x-powered-by");

  app.use((req: Request, res: Response, next: NextFunction) => {
    req.id = req.headers["x-request-id"]?.toString() ?? randomUUID();
    res.setHeader("x-request-id", req.id);
    next();
  });
  app.use(requestLogger());

  app.use(
    helmet({
      contentSecurityPolicy: false,
      crossOriginEmbedderPolicy: false,
    })
  );
  app.use(express.json({ limit: "64kb" }));
  app.use(express.urlencoded({ extended: false, limit: "64kb" }));
  app.use(cookieParser());
  app.use(resolveClientIp(config.isProduction));
  // 会话读取较早注册：setup、OAuth consent、页面与管理 API 都依赖 req.session
  app.use(loadSession());

  app.use(healthRoutes());

  // OAuth/OIDC（公开）
  app.use(oauthRoutes(config));
  app.use(legacyOidcRoutes(config));

  // 首次初始化（未初始化时也可访问）
  app.use(setupRoutes(config));

  // Web 登录、TOTP、Passkey
  app.use(sessionRoutes(config));

  // 管理台 API（Origin + 认证 guard 在路由内）
  app.use(adminRoutes(config));

  // 页面路由
  app.use(pageRoutes());

  // 静态资源兜底；/admin.html 直访也要求已认证会话
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (req.path === "/admin.html" && !req.session?.authenticated) return res.redirect("/login");
    next();
  });
  app.use(express.static(PUBLIC_DIR, { index: false }));

  // 404
  app.use((req: Request, res: Response) => {
    if (req.path.startsWith("/api/")) return res.status(404).json({ error: "not_found" });
    res.status(404).type("html").send(errorPage("页面不存在", "请求的资源不存在。"));
  });

  // 统一错误处理器：不向客户端返回堆栈和密钥
  app.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
    console.error(
      JSON.stringify({
        level: "error",
        requestId: req.id,
        method: req.method,
        path: req.path,
        message: err instanceof Error ? err.message : String(err),
      })
    );
    if (res.headersSent) return;
    if (req.path.startsWith("/api/") || req.path.startsWith("/oauth/") || req.path.startsWith("/auth/")) {
      return res.status(500).json({ error: "server_error" });
    }
    res.status(500).type("html").send(errorPage("服务错误", "服务器处理请求时发生错误，请稍后重试。"));
  });

  return app;
}

