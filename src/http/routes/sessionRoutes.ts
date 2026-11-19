import { Router } from "express";
import type { AppConfig } from "../../config/env";
import { sessionController } from "../controllers/sessionController";
import { requireAuthApi, requireOrigin } from "../middleware/auth";

/** Web 登录 / TOTP / Passkey 会话路由（文档 6.2） */
export function sessionRoutes(config: AppConfig): Router {
  const router = Router();
  const c = sessionController(config);
  const origin = requireOrigin(config);

  router.post("/api/v1/session/password", origin, c.password);
  router.post("/api/v1/session/totp", origin, c.totp);
  router.post("/api/v1/session/passkey/options", origin, c.passkeyOptions);
  router.post("/api/v1/session/passkey/verify", origin, c.passkeyVerify);
  router.delete("/api/v1/session", origin, c.logout);

  return router;
}
