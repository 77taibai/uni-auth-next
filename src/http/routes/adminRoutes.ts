import { Router } from "express";
import type { AppConfig } from "../../config/env";
import { adminController } from "../controllers/adminController";
import { requireAuthApi, requireOrigin } from "../middleware/auth";

/** 管理台 API：Origin 校验 + 完全认证会话 guard（文档 6.2） */
export function adminRoutes(config: AppConfig): Router {
  const router = Router();
  const c = adminController(config);
  const origin = requireOrigin(config);
  const guard = requireAuthApi();

  router.get("/api/v1/admin/overview", guard, c.overview);

  router.post("/api/v1/admin/profile", origin, guard, c.profileUpdate);
  router.post("/api/v1/admin/password", origin, guard, c.passwordChange);

  router.post("/api/v1/admin/totp/enroll", origin, guard, c.totpEnroll);
  router.post("/api/v1/admin/totp/confirm", origin, guard, c.totpConfirm);
  router.delete("/api/v1/admin/totp", origin, guard, c.totpDisable);

  router.post("/api/v1/admin/passkeys/options", origin, guard, c.passkeyOptions);
  router.post("/api/v1/admin/passkeys", origin, guard, c.passkeyRegister);
  router.patch("/api/v1/admin/passkeys/:id", origin, guard, c.passkeyRename);
  router.delete("/api/v1/admin/passkeys/:id", origin, guard, c.passkeyDelete);

  router.post("/api/v1/admin/clients", origin, guard, c.clientCreate);
  router.patch("/api/v1/admin/clients/:id", origin, guard, c.clientUpdate);
  router.delete("/api/v1/admin/clients/:id", origin, guard, c.clientDelete);

  return router;
}
