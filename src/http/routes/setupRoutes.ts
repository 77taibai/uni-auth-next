import { Router } from "express";
import type { AppConfig } from "../../config/env";
import { setupController } from "../controllers/setupController";
import { requireOrigin } from "../middleware/auth";

/** 首次初始化：/setup 页面与一次性创建 API */
export function setupRoutes(config: AppConfig): Router {
  const router = Router();
  const c = setupController(config);
  const origin = requireOrigin(config);

  router.get("/setup", c.page);
  router.post("/api/v1/setup", origin, c.create);

  return router;
}
