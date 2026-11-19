import { Router } from "express";
import type { AppConfig } from "../../config/env";
import { pageController } from "../controllers/pageController";
import { requireAuthPage } from "../middleware/auth";

/** 页面路由（文档 6.1） */
export function pageRoutes(): Router {
  const router = Router();
  const c = pageController();

  router.get("/", c.root);
  router.get("/login", c.loginPage);
  router.get("/admin", requireAuthPage(), c.adminPage);

  return router;
}
