import { Router } from "express";
import { query } from "../../db/pool";

export function healthRoutes(): Router {
  const router = Router();
  router.get("/health", async (_req, res) => {
    try {
      await query("SELECT 1");
      res.json({ ok: true, name: "uni-auth" });
    } catch {
      res.status(503).json({ ok: false, name: "uni-auth" });
    }
  });
  return router;
}
