import type { Request, RequestHandler, Response } from "express";
import type { AppConfig } from "../../config/env";
import { renderView } from "../../config/paths";
import { isInitialized, setup } from "../../services/setupService";
import { markAuthenticated, startSession } from "../../services/sessionService";
import { setSessionCookie } from "../middleware/cookies";
import { parseBody, setupSchema } from "../validators/schemas";
import { wrapHandlers } from "../middleware/async";

export function setupController(config: AppConfig) {
  return wrapHandlers({
    /** GET /setup：已初始化则跳 /login，否则提供初始化页面 */
    page: async (req: Request, res: Response) => {
      const reqId = typeof req.query.req === "string" ? req.query.req : undefined;
      if (await isInitialized()) {
        return res.redirect(withReq("/login", reqId));
      }
      return res.type("html").send(renderView("setup"));
    },

    /** POST /api/v1/setup：只允许创建一次 */
    create: async (req: Request, res: Response) => {
      const body = parseBody(setupSchema, req.body);
      if (!body) return res.status(400).json({ error: "weak_password" });

      const outcome = await setup(config, body.password);
      if (outcome.kind === "already_setup") return res.status(403).json({ error: "already_setup" });
      if (outcome.kind === "weak_password") return res.status(400).json({ error: "weak_password" });

      const session = await startSession(false);
      const signedIn = await markAuthenticated(session);
      setSessionCookie(config, res, signedIn.sid, false);
      return res.json({ ok: true });
    },
  });
}

function withReq(path: string, req: string | undefined): string {
  return req ? `${path}?req=${encodeURIComponent(req)}` : path;
}
