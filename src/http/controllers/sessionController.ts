import { wrapHandlers } from "../middleware/async.js";
import type { Request, RequestHandler, Response } from "express";
import type { AppConfig } from "../../config/env.js";
import type { LoginSession } from "../../services/sessionService.js";
import { parseBody, passwordLoginSchema, totpLoginSchema, passkeyVerifySchema } from "../validators/schemas.js";
import { clearSessionCookie, setSessionCookie } from "../middleware/cookies.js";
import {
  completeTotpLogin,
  loginWithPassword,
} from "../../services/authService.js";
import {
  authenticationOptions,
  loginWithPasskey,
} from "../../services/webauthnService.js";
import { destroySession, findSession } from "../../services/sessionService.js";
import { SESSION_COOKIE } from "../../services/sessionService.js";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";

export function sessionController(config: AppConfig){
  return wrapHandlers({
    password: async (req: Request, res: Response) => {
      const body = parseBody(passwordLoginSchema, req.body);
      if (!body) return res.status(400).json({ error: "bad_request" });
      try {
        const outcome = await loginWithPassword(
          config,
          req.clientIp ?? "local",
          body.password,
          body.remember,
          req.session ?? null
        );
        if (outcome.kind === "failed") return res.status(outcome.status).json({ error: outcome.error });
        setSessionCookie(config, res, outcome.session.sid, body.remember);
        if (outcome.kind === "totp_required") return res.json({ requires_totp: true });
        return res.json({ ok: true });
      } catch (err) {
        return res.status(500).json({ error: "server_error" });
      }
    },

    totp: async (req: Request, res: Response) => {
      const body = parseBody(totpLoginSchema, req.body);
      if (!body) return res.status(400).json({ error: "bad_request" });
      const outcome = await completeTotpLogin(config, req.clientIp ?? "local", body.code, req.session ?? null);
      if (outcome.kind === "failed") return res.status(outcome.status).json({ error: outcome.error });
      const persistent = outcome.session.persistent;
      setSessionCookie(config, res, outcome.session.sid, persistent);
      return res.json({ ok: true });
    },

    passkeyOptions: async (_req: Request, res: Response) => {
      const result = await authenticationOptions(config);
      if ("error" in result) return res.status(400).json({ error: result.error });
      return res.json(result);
    },

    passkeyVerify: async (req: Request, res: Response) => {
      const body = parseBody(passkeyVerifySchema, req.body);
      if (!body) return res.status(400).json({ error: "bad_request" });
      const outcome = await loginWithPasskey(
        config,
        req.clientIp ?? "local",
        {
          challengeId: body.challengeId,
          remember: body.remember,
          response: body.response as unknown as AuthenticationResponseJSON,
        },
        req.session ?? null
      );
      if (outcome.kind === "failed") return res.status(outcome.status).json({ error: outcome.error });
      setSessionCookie(config, res, outcome.session.sid, body.remember);
      return res.json({ ok: true });
    },

    logout: async (req: Request, res: Response) => {
      const sid = req.cookies?.[SESSION_COOKIE];
      const session: LoginSession | null = req.session ?? (sid ? await findSession(sid) : null);
      if (session) await destroySession(session);
      clearSessionCookie(res);
      return res.json({ ok: true });
    },
  });
}


