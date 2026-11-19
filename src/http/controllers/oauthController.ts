import type { Request, RequestHandler, Response } from "express";
import type { AppConfig } from "../../config/env.js";
import { renderView } from "../../config/paths.js";
import { authorize, consent, discoveryDocument, getAuthRequestInfo, issueTokens, userinfo } from "../../services/oauthService.js";
import { getSigningKey, publicJwks } from "../../security/jwt.js";
import { errorPage } from "../../views/pages.js";
import { tokenRequestSchema, consentSchema, parseBody } from "../validators/schemas.js";
import { wrapHandlers } from "../middleware/async.js";

const NO_STORE = { "Cache-Control": "no-store", Pragma: "no-cache" };

export function oauthController(config: AppConfig) {
  return wrapHandlers({
    discovery: (_req: Request, res: Response) => {
      res.json(discoveryDocument(config));
    },

    jwks: async (_req: Request, res: Response) => {
      res.json(publicJwks(await getSigningKey()));
    },

    authorize: async (req: Request, res: Response) => {
      const outcome = await authorize(config, req.query as Record<string, string | undefined>, !!req.session?.authenticated);
      if (outcome.kind === "page_error") {
        return res.status(400).type("html").send(errorPage("请求无效", outcome.message));
      }
      if (outcome.kind === "redirect_error") return res.redirect(302, outcome.location);
      if (outcome.kind === "login") return res.redirect(`/login?req=${encodeURIComponent(outcome.reqId)}`);
      return res.redirect(`/oauth/consent?req=${encodeURIComponent(outcome.reqId)}`);
    },

    token: async (req: Request, res: Response) => {
      const body = parseBody(tokenRequestSchema, req.body);
      if (!body) return res.status(400).set(NO_STORE).json({ error: "invalid_request" });
      if (body.grant_type !== "authorization_code") {
        return res.status(400).set(NO_STORE).json({ error: "unsupported_grant_type", error_description: "only authorization_code is supported" });
      }

      let clientId = body.client_id ?? "";
      let clientSecret = body.client_secret;
      const basic = /^Basic\s+(.+)$/i.exec(req.headers.authorization ?? "");
      if (basic) {
        try {
          const decoded = Buffer.from(basic[1], "base64").toString("utf8");
          const sep = decoded.indexOf(":");
          if (sep > 0) {
            clientId = decoded.slice(0, sep);
            clientSecret = decoded.slice(sep + 1);
          }
        } catch {
          /* fall back to form credentials */
        }
      }

      const result = await issueTokens(config, {
        clientId,
        clientSecret,
        code: body.code,
        redirectUri: body.redirect_uri,
        verifier: body.code_verifier,
      });
      return res.status(result.status).set(NO_STORE).json(result.body);
    },

    userinfo: async (req: Request, res: Response) => {
      const bearer = /^Bearer (.+)$/i.exec(req.headers.authorization ?? "")?.[1];
      const claims = await userinfo(bearer);
      if (!claims) return res.status(401).json({ error: "invalid_token" });
      return res.json(claims);
    },

    consentPage: async (req: Request, res: Response) => {
      const reqId = typeof req.query.req === "string" ? req.query.req : "";
      const info = reqId ? await getAuthRequestInfo(reqId) : null;
      if (!info) {
        return res.status(400).type("html").send(errorPage("链接已过期", "登录请求已过期或无效，请回到应用重新发起登录。"));
      }
      if (!req.session?.authenticated) return res.redirect(`/login?req=${encodeURIComponent(reqId)}`);
      return res.type("html").send(renderView("consent"));
    },

    consentInfo: async (req: Request, res: Response) => {
      if (!req.session?.authenticated) return res.status(401).json({ error: "unauthorized" });
      const reqId = typeof req.query.req === "string" ? req.query.req : "";
      const info = await getAuthRequestInfo(reqId);
      if (!info) return res.status(400).json({ error: "expired" });
      return res.json(info);
    },

    consentApprove: async (req: Request, res: Response) => {
      if (!req.session?.authenticated) return res.status(401).json({ error: "unauthorized" });
      const body = parseBody(consentSchema, req.body);
      if (!body) return res.status(400).json({ error: "bad_request" });
      const outcome = await consent(body.req, "confirm", req.session.auth_time);
      if (outcome.kind === "expired") return res.status(400).json({ error: "expired" });
      if (outcome.kind === "bad_action") return res.status(400).json({ error: "bad_request" });
      if (outcome.kind === "not_setup") return res.status(400).json({ error: "not_setup" });
      return res.json({ redirect: outcome.location });
    },

    consentDeny: async (req: Request, res: Response) => {
      if (!req.session?.authenticated) return res.status(401).json({ error: "unauthorized" });
      const body = parseBody(consentSchema, req.body);
      if (!body) return res.status(400).json({ error: "bad_request" });
      const outcome = await consent(body.req, "cancel", req.session.auth_time);
      if (outcome.kind === "expired") return res.status(400).json({ error: "expired" });
      if (outcome.kind === "bad_action") return res.status(400).json({ error: "bad_request" });
      if (outcome.kind === "not_setup") return res.status(400).json({ error: "not_setup" });
      return res.json({ redirect: outcome.location });
    },

    /** 旧根路径 /auth 重定向到 discovery */
    authRoot: (_req: Request, res: Response) => {
      res.redirect(308, "/auth/.well-known/openid-configuration");
    },
  });
}
