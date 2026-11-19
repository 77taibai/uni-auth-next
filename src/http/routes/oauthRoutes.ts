import { Router } from "express";
import type { AppConfig } from "../../config/env";
import { oauthController } from "../controllers/oauthController";

/** 标准 OAuth/OIDC 根级路由（文档 6.3） */
export function oauthRoutes(config: AppConfig): Router {
  const router = Router();
  const c = oauthController(config);

  router.get("/.well-known/openid-configuration", c.discovery);
  router.get("/oauth/authorize", c.authorize);
  router.post("/oauth/token", c.token);
  router.get("/oauth/userinfo", c.userinfo);
  router.get("/oauth/jwks.json", c.jwks);
  router.get("/oauth/consent", c.consentPage);
  router.get("/oauth/consent/info", c.consentInfo);
  router.post("/oauth/consent/approve", c.consentApprove);
  router.post("/oauth/consent/deny", c.consentDeny);

  return router;
}

/**
 * 兼容 adapter：旧 /auth/* 与根级别名只转发到相同 controller，
 * 不复制业务逻辑。保留以便既有客户端继续工作。
 */
export function legacyOidcRoutes(config: AppConfig): Router {
  const router = Router();
  const c = oauthController(config);

  router.get("/auth", c.authRoot);
  router.get("/auth/.well-known/openid-configuration", c.discovery);
  router.get("/auth/jwks", c.jwks);
  router.get("/auth/authorize", c.authorize);
  router.post("/auth/token", c.token);
  router.get("/auth/userinfo", c.userinfo);
  router.get("/auth/confirm", c.consentPage);
  router.get("/auth/api/confirm/info", c.consentInfo);
  router.post("/auth/api/confirm", (req, res, next) => {
    // 旧接口用 action: confirm|cancel 合并在一个端点
    const action = (req.body as { action?: string })?.action;
    if (action === "cancel") { void c.consentDeny(req, res, next); return; }
    void c.consentApprove(req, res, next);
  });

  // 旧根级别名 308 到 /auth（保持既有集成方行为）
  const legacyRedirects: Array<[string, string]> = [
    ["/authorize", "/auth/authorize"],
    ["/token", "/auth/token"],
    ["/userinfo", "/auth/userinfo"],
    ["/jwks", "/auth/jwks"],
    ["/confirm", "/auth/confirm"],
    ["/api/confirm/info", "/auth/api/confirm/info"],
    ["/api/confirm", "/auth/api/confirm"],
  ];
  for (const [from, to] of legacyRedirects) {
    router.all(from, (req, res) => res.redirect(308, `${to}${requestSearch(req.url)}`));
  }

  return router;
}

function requestSearch(url: string): string {
  const idx = url.indexOf("?");
  return idx >= 0 ? url.slice(idx) : "";
}
