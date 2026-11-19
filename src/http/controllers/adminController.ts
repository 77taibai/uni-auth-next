import { wrapHandlers } from "../middleware/async.js";
import type { Request, RequestHandler, Response } from "express";
import type { AppConfig } from "../../config/env.js";
import { displayNameOf } from "../../config/identity.js";
import { listPasskeys, renamePasskey, deletePasskey, getPasskeyById } from "../../db/repositories/passkeyRepository.js";
import { listClients, getClientById, createClient, updateClientName, updateClientRedirectUris, deleteClient } from "../../db/repositories/clientRepository.js";
import { getProfile, updateProfile, updatePasswordHash } from "../../db/repositories/profileRepository.js";
import { randomAlphanumeric, hashPassword, verifyPassword } from "../../security/crypto.js";
import { beginEnrollment, confirmEnrollment, disable, isEnabled as totpEnabled } from "../../services/totpService.js";
import { registrationOptions, registerPasskey } from "../../services/webauthnService.js";
import { destroySession } from "../../services/sessionService.js";
import { clearSessionCookie } from "../middleware/cookies.js";
import {
  parseBody,
  clientCreateSchema,
  clientUpdateSchema,
  totpConfirmSchema,
  passkeyRegisterSchema,
  passkeyRenameSchema,
  profileUpdateSchema,
  passwordChangeSchema,
} from "../validators/schemas.js";
import type { RegistrationResponseJSON } from "@simplewebauthn/server";

export function adminController(config: AppConfig){
  return wrapHandlers({
    /** 身份资料摘要 + TOTP 状态 + Passkey 列表 + client 列表 */
    overview: async (_req: Request, res: Response) => {
      const [passkeys, clients, totpOn, profile] = await Promise.all([
        listPasskeys(),
        listClients(),
        totpEnabled(),
        getProfile(),
      ]);
      if (!profile) return res.status(400).json({ error: "not_setup" });

      res.json({
        identity: {
          subject: profile.subject,
          display_name: displayNameOf({ displayName: profile.display_name }),
          email: profile.email,
          password_configured: true,
        },
        totp_enabled: totpOn,
        passkeys: passkeys.map((p) => ({
          id: p.id,
          name: p.name,
          created_at: p.created_at,
          last_used_at: p.last_used_at,
        })),
        clients: clients.map((c) => ({
          id: c.id,
          client_id: c.client_id,
          name: c.name,
          redirect_uris: c.redirect_uris,
          has_secret: !!c.client_secret,
        })),
        oidc: {
          issuer: `${config.publicOrigin}/auth`,
          discovery: `${config.publicOrigin}/.well-known/openid-configuration`,
          authorize: `${config.publicOrigin}/oauth/authorize`,
          token: `${config.publicOrigin}/oauth/token`,
          userinfo: `${config.publicOrigin}/oauth/userinfo`,
          jwks: `${config.publicOrigin}/oauth/jwks.json`,
        },
      });
    },

    /** 修改显示名与邮箱 */
    profileUpdate: async (req: Request, res: Response) => {
      const body = parseBody(profileUpdateSchema, req.body);
      if (!body) return res.status(400).json({ error: "bad_request" });
      const ok = await updateProfile({ displayName: body.display_name, email: body.email || null });
      return ok ? res.json({ ok: true }) : res.status(400).json({ error: "not_setup" });
    },

    /** 修改密码：校验旧密码，成功后作废当前会话 */
    passwordChange: async (req: Request, res: Response) => {
      const body = parseBody(passwordChangeSchema, req.body);
      if (!body) return res.status(400).json({ error: "weak_password" });

      const profile = await getProfile();
      if (!profile) return res.status(400).json({ error: "not_setup" });
      if (!verifyPassword(profile.password_hash, body.old_password)) {
        return res.status(401).json({ error: "bad_password" });
      }
      await updatePasswordHash(hashPassword(body.new_password, config.pbkdf2Iterations));
      if (req.session) await destroySession(req.session);
      clearSessionCookie(res);
      return res.json({ ok: true });
    },

    totpEnroll: async (_req: Request, res: Response) => {
      res.json(await beginEnrollment(config));
    },

    totpConfirm: async (req: Request, res: Response) => {
      const body = parseBody(totpConfirmSchema, req.body);
      if (!body) return res.status(400).json({ error: "bad_request" });
      const outcome = await confirmEnrollment(config, body.code);
      if (outcome === "not_begun") return res.status(400).json({ error: "not_begun" });
      if (outcome === "bad_totp") return res.status(401).json({ error: "bad_totp" });
      return res.json({ ok: true });
    },

    totpDisable: async (_req: Request, res: Response) => {
      await disable();
      res.json({ ok: true });
    },

    passkeyOptions: async (_req: Request, res: Response) => {
      res.json(await registrationOptions(config));
    },

    passkeyRegister: async (req: Request, res: Response) => {
      const body = parseBody(passkeyRegisterSchema, req.body);
      if (!body) return res.status(400).json({ error: "bad_request" });
      const outcome = await registerPasskey(config, {
        challengeId: body.challengeId,
        name: body.name,
        response: body.response as unknown as RegistrationResponseJSON,
      });
      if ("error" in outcome) {
        const status = outcome.error === "bad_challenge" || outcome.error === "bad_request" ? 400 : 401;
        return res.status(status).json({ error: outcome.error });
      }
      return res.json({ ok: true });
    },

    passkeyRename: async (req: Request, res: Response) => {
      const body = parseBody(passkeyRenameSchema, req.body);
      if (!body) return res.status(400).json({ error: "bad_request" });
      const ok = await renamePasskey(req.params.id, body.name.trim());
      return ok ? res.json({ ok: true }) : res.status(404).json({ error: "not_found" });
    },

    passkeyDelete: async (req: Request, res: Response) => {
      if (!(await getPasskeyById(req.params.id))) return res.status(404).json({ error: "not_found" });
      await deletePasskey(req.params.id);
      return res.json({ ok: true });
    },

    clientCreate: async (req: Request, res: Response) => {
      const body = parseBody(clientCreateSchema, req.body);
      if (!body) return res.status(400).json({ error: "bad_request" });
      const clientId = `cli_${randomAlphanumeric(11)}`;
      await createClient({
        clientId,
        name: body.name.trim(),
        redirectUris: body.redirect_uris,
        secret: body.client_secret?.trim() || null,
      });
      return res.json({ ok: true, client_id: clientId });
    },

    clientUpdate: async (req: Request, res: Response) => {
      const body = parseBody(clientUpdateSchema, req.body);
      if (!body) return res.status(400).json({ error: "bad_request" });
      if (!(await getClientById(req.params.id))) return res.status(404).json({ error: "not_found" });
      if (body.name !== undefined) await updateClientName(req.params.id, body.name.trim());
      if (body.redirect_uris !== undefined) await updateClientRedirectUris(req.params.id, body.redirect_uris);
      return res.json({ ok: true });
    },

    clientDelete: async (req: Request, res: Response) => {
      if (!(await getClientById(req.params.id))) return res.status(404).json({ error: "not_found" });
      await deleteClient(req.params.id);
      return res.json({ ok: true });
    },
  });
}


