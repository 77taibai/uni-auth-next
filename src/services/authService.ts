import { displayNameOf, type Identity } from "../config/identity.js";
import { getConfirmedTotp } from "../db/repositories/totpRepository.js";
import { getProfile } from "../db/repositories/profileRepository.js";
import { verifyPassword } from "../security/crypto.js";
import { decryptTotpSecret } from "../security/encryption.js";
import { verifyTotp } from "../security/totp.js";
import { clearFailures, isLocked, recordFailure } from "../db/repositories/rateLimitRepository.js";
import type { AppConfig } from "../config/env.js";
import {
  markAuthenticated,
  markPasswordOk,
  setPersistence,
  startSession,
  type LoginSession,
} from "./sessionService.js";

export type LoginOutcome =
  | { kind: "failed"; error: "locked"; status: 429 }
  | { kind: "failed"; error: "not_setup"; status: 400 }
  | { kind: "failed"; error: "bad_password"; status: 401 }
  | { kind: "totp_required"; session: LoginSession }
  | { kind: "ok"; session: LoginSession };

/** 从数据库读取身份资料（单行） */
export async function loadIdentity(): Promise<Identity | null> {
  const row = await getProfile();
  if (!row) return null;
  return {
    subject: row.subject,
    displayName: row.display_name,
    email: row.email,
    passwordHash: row.password_hash,
  };
}

/**
 * 密码登录：限速 → 读取数据库资料 → 校验 → 可选 TOTP 二步。
 * 已启用 TOTP 时只写入 password_ok，不建立完整会话。
 */
export async function loginWithPassword(
  _config: AppConfig,
  ip: string,
  password: unknown,
  remember: boolean,
  existing: LoginSession | null
): Promise<LoginOutcome> {
  if (await isLocked(ip)) return { kind: "failed", error: "locked", status: 429 };

  const identity = await loadIdentity();
  if (!identity) return { kind: "failed", error: "not_setup", status: 400 };

  const ok = typeof password === "string" && verifyPassword(identity.passwordHash, password);
  if (!ok) {
    await recordFailure(ip);
    return { kind: "failed", error: "bad_password", status: 401 };
  }
  await clearFailures(ip);

  const session = existing ?? (await startSession(remember));
  if (existing) await setPersistence(existing, remember);

  if (await getConfirmedTotp()) {
    await markPasswordOk(session);
    return { kind: "totp_required", session };
  }

  // 无 TOTP：直接完成认证（sid 轮换，避免 session fixation）
  const signedIn = await markAuthenticated(session);
  await setPersistence(signedIn, remember);
  return { kind: "ok", session: signedIn };
}

export type TotpOutcome =
  | { kind: "failed"; error: "locked"; status: 429 }
  | { kind: "failed"; error: "unauthorized"; status: 401 }
  | { kind: "failed"; error: "not_configured"; status: 400 }
  | { kind: "failed"; error: "bad_totp"; status: 401 }
  | { kind: "ok"; session: LoginSession };

/** TOTP 第二步：需要 password_ok 标记；校验限速与验证码 */
export async function completeTotpLogin(
  config: AppConfig,
  ip: string,
  code: unknown,
  session: LoginSession | null
): Promise<TotpOutcome> {
  if (await isLocked(ip)) return { kind: "failed", error: "locked", status: 429 };
  if (!session?.password_ok) return { kind: "failed", error: "unauthorized", status: 401 };

  const row = await getConfirmedTotp();
  if (!row) return { kind: "failed", error: "not_configured", status: 400 };

  const secret = await decryptTotpSecret(config.masterKey, row.secret_encrypted);
  if (typeof code !== "string" || !verifyTotp(secret, code.trim())) {
    await recordFailure(ip);
    return { kind: "failed", error: "bad_totp", status: 401 };
  }

  await clearFailures(ip);
  const signedIn = await markAuthenticated(session);
  return { kind: "ok", session: signedIn };
}

/** 管理台/overview 的身份摘要 */
export function identitySummary(identity: Identity) {
  return {
    subject: identity.subject,
    display_name: displayNameOf(identity),
    email: identity.email,
  };
}
