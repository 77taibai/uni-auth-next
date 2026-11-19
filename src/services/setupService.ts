import type { AppConfig } from "../config/env.js";
import { createProfile, getProfile } from "../db/repositories/profileRepository.js";
import { hashPassword } from "../security/crypto.js";

export const MIN_PASSWORD_LENGTH = 8;

export async function isInitialized(): Promise<boolean> {
  return (await getProfile()) !== null;
}

export type SetupOutcome =
  | { kind: "ok" }
  | { kind: "already_setup" }
  | { kind: "weak_password" };

/**
 * 首次初始化：只允许创建一次，密码至少 8 位。
 * 身份资料写入数据库 admin_profile，成功后由调用方建立已认证会话。
 */
export async function setup(config: AppConfig, password: unknown): Promise<SetupOutcome> {
  if (typeof password !== "string" || password.length < MIN_PASSWORD_LENGTH) {
    return { kind: "weak_password" };
  }
  const created = await createProfile({
    // subject 保持旧系统的固定取值，保证既有 OIDC sub 不变
    subject: "me",
    displayName: "管理员",
    email: null,
    passwordHash: hashPassword(password, config.pbkdf2Iterations),
  });
  return created ? { kind: "ok" } : { kind: "already_setup" };
}
