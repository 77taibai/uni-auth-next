import { renderSVG } from "uqr";
import type { AppConfig } from "../config/env";
import {
  confirmTotp,
  deleteTotp,
  getTotp,
  upsertPendingTotp,
} from "../db/repositories/totpRepository";
import { decryptTotpSecret, encryptTotpSecret } from "../security/encryption";
import { generateTotpSecret, totpUri, verifyTotp } from "../security/totp";

export type EnrollResult = { uri: string; secret: string; svg: string };

/** 生成新密钥并以未确认状态落库 */
export async function beginEnrollment(config: AppConfig): Promise<EnrollResult> {
  const secret = generateTotpSecret();
  await upsertPendingTotp(await encryptTotpSecret(config.masterKey, secret));
  const uri = totpUri(secret);
  return { uri, secret, svg: renderSVG(uri) };
}

export async function confirmEnrollment(config: AppConfig, code: unknown): Promise<"ok" | "not_begun" | "bad_totp"> {
  const row = await getTotp();
  if (!row) return "not_begun";
  const secret = await decryptTotpSecret(config.masterKey, row.secret_encrypted);
  if (typeof code !== "string" || !verifyTotp(secret, code.trim())) return "bad_totp";
  await confirmTotp();
  return "ok";
}

export async function disable(): Promise<void> {
  await deleteTotp();
}

export async function isEnabled(): Promise<boolean> {
  return (await getTotp())?.confirmed === true;
}
