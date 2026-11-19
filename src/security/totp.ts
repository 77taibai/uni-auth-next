import { Secret, TOTP } from "otpauth";

export function generateTotpSecret(): string {
  return new Secret({ size: 20 }).base32;
}

function totpClient(secretB32: string): TOTP {
  return new TOTP({
    issuer: "uni-auth",
    label: "admin",
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    secret: Secret.fromBase32(secretB32),
  });
}

export function totpUri(secretB32: string): string {
  return totpClient(secretB32).toString();
}

/** 校验当前 ±1 个 30s 窗口内的验证码 */
export function verifyTotp(secretB32: string, token: string): boolean {
  return /^\d{6}$/.test(token) && totpClient(secretB32).validate({ token, window: 1 }) !== null;
}
