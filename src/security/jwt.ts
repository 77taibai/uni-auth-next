import { exportJWK, generateKeyPair, importJWK, type JWK, SignJWT } from "jose";
import { randomToken } from "./crypto.js";
import { getSigningKeyRow, insertSigningKey } from "../db/repositories/signingKeyRepository.js";

/**
 * ES256 签名密钥：首次使用时生成并持久化到 PostgreSQL（单行）。
 * 轮换策略（手动）：删除 oidc_signing_keys 中的行即重新生成，旧 id_token 失效。
 */
export type StoredKey = { kid: string; privateJwk: JWK; publicJwk: JWK };

export async function getSigningKey(): Promise<StoredKey> {
  const row = await getSigningKeyRow();
  if (row) return { kid: row.kid, privateJwk: row.private_jwk, publicJwk: row.public_jwk };

  const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
  const key: StoredKey = {
    kid: randomToken(8),
    privateJwk: await exportJWK(privateKey),
    publicJwk: await exportJWK(publicKey),
  };
  await insertSigningKey(key);
  // 并发冷启动时可能已被其他实例插入，重新读一次以取唯一行
  const stored = await getSigningKeyRow();
  return stored ? { kid: stored.kid, privateJwk: stored.private_jwk, publicJwk: stored.public_jwk } : key;
}

export function publicJwks(key: StoredKey) {
  return { keys: [{ ...key.publicJwk, kid: key.kid, alg: "ES256", use: "sig" }] };
}

export type IdTokenInput = {
  iss: string;
  sub: string;
  aud: string;
  email?: string;
  nonce?: string;
  authTime: number;
  /** 默认 300 秒（5 分钟短时效） */
  ttlSeconds?: number;
};

export async function signIdToken(input: IdTokenInput): Promise<string> {
  const key = await getSigningKey();
  const privateKey = await importJWK(key.privateJwk, "ES256");
  const now = Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = { auth_time: input.authTime };
  if (input.email) payload.email = input.email;
  if (input.nonce) payload.nonce = input.nonce;
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "ES256", kid: key.kid })
    .setIssuer(input.iss)
    .setSubject(input.sub)
    .setAudience(input.aud)
    .setIssuedAt(now)
    .setExpirationTime(now + (input.ttlSeconds ?? 300))
    .sign(privateKey);
}
