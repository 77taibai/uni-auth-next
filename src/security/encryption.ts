import type { webcrypto } from "node:crypto";
import { aesDecrypt, aesEncrypt, importMasterKey } from "./crypto.js";

type CryptoKey = webcrypto.CryptoKey;

const TOTP_ID = "totp";
let cachedKey: Promise<CryptoKey> | null = null;
let cachedMasterKeyValue: string | null = null;

/** MASTER_KEY 来自配置；按进程缓存派生密钥，避免每请求重复导入 */
async function masterKey(masterKeyB64: string): Promise<CryptoKey> {
  if (!cachedKey || cachedMasterKeyValue !== masterKeyB64) {
    cachedMasterKeyValue = masterKeyB64;
    cachedKey = importMasterKey(masterKeyB64);
  }
  return cachedKey;
}

/** 密钥以 AES-256-GCM 加密存储，AAD 绑定记录 id 防挪用（与旧系统保持一致） */
export async function encryptTotpSecret(masterKeyB64: string, secretB32: string): Promise<string> {
  return aesEncrypt(await masterKey(masterKeyB64), secretB32, `totp:${TOTP_ID}`);
}

export async function decryptTotpSecret(masterKeyB64: string, encrypted: string): Promise<string> {
  return aesDecrypt(await masterKey(masterKeyB64), encrypted, `totp:${TOTP_ID}`);
}

export function resetMasterKeyCache(): void {
  cachedKey = null;
  cachedMasterKeyValue = null;
}
