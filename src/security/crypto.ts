import crypto from "node:crypto";
import type { webcrypto } from "node:crypto";

type CryptoKey = webcrypto.CryptoKey;

const ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const encoder = new TextEncoder();

/** 随机 token（base64url，默认 32 字节） */
export function randomToken(bytes = 32): string {
  return toB64Url(crypto.randomBytes(bytes));
}

export function randomAlphanumeric(length: number, alphabet = ALPHANUMERIC): string {
  if (!Number.isInteger(length) || length < 0) throw new RangeError("length must be a non-negative integer");
  const limit = 256 - (256 % alphabet.length);
  const result: string[] = [];
  while (result.length < length) {
    for (const byte of crypto.randomBytes(length - result.length)) {
      if (byte < limit) result.push(alphabet[byte % alphabet.length]);
      if (result.length === length) break;
    }
  }
  return result.join("");
}

export function toB64Url(buf: Uint8Array): string {
  return Buffer.from(buf).toString("base64url");
}

export function fromB64Url(s: string): Uint8Array<ArrayBuffer> {
  const buf = Buffer.from(s, "base64url");
  return new Uint8Array(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)) as Uint8Array<ArrayBuffer>;
}

export function sha256(input: string | Uint8Array): string {
  return crypto.createHash("sha256").update(input).digest("base64url");
}

export async function sha256Async(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(input));
  return toB64Url(new Uint8Array(digest));
}

/** 存储格式: pbkdf2$sha256$<iter>$<salt_b64url>$<hash_b64url>（与旧系统兼容） */
export function hashPassword(password: string, iterations: number): string {
  const salt = crypto.randomBytes(16);
  const bits = crypto.pbkdf2Sync(password, salt, iterations, 32, "sha256");
  return `pbkdf2$sha256$${iterations}$${toB64Url(salt)}$${toB64Url(bits)}`;
}

export function verifyPassword(stored: string, password: string): boolean {
  const parts = stored.split("$");
  if (parts.length !== 5 || parts[0] !== "pbkdf2" || parts[1] !== "sha256") return false;
  const iterations = parseInt(parts[2], 10);
  if (!Number.isFinite(iterations) || iterations < 1) return false;
  const salt = fromB64Url(parts[3]);
  const expected = fromB64Url(parts[4]);
  const actual = new Uint8Array(crypto.pbkdf2Sync(password, salt, iterations, expected.length || 32, "sha256"));
  return timingSafeEqual(expected, actual);
}

export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

export function stringsEqual(a: string, b: string): boolean {
  return timingSafeEqual(encoder.encode(a), encoder.encode(b));
}

export function parseIterations(v: string | undefined): number {
  const n = parseInt(v ?? "", 10);
  return Number.isFinite(n) && n >= 1000 ? n : 100000;
}

export async function importMasterKey(masterKeyB64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", fromB64Url(masterKeyB64), "AES-GCM", false, ["encrypt", "decrypt"]);
}

/** AES-256-GCM 加密：输出 b64url(iv12 + ciphertext)，AAD 绑定上下文（如记录 id） */
export async function aesEncrypt(key: CryptoKey, plaintext: string, aad?: string): Promise<string> {
  const iv = crypto.randomBytes(12);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(gcmParams(iv, aad), key, encoder.encode(plaintext))
  );
  const combined = new Uint8Array(iv.length + ct.length);
  combined.set(iv);
  combined.set(ct, iv.length);
  return toB64Url(combined);
}

export async function aesDecrypt(key: CryptoKey, combined: string, aad?: string): Promise<string> {
  const data = fromB64Url(combined);
  const pt = await crypto.subtle.decrypt(gcmParams(data.slice(0, 12), aad), key, data.slice(12));
  return new TextDecoder().decode(pt);
}

function gcmParams(iv: Uint8Array, aad?: string) {
  return aad ? { name: "AES-GCM" as const, iv, additionalData: encoder.encode(aad) } : { name: "AES-GCM" as const, iv };
}
