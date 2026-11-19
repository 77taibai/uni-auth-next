import { describe, expect, it } from "vitest";
import {
  aesDecrypt,
  aesEncrypt,
  fromB64Url,
  hashPassword,
  importMasterKey,
  randomAlphanumeric,
  randomToken,
  timingSafeEqual,
  toB64Url,
  verifyPassword,
} from "../src/security/crypto";

describe("pbkdf2", () => {
  it("hash/verify roundtrip with versioned format", () => {
    const hash = hashPassword("correct horse", 1000);
    expect(hash).toMatch(/^pbkdf2\$sha256\$1000\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$/);
    expect(verifyPassword(hash, "correct horse")).toBe(true);
    expect(verifyPassword(hash, "wrong")).toBe(false);
  });

  it("verifies legacy-format hashes produced by the old system", () => {
    const legacy = "pbkdf2$sha256$1000$HncG_khIANQSrzHtdvx0lg$QE1y_SkOkhIOm2fp98gdY_Bqwda3OgUEJHhp_cHLFZI";
    expect(verifyPassword(legacy, "correct horse")).toBe(true);
    expect(verifyPassword(legacy, "wrong")).toBe(false);
  });

  it("same password yields different hashes (random salt)", () => {
    expect(hashPassword("same", 1000)).not.toBe(hashPassword("same", 1000));
  });

  it("malformed stored hash fails closed", () => {
    expect(verifyPassword("garbage", "x")).toBe(false);
    expect(verifyPassword("argon2$unknown$1$aa$bb", "x")).toBe(false);
  });
});

describe("aes-gcm", () => {
  it("encrypt/decrypt roundtrip bound to aad", async () => {
    const key = await importMasterKey(randomToken(32));
    const ct = await aesEncrypt(key, "totp-secret", "totp:row-1");
    expect(await aesDecrypt(key, ct, "totp:row-1")).toBe("totp-secret");
    await expect(aesDecrypt(key, ct, "totp:row-2")).rejects.toThrow();
  });
});

describe("base64url / tokens", () => {
  it("b64url roundtrip preserves bytes", () => {
    const bytes = new Uint8Array(64).map((_, i) => i * 3);
    expect(fromB64Url(toB64Url(bytes))).toEqual(bytes);
  });

  it("randomToken is unique and 43 chars", () => {
    expect(randomToken()).not.toBe(randomToken());
    expect(randomToken()).toHaveLength(43);
  });

  it("randomAlphanumeric uses a fixed alphanumeric format", () => {
    const value = randomAlphanumeric(11);
    expect(value).toHaveLength(11);
    expect(value).toMatch(/^[A-Za-z0-9]+$/);
    expect(randomAlphanumeric(11)).not.toBe(value);
  });
});

describe("timingSafeEqual", () => {
  it("matches only identical buffers", () => {
    const a = fromB64Url("AAAAAAAAAAA");
    expect(timingSafeEqual(a, a)).toBe(true);
    expect(timingSafeEqual(a, fromB64Url("AAAAAAAABA"))).toBe(false);
    expect(timingSafeEqual(a, fromB64Url("AAAA"))).toBe(false);
  });
});
