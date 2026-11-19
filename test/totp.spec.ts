import { Secret, TOTP } from "otpauth";
import { beforeEach, describe, expect, it } from "vitest";
import { api, ORIGIN, TEST_PASSWORD, authenticatedCookie, ensureProfile } from "./helpers";
import { truncateAll } from "../src/db/migrate";
import { generateTotpSecret, verifyTotp } from "../src/security/totp";
import { query } from "../src/db/pool";
import { clearFailures } from "../src/db/repositories/rateLimitRepository";

function gen(secretB32: string, offsetMs = 0): string {
  return new TOTP({
    issuer: "uni-auth",
    label: "admin",
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    secret: Secret.fromBase32(secretB32),
  }).generate({ timestamp: Date.now() + offsetMs });
}

function post(path: string, body: unknown, cookie?: string) {
  const req = api.post(path).set("content-type", "application/json").set("origin", ORIGIN).send(body as object);
  return cookie ? req.set("cookie", cookie) : req;
}

beforeEach(async () => {
  await truncateAll();
  await ensureProfile();
  await clearFailures("127.0.0.1");
});

describe("totp primitives", () => {
  it("accepts ±1 window, rejects farther or malformed", () => {
    const secret = generateTotpSecret();
    expect(verifyTotp(secret, gen(secret))).toBe(true);
    expect(verifyTotp(secret, gen(secret, -30_000))).toBe(true);
    expect(verifyTotp(secret, gen(secret, 30_000))).toBe(true);
    expect(verifyTotp(secret, gen(secret, -90_000))).toBe(false);
    expect(verifyTotp(secret, "12345")).toBe(false);
    expect(verifyTotp(secret, "abcdef")).toBe(false);
  });
});

describe("totp enrollment", () => {
  it("begin stores encrypted unconfirmed secret; confirm requires valid code", async () => {
    const cookie = await authenticatedCookie();
    const begin = await post("/api/v1/admin/totp/enroll", {}, cookie);
    expect(begin.status).toBe(200);
    const { uri, secret, svg } = begin.body;
    expect(uri).toMatch(/^otpauth:\/\/totp\//);
    expect(svg).toContain("<svg");

    const { rows } = await query<{ secret_encrypted: string; confirmed: boolean }>(
      "SELECT secret_encrypted, confirmed FROM totp_credentials WHERE id = 'totp'"
    );
    expect(rows[0].confirmed).toBe(false);
    expect(rows[0].secret_encrypted).not.toContain(secret);

    expect((await post("/api/v1/admin/totp/confirm", { code: "000000" }, cookie)).status).toBe(401);
    expect((await post("/api/v1/admin/totp/confirm", { code: gen(secret) }, cookie)).status).toBe(200);

    const after = await query<{ confirmed: boolean }>("SELECT confirmed FROM totp_credentials WHERE id = 'totp'");
    expect(after.rows[0].confirmed).toBe(true);
  });

  it("requires authenticated session", async () => {
    for (const [method, path] of [
      ["post", "/api/v1/admin/totp/enroll"],
      ["post", "/api/v1/admin/totp/confirm"],
      ["delete", "/api/v1/admin/totp"],
    ] as const) {
      const req = api[method](path).set("origin", ORIGIN);
      const res = await (method === "delete" ? req : req.set("content-type", "application/json").send({}));
      expect(res.status, path).toBe(401);
    }
  });
});

describe("totp login", () => {
  it("enforces TOTP after password step", async () => {
    const cookie = await authenticatedCookie();
    const begin = await post("/api/v1/admin/totp/enroll", {}, cookie);
    const { secret } = begin.body;
    expect((await post("/api/v1/admin/totp/confirm", { code: gen(secret) }, cookie)).status).toBe(200);
    await clearFailures("127.0.0.1");

    // 无 password_ok 会话 → 401
    const noSess = await post("/api/v1/session/totp", { code: gen(secret) });
    expect(noSess.status).toBe(401);

    // 密码步骤 → requires_totp
    const pw = await post("/api/v1/session/password", { password: TEST_PASSWORD });
    expect(pw.status).toBe(200);
    expect(pw.body).toEqual({ requires_totp: true });
    const sid = (pw.headers["set-cookie"]?.[0] ?? "").split(";")[0];

    expect((await post("/api/v1/session/totp", { code: "000000" }, sid)).status).toBe(401);

    const ok = await post("/api/v1/session/totp", { code: gen(secret) }, sid);
    expect(ok.status).toBe(200);
    expect(ok.body).toEqual({ ok: true });

    // 认证完成时轮换 sid（防 session fixation）：旧 sid 失效，使用新 Cookie
    const newSid = (ok.headers["set-cookie"]?.[0] ?? "").split(";")[0];
    expect(newSid).not.toBe(sid);
    expect(newSid).toContain("uni_auth_sid=");

    expect((await api.get("/admin").set("cookie", sid).redirects(0)).status).toBe(302);
    const admin = await api.get("/admin").set("cookie", newSid).redirects(0);
    expect(admin.status).toBe(200);
    await clearFailures("127.0.0.1");
  });

  it("disable removes TOTP enforcement", async () => {
    const cookie = await authenticatedCookie();
    const begin = await post("/api/v1/admin/totp/enroll", {}, cookie);
    const { secret } = begin.body;
    await post("/api/v1/admin/totp/confirm", { code: gen(secret) }, cookie);
    expect((await api.delete("/api/v1/admin/totp").set("origin", ORIGIN).set("cookie", cookie)).status).toBe(200);
    await clearFailures("127.0.0.1");

    const pw = await post("/api/v1/session/password", { password: TEST_PASSWORD });
    expect(pw.body).toEqual({ ok: true });
  });
});




