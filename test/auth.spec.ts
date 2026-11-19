import { beforeEach, describe, expect, it } from "vitest";
import { api, ORIGIN, TEST_PASSWORD, ensureProfile } from "./helpers.js";
import { clearFailures } from "../src/db/repositories/rateLimitRepository.js";
import { truncateAll } from "../src/db/migrate.js";

beforeEach(async () => {
  await truncateAll();
  await ensureProfile();
});

describe("password login", () => {
  it("rejects POST without matching Origin", async () => {
    const evil = await api
      .post("/api/v1/session/password")
      .set("content-type", "application/json")
      .set("origin", "https://evil.example")
      .send({ password: TEST_PASSWORD });
    expect(evil.status).toBe(403);
    expect(evil.body.error).toBe("bad_origin");

    const noOrigin = await api
      .post("/api/v1/session/password")
      .set("content-type", "application/json")
      .send({ password: TEST_PASSWORD });
    expect(noOrigin.status).toBe(403);
  });

  it("wrong → 401, correct → ok with secure session cookie", async () => {
    await clearFailures("127.0.0.1");
    const bad = await api
      .post("/api/v1/session/password")
      .set("content-type", "application/json")
      .set("origin", ORIGIN)
      .send({ password: "wrong" });
    expect(bad.status).toBe(401);
    expect(bad.body.error).toBe("bad_password");

    const good = await api
      .post("/api/v1/session/password")
      .set("content-type", "application/json")
      .set("origin", ORIGIN)
      .send({ password: TEST_PASSWORD });
    expect(good.status).toBe(200);
    expect(good.body).toEqual({ ok: true });
    const cookie = good.headers["set-cookie"]?.[0] ?? "";
    expect(cookie).toContain("uni_auth_sid=");
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("SameSite=Lax");
  });

  it("persistent login sets a max-age cookie", async () => {
    const res = await api
      .post("/api/v1/session/password")
      .set("content-type", "application/json")
      .set("origin", ORIGIN)
      .send({ password: TEST_PASSWORD, remember: true });
    expect(res.status).toBe(200);
    const cookie = res.headers["set-cookie"]?.[0] ?? "";
    expect(cookie).toMatch(/Max-Age=/i);
  });

  it("locks IP after 5 consecutive failures, success clears", async () => {
    await clearFailures("127.0.0.1");
    for (let i = 0; i < 5; i++) {
      const r = await api
        .post("/api/v1/session/password")
        .set("content-type", "application/json")
        .set("origin", ORIGIN)
        .send({ password: "wrong" });
      expect(r.status).toBe(401);
    }
    const locked = await api
      .post("/api/v1/session/password")
      .set("content-type", "application/json")
      .set("origin", ORIGIN)
      .send({ password: TEST_PASSWORD });
    expect(locked.status).toBe(429);
    expect(locked.body.error).toBe("locked");
    await clearFailures("127.0.0.1");
  });

  it("logout clears the session", async () => {
    const login = await api
      .post("/api/v1/session/password")
      .set("content-type", "application/json")
      .set("origin", ORIGIN)
      .send({ password: TEST_PASSWORD });
    const cookie = (login.headers["set-cookie"]?.[0] ?? "").split(";")[0];

    const out = await api.delete("/api/v1/session").set("origin", ORIGIN).set("cookie", cookie);
    expect(out.status).toBe(200);

    const after = await api.get("/api/v1/admin/overview").set("cookie", cookie);
    expect(after.status).toBe(401);
  });
});


