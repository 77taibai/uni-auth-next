import { beforeEach, describe, expect, it } from "vitest";
import { api, ORIGIN, ensureProfile, CLIENT_COOKIE } from "./helpers.js";
import { truncateAll } from "../src/db/migrate.js";
import { getProfile } from "../src/db/repositories/profileRepository.js";
import { query } from "../src/db/pool.js";
import { createAuthRequest } from "../src/db/repositories/authRequestRepository.js";
import { createClient } from "../src/db/repositories/clientRepository.js";

const CB = "https://app.example.com/cb";

beforeEach(async () => {
  await truncateAll();
  await ensureProfile();
  await createClient({ clientId: "setup-app", name: "setup-app", redirectUris: [CB], secret: null });
  await createAuthRequest({
    id: "pending-req",
    clientId: "setup-app",
    redirectUri: CB,
    scope: "openid",
    state: "st-1",
  });
});

describe("setup", () => {
  it("requires matching Origin", async () => {
    const evil = await api
      .post("/api/v1/setup")
      .set("content-type", "application/json")
      .set("origin", "https://evil.example")
      .send({ password: "correct horse" });
    expect(evil.status).toBe(403);
  });

  it("rejects weak password and creates nothing", async () => {
    await truncateAll();
    const res = await api
      .post("/api/v1/setup")
      .set("content-type", "application/json")
      .set("origin", ORIGIN)
      .send({ password: "short" });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("weak_password");
    const { rows } = await query<{ n: string }>("SELECT COUNT(*) AS n FROM admin_profile");
    expect(Number(rows[0].n)).toBe(0);
  });

  it("creates the profile, sets an authenticated cookie, and only works once", async () => {
    await truncateAll();
    const res = await api
      .post("/api/v1/setup")
      .set("content-type", "application/json")
      .set("origin", ORIGIN)
      .send({ password: "correct horse" });
    expect(res.status).toBe(200);

    const cookie = res.headers["set-cookie"]?.[0] ?? "";
    expect(cookie).toContain(`${CLIENT_COOKIE}=`);
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("SameSite=Lax");

    // 资料落库，密码以哈希存储
    const profile = await getProfile();
    expect(profile).toMatchObject({ subject: "me", display_name: "管理员", email: null });
    expect(profile!.password_hash).toMatch(/^pbkdf2\$sha256\$/);
    expect(profile!.password_hash).not.toContain("correct horse");

    // 已初始化后可访问 /admin
    const sid = cookie.split(";")[0];
    expect((await api.get("/admin").set("cookie", sid).redirects(0)).status).toBe(200);

    const again = await api
      .post("/api/v1/setup")
      .set("content-type", "application/json")
      .set("origin", ORIGIN)
      .send({ password: "another pass" });
    expect(again.status).toBe(403);
    expect(again.body.error).toBe("already_setup");
  });

  it("GET /setup serves the form, then redirects to /login after initialization", async () => {
    await truncateAll();
    const before = await api.get("/setup").redirects(0);
    expect(before.status).toBe(200);
    expect(before.text).toContain("初始化");

    await ensureProfile();

    const after = await api.get("/setup").redirects(0);
    expect(after.status).toBe(302);
    expect(after.headers.location).toBe("/login");
  });

  it("GET /login redirects to /setup before initialization", async () => {
    await truncateAll();
    const res = await api.get("/login").redirects(0);
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe("/setup");
  });

  it("keeps the pending authorization request id across setup", async () => {
    await truncateAll();
    await createClient({ clientId: "setup-app", name: "setup-app", redirectUris: [CB], secret: null });
    await createAuthRequest({
      id: "pending-req",
      clientId: "setup-app",
      redirectUri: CB,
      scope: "openid",
      state: "st-1",
    });
    const res = await api.get("/login?req=pending-req").redirects(0);
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe("/setup?req=pending-req");
  });

  it("rejects a stale req with the expired page", async () => {
    await truncateAll();
    const res = await api.get("/login?req=stale").redirects(0);
    expect(res.status).toBe(400);
    expect(res.text).toContain("过期");
  });
});


