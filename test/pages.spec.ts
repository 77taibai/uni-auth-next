import { describe, expect, it } from "vitest";
import { api } from "./helpers.js";

describe("pages", () => {
  it("GET / for non-HTML client 308 → /auth", async () => {
    const res = await api.get("/").set("accept", "application/json").redirects(0);
    expect(res.status).toBe(308);
    expect(res.headers.location).toBe("/auth");
  });

  it("GET / for browser redirects to /login without session", async () => {
    const res = await api.get("/").set("accept", "text/html").redirects(0);
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe("/login");
  });

  it("GET /login serves the login page", async () => {
    const res = await api.get("/login");
    expect(res.status).toBe(200);
    expect(res.text).toContain("密码");
    expect(res.text).toContain("/api/v1/session/password");
  });

  it("GET /admin redirects to /login without authenticated session", async () => {
    const res = await api.get("/admin").redirects(0);
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe("/login");
  });

  it("GET /admin serves the console when authenticated", async () => {
    const { authenticatedCookie } = await import("./helpers.js");
    const cookie = await authenticatedCookie();
    const res = await api.get("/admin").set("cookie", cookie).redirects(0);
    expect(res.status).toBe(200);
    expect(res.text).toContain("Passkey");
    expect(res.text).toContain("TOTP");
    expect(res.text).toContain("OIDC");
  });

  it("/admin.html direct access requires authentication", async () => {
    const res = await api.get("/admin.html").redirects(0);
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe("/login");
  });

  it("GET /auth 308 → discovery", async () => {
    const res = await api.get("/auth").redirects(0);
    expect(res.status).toBe(308);
    expect(res.headers.location).toBe("/auth/.well-known/openid-configuration");
  });

  it("stale req on /login shows the expired page", async () => {
    const res = await api.get("/login?req=does-not-exist");
    expect(res.status).toBe(400);
    expect(res.text).toContain("过期");
  });
});

