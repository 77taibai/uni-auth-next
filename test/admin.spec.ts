import { beforeEach, describe, expect, it } from "vitest";
import { api, ORIGIN, authenticatedCookie, ensureProfile } from "./helpers.js";
import { truncateAll } from "../src/db/migrate.js";
import { createPasskey } from "../src/db/repositories/passkeyRepository.js";

function post(path: string, body: unknown, cookie?: string) {
  const req = api.post(path).set("content-type", "application/json").set("origin", ORIGIN).send(body as object);
  return cookie ? req.set("cookie", cookie) : req;
}

async function state(cookie: string) {
  const res = await api.get("/api/v1/admin/overview").set("cookie", cookie);
  expect(res.status).toBe(200);
  return res.body as {
    identity: { subject: string; display_name: string; email: string | null };
    totp_enabled: boolean;
    passkeys: { id: string; name: string }[];
    clients: { id: string; client_id: string; name: string; redirect_uris: string[]; has_secret: boolean }[];
    oidc: Record<string, string>;
  };
}

beforeEach(async () => {
  await truncateAll();
  await ensureProfile();
});

describe("admin guard", () => {
  it("requires authenticated session", async () => {
    expect((await api.get("/api/v1/admin/overview")).status).toBe(401);
    expect((await post("/api/v1/admin/clients", { name: "x", redirect_uris: ["https://a.b/c"] })).status).toBe(401);
    expect((await post("/api/v1/admin/passkeys/options", {})).status).toBe(401);
  });

  it("rejects bad Origin on mutations", async () => {
    const cookie = await authenticatedCookie();
    const res = await api
      .post("/api/v1/admin/clients")
      .set("cookie", cookie)
      .set("content-type", "application/json")
      .set("origin", "https://evil.example")
      .send({ name: "x", redirect_uris: ["https://a.b/c"] });
    expect(res.status).toBe(403);
  });
});

describe("overview", () => {
  it("returns read-only identity from env, oidc endpoints and clients", async () => {
    const cookie = await authenticatedCookie();
    const created = await post("/api/v1/admin/clients", { name: "我的应用", redirect_uris: ["https://app.example.com/cb"], client_secret: "s3cret" }, cookie);
    expect(created.status).toBe(200);

    const st = await state(cookie);
    expect(st.identity).toMatchObject({ subject: "me", display_name: "测试用户" });
    expect(st.totp_enabled).toBe(false);
    expect(st.oidc.issuer).toBe(`${ORIGIN}/auth`);
    expect(st.oidc.authorize).toBe(`${ORIGIN}/oauth/authorize`);
    const cl = st.clients[0];
    expect(cl.has_secret).toBe(true);
    expect(cl.redirect_uris).toEqual(["https://app.example.com/cb"]);
  });
});

describe("clients CRUD", () => {
  it("validates redirect URIs and supports rename / update", async () => {
    const cookie = await authenticatedCookie();

    expect((await post("/api/v1/admin/clients", { name: "X", redirect_uris: ["ftp://x/cb"] }, cookie)).status).toBe(400);
    expect((await post("/api/v1/admin/clients", { name: "X", redirect_uris: [] }, cookie)).status).toBe(400);

    const ok = await post(
      "/api/v1/admin/clients",
      { name: "我的应用", redirect_uris: ["https://app.example.com/cb", "http://localhost:3000/cb"], client_secret: "abc" },
      cookie
    );
    expect(ok.status).toBe(200);
    expect(ok.body.client_id).toMatch(/^cli_/);

    const st = await state(cookie);
    const row = st.clients.find((c) => c.client_id === ok.body.client_id)!;

    const rename = await api
      .patch(`/api/v1/admin/clients/${row.id}`)
      .set("cookie", cookie)
      .set("content-type", "application/json")
      .set("origin", ORIGIN)
      .send({ name: "改名" });
    expect(rename.status).toBe(200);

    const updUris = await api
      .patch(`/api/v1/admin/clients/${row.id}`)
      .set("cookie", cookie)
      .set("content-type", "application/json")
      .set("origin", ORIGIN)
      .send({ redirect_uris: ["https://app2.example.com/cb"] });
    expect(updUris.status).toBe(200);

    const st2 = await state(cookie);
    const after = st2.clients.find((c) => c.client_id === ok.body.client_id)!;
    expect(after.name).toBe("改名");
    expect(after.redirect_uris).toEqual(["https://app2.example.com/cb"]);

    const del = await api.delete(`/api/v1/admin/clients/${row.id}`).set("origin", ORIGIN).set("cookie", cookie);
    expect(del.status).toBe(200);
    expect((await state(cookie)).clients).toHaveLength(0);

    const missing = await api.delete(`/api/v1/admin/clients/${row.id}`).set("origin", ORIGIN).set("cookie", cookie);
    expect(missing.status).toBe(404);
  });

  it("updates profile and validates input", async () => {
    const cookie = await authenticatedCookie();

    const bad = await post("/api/v1/admin/profile", { display_name: "", email: "" }, cookie);
    expect(bad.status).toBe(400);
    const badEmail = await post("/api/v1/admin/profile", { display_name: "我的名字", email: "not-an-email" }, cookie);
    expect(badEmail.status).toBe(400);

    const saved = await post("/api/v1/admin/profile", { display_name: "我的名字", email: "new@example.com" }, cookie);
    expect(saved.status).toBe(200);
    const st = await state(cookie);
    expect(st.identity.display_name).toBe("我的名字");
    expect(st.identity.email).toBe("new@example.com");

    // 清空邮箱
    const cleared = await post("/api/v1/admin/profile", { display_name: "我的名字", email: "" }, cookie);
    expect(cleared.status).toBe(200);
    expect((await state(cookie)).identity.email).toBeNull();
  });

  it("changes password: verifies old, invalidates session, new password works", async () => {
    const cookie = await authenticatedCookie();

    const bad = await post("/api/v1/admin/password", { old_password: "wrong", new_password: "new password 2" }, cookie);
    expect(bad.status).toBe(401);
    const weak = await post("/api/v1/admin/password", { old_password: "correct horse", new_password: "short" }, cookie);
    expect(weak.status).toBe(400);

    const ok = await post("/api/v1/admin/password", { old_password: "correct horse", new_password: "new password 2" }, cookie);
    expect(ok.status).toBe(200);

    // 旧会话已作废
    expect((await api.get("/admin").set("cookie", cookie).redirects(0)).status).toBe(302);

    // 新密码可登录，旧密码不可
    const oldLogin = await post("/api/v1/session/password", { password: "correct horse" });
    expect(oldLogin.status).toBe(401);
    const newLogin = await post("/api/v1/session/password", { password: "new password 2" });
    expect(newLogin.status).toBe(200);
    expect(newLogin.body).toEqual({ ok: true });
  });

  it("rejects empty PATCH bodies", async () => {
    const cookie = await authenticatedCookie();
    const created = await post("/api/v1/admin/clients", { name: "a", redirect_uris: ["https://a.b/c"] }, cookie);
    const st = await state(cookie);
    const row = st.clients.find((c) => c.client_id === created.body.client_id)!;
    const res = await api
      .patch(`/api/v1/admin/clients/${row.id}`)
      .set("cookie", cookie)
      .set("content-type", "application/json")
      .set("origin", ORIGIN)
      .send({});
    expect(res.status).toBe(400);
  });
});

describe("passkeys admin", () => {
  it("renames and deletes", async () => {
    const cookie = await authenticatedCookie();
    await createPasskey({ credentialId: "cred-1", publicKey: "pk", counter: 0, transports: [], name: "旧名" });
    const st = await state(cookie);
    const id = st.passkeys[0].id;

    const rename = await api
      .patch(`/api/v1/admin/passkeys/${id}`)
      .set("cookie", cookie)
      .set("content-type", "application/json")
      .set("origin", ORIGIN)
      .send({ name: "新名" });
    expect(rename.status).toBe(200);
    expect((await state(cookie)).passkeys[0].name).toBe("新名");

    const del = await api.delete(`/api/v1/admin/passkeys/${id}`).set("origin", ORIGIN).set("cookie", cookie);
    expect(del.status).toBe(200);
    expect((await state(cookie)).passkeys).toHaveLength(0);

    const missing = await api
      .patch("/api/v1/admin/passkeys/00000000-0000-0000-0000-000000000000")
      .set("cookie", cookie)
      .set("content-type", "application/json")
      .set("origin", ORIGIN)
      .send({ name: "x" });
    expect(missing.status).toBe(404);
  });
});



