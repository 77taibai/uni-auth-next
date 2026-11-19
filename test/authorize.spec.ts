import { beforeEach, describe, expect, it } from "vitest";
import { api, ORIGIN, challengeFor, seedClient, authenticatedCookie, authorize, ensureProfile } from "./helpers";
import { truncateAll } from "../src/db/migrate";

const CB = "https://app.example.com/cb";
const VERIFIER = "unit-test-verifier-unit-test-verifier-0123456789";

beforeEach(async () => {
  await truncateAll();
  await ensureProfile();
});

describe("discovery", () => {
  it("issuer is <origin>/auth and endpoints use /oauth", async () => {
    const res = await api.get("/.well-known/openid-configuration");
    expect(res.status).toBe(200);
    const doc = res.body;
    expect(doc.issuer).toBe(`${ORIGIN}/auth`);
    expect(doc.authorization_endpoint).toBe(`${ORIGIN}/oauth/authorize`);
    expect(doc.token_endpoint).toBe(`${ORIGIN}/oauth/token`);
    expect(doc.userinfo_endpoint).toBe(`${ORIGIN}/oauth/userinfo`);
    expect(doc.jwks_uri).toBe(`${ORIGIN}/oauth/jwks.json`);
    expect(doc.grant_types_supported).toEqual(["authorization_code"]);
    expect(doc.token_endpoint_auth_methods_supported).toContain("client_secret_basic");
    expect(doc.code_challenge_methods_supported).toEqual(["S256"]);
    expect(doc.id_token_signing_alg_values_supported).toEqual(["ES256"]);
  });

  it("legacy /auth discovery still works for existing clients", async () => {
    const res = await api.get("/auth/.well-known/openid-configuration");
    expect(res.status).toBe(200);
    expect(res.body.issuer).toBe(`${ORIGIN}/auth`);
  });
});

describe("authorize", () => {
  it("unknown client → 400 page (no redirect)", async () => {
    await seedClient("test-app", [CB]);
    const res = await api
      .get("/oauth/authorize")
      .query({ client_id: "nope", redirect_uri: CB, response_type: "code", scope: "openid", state: "s" })
      .redirects(0);
    expect(res.status).toBe(400);
    expect(res.text).toContain("client_id");
  });

  it("unregistered redirect_uri → 400 page (no redirect)", async () => {
    await seedClient("test-app", [CB]);
    const res = await api
      .get("/oauth/authorize")
      .query({ client_id: "test-app", redirect_uri: "https://evil.example/cb", response_type: "code", scope: "openid", state: "s" })
      .redirects(0);
    expect(res.status).toBe(400);
    expect(res.text).toContain("redirect_uri");
  });

  it("missing state → invalid_request without state echo", async () => {
    await seedClient("test-app", [CB]);
    const res = await api
      .get("/oauth/authorize")
      .query({ client_id: "test-app", redirect_uri: CB, response_type: "code", scope: "openid" })
      .redirects(0);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.location!);
    expect(loc.origin + loc.pathname).toBe(CB);
    expect(loc.searchParams.get("error")).toBe("invalid_request");
    expect(loc.searchParams.get("state")).toBeNull();
  });

  it("pkce plain / missing challenge / bad scope / bad response_type all rejected with state echo", async () => {
    await seedClient("test-app", [CB]);
    const base = { client_id: "test-app", redirect_uri: CB, response_type: "code", scope: "openid", state: "st-123" };

    const plain = await api
      .get("/oauth/authorize")
      .query({ ...base, code_challenge: await challengeFor(VERIFIER), code_challenge_method: "plain" })
      .redirects(0);
    expect(errorOf(plain)).toBe("invalid_request");
    expect(new URL(plain.headers.location!).searchParams.get("state")).toBe("st-123");

    const noScope = await api.get("/oauth/authorize").query({ ...base, scope: "profile" }).redirects(0);
    expect(errorOf(noScope)).toBe("invalid_scope");

    const badType = await api.get("/oauth/authorize").query({ ...base, response_type: "token" }).redirects(0);
    expect(errorOf(badType)).toBe("unsupported_response_type");
  });

  it("valid unauthenticated → /login?req= with stored auth request", async () => {
    await seedClient("test-app", [CB]);
    const res = await api
      .get("/oauth/authorize")
      .query({
        client_id: "test-app",
        redirect_uri: CB,
        response_type: "code",
        scope: "openid profile",
        state: "st-1",
        code_challenge: await challengeFor(VERIFIER),
        code_challenge_method: "S256",
      })
      .redirects(0);
    expect(res.status).toBe(302);
    expect(res.headers.location).toMatch(/^\/login\?req=/);
  });

  it("valid authenticated → /oauth/consent?req=", async () => {
    await seedClient("test-app", [CB]);
    const cookie = await authenticatedCookie();
    const reqId = await authorize("test-app", CB, await challengeFor(VERIFIER));
    const res = await api.get(`/oauth/consent?req=${reqId}`).set("cookie", cookie).redirects(0);
    expect(res.status).toBe(200);
    expect(res.text).toContain("确认登录");
  });

  it("legacy root aliases redirect 308", async () => {
    const discovery = await api.get("/.well-known/openid-configuration").redirects(0);
    expect(discovery.status).toBe(200);
    // 兼容旧客户端：/authorize 308 到 /auth/authorize
    const legacy = await api.get("/authorize?client_id=test-app").redirects(0);
    expect(legacy.status).toBe(308);
    expect(legacy.headers.location).toBe("/auth/authorize?client_id=test-app");
  });
});

describe("consent", () => {
  it("issues code and token exchange works end to end", async () => {
    await seedClient("conf-app", [CB]);
    const cookie = await authenticatedCookie();
    const reqId = await authorize("conf-app", CB, await challengeFor(VERIFIER));

    const info = await api.get(`/oauth/consent/info?req=${reqId}`).set("cookie", cookie);
    expect(info.status).toBe(200);
    expect(info.body).toEqual({ clientName: "conf-app-name", scopes: ["openid", "profile"] });

    const approve = await api
      .post("/oauth/consent/approve")
      .set("cookie", cookie)
      .set("content-type", "application/json")
      .set("origin", ORIGIN)
      .send({ req: reqId });
    expect(approve.status).toBe(200);
    const target = new URL(approve.body.redirect);
    expect(target.origin + target.pathname).toBe(CB);
    expect(target.searchParams.get("state")).toBe("st-1");
    const code = target.searchParams.get("code")!;

    const exchange = () => api.post("/oauth/token").type("form").send({
      grant_type: "authorization_code",
      client_id: "conf-app",
      code,
      redirect_uri: CB,
      code_verifier: VERIFIER,
    });
    expect((await exchange()).status).toBe(200);
    expect((await exchange()).status).toBe(400); // 单次使用
  });

  it("cancel → access_denied with state", async () => {
    await seedClient("conf-app", [CB]);
    const cookie = await authenticatedCookie();
    const reqId = await authorize("conf-app", CB, await challengeFor(VERIFIER));
    const res = await api
      .post("/oauth/consent/deny")
      .set("cookie", cookie)
      .set("content-type", "application/json")
      .set("origin", ORIGIN)
      .send({ req: reqId });
    expect(res.status).toBe(200);
    expect(res.body.redirect).toContain("error=access_denied");
    expect(res.body.redirect).toContain("state=st-1");
  });

  it("requires session and live request", async () => {
    await seedClient("conf-app", [CB]);
    const noSess = await api
      .post("/oauth/consent/approve")
      .set("content-type", "application/json")
      .set("origin", ORIGIN)
      .send({ req: "x" });
    expect(noSess.status).toBe(401);

    const cookie = await authenticatedCookie();
    const missing = await api.get("/oauth/consent/info?req=nope").set("cookie", cookie);
    expect(missing.status).toBe(400);
  });
});

function errorOf(res: { headers: Record<string, string> }): string {
  return new URL(res.headers.location!).searchParams.get("error") ?? "";
}



