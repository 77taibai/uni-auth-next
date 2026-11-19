import { beforeEach, describe, expect, it } from "vitest";
import { createLocalJWKSet, jwtVerify } from "jose";
import { api, ORIGIN, authenticatedCookie, seedClient, ensureProfile } from "./helpers";
import { truncateAll } from "../src/db/migrate";
import { createAuthorizationCode } from "../src/db/repositories/authorizationCodeRepository";
import { sha256 } from "../src/security/crypto";

const CB = "https://app.example.com/cb";
const VERIFIER = "unit-test-verifier-unit-test-verifier-0123456789";

beforeEach(async () => {
  await truncateAll();
  await ensureProfile();
});

async function seedCode(overrides: Partial<Parameters<typeof createAuthorizationCode>[0]> = {}): Promise<string> {
  const code = `test-code-${Math.random().toString(36).slice(2)}`;
  await createAuthorizationCode({
    codeHash: sha256(code),
    clientId: "test-app",
    redirectUri: CB,
    scope: "openid profile email",
    codeChallenge: sha256(VERIFIER),
    nonce: "n-abc",
    subject: "me",
    authTime: new Date(),
    ...overrides,
  });
  return code;
}

function tokenReq(code: string, overrides: Record<string, string> = {}, authorization?: string) {
  const req = api.post("/oauth/token").type("form").send({
    grant_type: "authorization_code",
    client_id: "test-app",
    code,
    redirect_uri: CB,
    code_verifier: VERIFIER,
    ...overrides,
  });
  return authorization ? req.set("authorization", authorization) : req;
}

describe("token", () => {
  it("happy path: verifiable id_token, single-use code, no-store", async () => {
    await seedClient("test-app", [CB]);
    const code = await seedCode();

    const res = await tokenReq(code);
    expect(res.status).toBe(200);
    expect(res.headers["cache-control"]).toContain("no-store");
    expect(res.body.token_type).toBe("Bearer");
    expect(res.body.expires_in).toBe(600);

    const jwks = (await api.get("/oauth/jwks.json")).body as { keys: Array<Record<string, unknown>> };
    expect(jwks.keys[0]).toMatchObject({ kty: "EC", alg: "ES256", use: "sig" });
    const { payload } = await jwtVerify(res.body.id_token, createLocalJWKSet(jwks), {
      issuer: `${ORIGIN}/auth`,
      audience: "test-app",
    });
    expect(payload.sub).toBe("me");
    expect(payload.email).toBe("me@example.com");
    expect(payload.nonce).toBe("n-abc");
    expect(typeof payload.auth_time).toBe("number");
    expect((payload.exp as number) - (payload.iat as number)).toBe(300);

    expect((await tokenReq(code)).status).toBe(400); // 重放
  });

  it("wrong code_verifier → invalid_grant", async () => {
    await seedClient("test-app", [CB]);
    const code = await seedCode();
    const res = await tokenReq(code, { code_verifier: "wrong-verifier" });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_grant");
  });

  it("redirect_uri mismatch → invalid_grant", async () => {
    await seedClient("test-app", [CB]);
    const code = await seedCode();
    const res = await tokenReq(code, { redirect_uri: "https://app.example.com/other" });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_grant");
  });

  it("PKCE only required when the code carried a challenge", async () => {
    await seedClient("test-app", [CB]);
    const code = await seedCode({ codeChallenge: null });
    const res = await tokenReq(code, { code_verifier: "" });
    expect(res.status).toBe(200);
  });

  it("client_secret enforced before code consumption (Basic and form)", async () => {
    await seedClient("test-app", [CB], "s3cr3t-value");
    const code = await seedCode();

    const noSecret = await tokenReq(code);
    expect(noSecret.status).toBe(401);
    expect(noSecret.body.error).toBe("invalid_client");

    const badSecret = await tokenReq(code, { client_secret: "wrong" });
    expect(badSecret.status).toBe(401);

    const ok = await tokenReq(code, {}, `Basic ${Buffer.from("test-app:s3cr3t-value").toString("base64")}`);
    expect(ok.status).toBe(200);

    const code2 = await seedCode();
    const formOk = await tokenReq(code2, { client_secret: "s3cr3t-value" });
    expect(formOk.status).toBe(200);
  });

  it("falls back to form credentials when Basic cannot be parsed", async () => {
    await seedClient("test-app", [CB], "s3cr3t-value");
    const code = await seedCode();
    const res = await tokenReq(code, { client_secret: "s3cr3t-value" }, "Basic not-base64");
    expect(res.status).toBe(200);
  });

  it("unsupported grant type is rejected", async () => {
    const res = await api.post("/oauth/token").type("form").send({ grant_type: "client_credentials" });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("unsupported_grant_type");
  });
});

describe("userinfo", () => {
  it("returns claims by scope", async () => {
    await seedClient("test-app", [CB]);
    const code = await seedCode();
    const { access_token } = (await tokenReq(code)).body;

    const res = await api.get("/oauth/userinfo").set("authorization", `Bearer ${access_token}`);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ sub: "me", name: "测试用户", preferred_username: "me", email: "me@example.com" });
  });

  it("omits email when not in scope", async () => {
    await seedClient("test-app", [CB]);
    const code = await seedCode({ scope: "openid profile" });
    const { access_token } = (await tokenReq(code)).body;
    const res = await api.get("/oauth/userinfo").set("authorization", `Bearer ${access_token}`);
    expect(res.body.email).toBeUndefined();
    expect(res.body.name).toBe("测试用户");
  });

  it("rejects missing/unknown bearer token", async () => {
    expect((await api.get("/oauth/userinfo")).status).toBe(401);
    expect((await api.get("/oauth/userinfo").set("authorization", "Bearer bogus")).status).toBe(401);
  });
});

/** 未使用的辅助导出，避免误删 authenticatedCookie 引入 */
void authenticatedCookie;



