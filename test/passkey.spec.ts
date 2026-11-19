import { beforeEach, describe, expect, it } from "vitest";
import { api, ORIGIN, authenticatedCookie } from "./helpers.js";
import { truncateAll } from "../src/db/migrate.js";
import { clearFailures } from "../src/db/repositories/rateLimitRepository.js";
import { query } from "../src/db/pool.js";
import { VirtualAuthenticator } from "./webauthn-emulator.js";
import { toB64Url } from "../src/security/crypto.js";

const RP_ID = "localhost";

function post(path: string, body: unknown, cookie?: string) {
  const req = api.post(path).set("content-type", "application/json").set("origin", ORIGIN).send(body as object);
  return cookie ? req.set("cookie", cookie) : req;
}

async function register(cookie: string, authr: VirtualAuthenticator, name?: string) {
  const opt = await post("/api/v1/admin/passkeys/options", {}, cookie);
  expect(opt.status).toBe(200);
  const { options, challengeId } = opt.body as { options: { rp: { id: string }; challenge: string }; challengeId: string };
  expect(options.rp.id).toBe(RP_ID);
  const reg = await authr.registration(RP_ID, ORIGIN, options.challenge);
  return post("/api/v1/admin/passkeys", { challengeId, response: reg, name }, cookie);
}

beforeEach(async () => {
  await truncateAll();
  await clearFailures("127.0.0.1");
});

describe("passkey registration", () => {
  it("option endpoints enforce auth/no-credentials", async () => {
    expect((await post("/api/v1/admin/passkeys/options", {})).status).toBe(401);
    expect((await post("/api/v1/session/passkey/options", {})).status).toBe(400); // 无凭证
  });

  it("stores credential and excludes it on next options", async () => {
    const cookie = await authenticatedCookie();
    const authr = await VirtualAuthenticator.create();
    const res = await register(cookie, authr, "MacBook 指纹");
    expect(res.status).toBe(200);

    const { rows } = await query<{ credential_id: string; counter: string; name: string }>(
      "SELECT credential_id, counter, name FROM passkey_credentials"
    );
    expect(rows[0].name).toBe("MacBook 指纹");
    expect(rows[0].credential_id).toBe(toB64Url(authr.rawId));
    expect(Number(rows[0].counter)).toBe(0);

    const opt = await post("/api/v1/admin/passkeys/options", {}, cookie);
    const excluded = (opt.body.options.excludeCredentials as { id: string }[]).map((c) => c.id);
    expect(excluded).toContain(toB64Url(authr.rawId));
  });

  it("challenge is single-use", async () => {
    const cookie = await authenticatedCookie();
    const opt = await post("/api/v1/admin/passkeys/options", {}, cookie);
    const { challengeId } = opt.body as { challengeId: string };

    const first = await post("/api/v1/admin/passkeys", { challengeId, response: { garbage: true } }, cookie);
    expect(first.status).toBe(401);
    const second = await post("/api/v1/admin/passkeys", { challengeId, response: { garbage: true } }, cookie);
    expect(second.status).toBe(400);
    expect(second.body.error).toBe("bad_challenge");
  });
});

describe("passkey login", () => {
  it("full login authenticates and bumps counter", async () => {
    const cookie = await authenticatedCookie();
    const authr = await VirtualAuthenticator.create();
    expect((await register(cookie, authr)).status).toBe(200);

    const opt = await post("/api/v1/session/passkey/options", {});
    expect(opt.status).toBe(200);
    const { options, challengeId } = opt.body as { options: { challenge: string; allowCredentials: { id: string }[] }; challengeId: string };
    expect(options.allowCredentials.map((c) => c.id)).toContain(toB64Url(authr.rawId));

    const assertion = await authr.assertion(RP_ID, ORIGIN, options.challenge);
    const login = await post("/api/v1/session/passkey/verify", { challengeId, response: assertion });
    expect(login.status).toBe(200);
    expect(login.body).toEqual({ ok: true });

    const sid = (login.headers["set-cookie"]?.[0] ?? "").split(";")[0];
    expect(sid).toContain("uni_auth_sid=");
    expect((await api.get("/admin").set("cookie", sid).redirects(0)).status).toBe(200);

    const { rows } = await query<{ counter: string }>(
      "SELECT counter FROM passkey_credentials WHERE credential_id = $1",
      [toB64Url(authr.rawId)]
    );
    expect(Number(rows[0].counter)).toBe(1);
  });

  it("unknown credential → 401", async () => {
    const cookie = await authenticatedCookie();
    const authr = await VirtualAuthenticator.create();
    await register(cookie, authr);

    const rogue = await VirtualAuthenticator.create();
    const opt = await post("/api/v1/session/passkey/options", {});
    const { options, challengeId } = opt.body as { options: { challenge: string }; challengeId: string };
    const assertion = await rogue.assertion(RP_ID, ORIGIN, options.challenge);
    const res = await post("/api/v1/session/passkey/verify", { challengeId, response: assertion });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe("unknown_credential");
  });

  it("locks IP after 5 failed passkey logins", async () => {
    const cookie = await authenticatedCookie();
    const authr = await VirtualAuthenticator.create();
    await register(cookie, authr);
    await clearFailures("127.0.0.1");

    const rogue = await VirtualAuthenticator.create();
    for (let i = 0; i < 5; i++) {
      const opt = await post("/api/v1/session/passkey/options", {});
      const { options, challengeId } = opt.body as { options: { challenge: string }; challengeId: string };
      const assertion = await rogue.assertion(RP_ID, ORIGIN, options.challenge);
      const res = await post("/api/v1/session/passkey/verify", { challengeId, response: assertion });
      expect(res.status, `attempt ${i}`).toBe(401);
    }

    const opt = await post("/api/v1/session/passkey/options", {});
    const { options, challengeId } = opt.body as { options: { challenge: string }; challengeId: string };
    const assertion = await rogue.assertion(RP_ID, ORIGIN, options.challenge);
    const locked = await post("/api/v1/session/passkey/verify", { challengeId, response: assertion });
    expect(locked.status).toBe(429);
    expect(locked.body.error).toBe("locked");
    await clearFailures("127.0.0.1");
  });
});
