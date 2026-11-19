import request from "supertest";
import { createApp } from "../src/app.js";
import { loadConfig, resetConfigCache } from "../src/config/env.js";
import { createSession } from "../src/db/repositories/sessionRepository.js";
import { createClient } from "../src/db/repositories/clientRepository.js";
import { createProfile } from "../src/db/repositories/profileRepository.js";
import { hashPassword, sha256, randomToken } from "../src/security/crypto.js";

export const ORIGIN = "http://localhost:3000";
export const TEST_PASSWORD = "correct horse";
export const CLIENT_COOKIE = "uni_auth_sid";

/** 每个测试文件共享同一个 app（配置在模块加载时校验） */
export function buildApp() {
  resetConfigCache();
  return createApp(loadConfig());
}

export const app = buildApp();
export const api = request(app);

export function jsonHeaders(origin = ORIGIN) {
  return { "content-type": "application/json", origin };
}

/** 直接建一个已认证会话并返回 Cookie 头值 */
export async function authenticatedCookie(): Promise<string> {
  const sid = randomToken();
  await createSession({ sid, persistent: false, authenticated: true, authTime: new Date() });
  return `${CLIENT_COOKIE}=${sid}`;
}

/** 确保数据库中存在管理员身份（对应 /setup 的结果） */
export async function ensureProfile(password = TEST_PASSWORD): Promise<void> {
  await createProfile({
    subject: "me",
    displayName: "测试用户",
    email: "me@example.com",
    passwordHash: hashPassword(password, 1000),
  });
}

export async function seedClient(clientId: string, redirectUris: string[], secret: string | null = null): Promise<void> {
  await createClient({ clientId, name: `${clientId}-name`, redirectUris, secret });
}

export async function challengeFor(verifier: string): Promise<string> {
  return sha256(verifier);
}

/** 发起 /oauth/authorize，返回暂存的 authreq id */
export async function authorize(
  clientId: string,
  redirectUri: string,
  chal: string | null,
  state = "st-1"
): Promise<string> {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: "openid profile",
    state,
  });
  if (chal) {
    params.set("code_challenge", chal);
    params.set("code_challenge_method", "S256");
  }
  const res = await api.get(`/oauth/authorize?${params.toString()}`).redirects(0);
  const location = res.headers.location ?? "";
  const reqId = new URL(location, ORIGIN).searchParams.get("req");
  if (!reqId) throw new Error(`no req in redirect: ${res.status} ${location}`);
  return reqId;
}
