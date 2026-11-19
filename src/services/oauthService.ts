import { displayNameOf } from "../config/identity";
import { getClientByClientId, type ClientRow } from "../db/repositories/clientRepository";
import {
  createAuthRequest,
  getAuthRequest,
  consumeAuthRequest,
  type OidcAuthRequestRow,
} from "../db/repositories/authRequestRepository";
import { createAuthorizationCode, consumeAuthorizationCode } from "../db/repositories/authorizationCodeRepository";
import {
  createAccessToken,
  getAccessToken,
  ACCESS_TOKEN_TTL_SECONDS,
} from "../db/repositories/accessTokenRepository";
import { getProfile } from "../db/repositories/profileRepository";
import { randomToken, sha256, sha256Async, stringsEqual } from "../security/crypto";
import { signIdToken } from "../security/jwt";
import type { AppConfig } from "../config/env";

export const SUPPORTED_SCOPES = ["openid", "profile", "email"] as const;

/** issuer 是 <PUBLIC_ORIGIN>/auth，不依赖 Host 头；保持不变以兼容既有 id_token 校验 */
export function issuerOf(config: AppConfig): string {
  return `${config.publicOrigin}/auth`;
}

/**
 * 协议端点使用新的根级 /oauth/* 路径（文档 6.3），
 * 但 issuer 仍为 <origin>/auth，避免既有客户端的 iss 校验失效。
 * 旧 /auth/* 路径由兼容 adapter 转发到相同 controller。
 */
export function discoveryDocument(config: AppConfig) {
  return {
    issuer: issuerOf(config),
    authorization_endpoint: `${config.publicOrigin}/oauth/authorize`,
    token_endpoint: `${config.publicOrigin}/oauth/token`,
    userinfo_endpoint: `${config.publicOrigin}/oauth/userinfo`,
    jwks_uri: `${config.publicOrigin}/oauth/jwks.json`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    subject_type: "public",
    id_token_signing_alg_values_supported: ["ES256"],
    scopes_supported: [...SUPPORTED_SCOPES],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
    claims_supported: [
      "iss",
      "sub",
      "aud",
      "exp",
      "iat",
      "auth_time",
      "nonce",
      "name",
      "email",
      "preferred_username",
    ],
    code_challenge_methods_supported: ["S256"],
  };
}

export type AuthorizeQuery = {
  client_id?: string;
  redirect_uri?: string;
  response_type?: string;
  scope?: string;
  state?: string;
  code_challenge?: string;
  code_challenge_method?: string;
  nonce?: string;
};

export type AuthorizeOutcome =
  | { kind: "page_error"; message: string }
  | { kind: "redirect_error"; location: string }
  | { kind: "login"; reqId: string }
  | { kind: "consent"; reqId: string };

/** 校验授权请求；未知 client / 未注册 redirect_uri 只能落在本服务错误页 */
export async function authorize(
  config: AppConfig,
  query: AuthorizeQuery,
  authenticated: boolean
): Promise<AuthorizeOutcome> {
  const client: ClientRow | null = query.client_id ? await getClientByClientId(query.client_id) : null;
  if (!client) return { kind: "page_error", message: "未知的应用（client_id 无效）" };

  const redirectUri = query.redirect_uri ?? "";
  if (!client.redirect_uris.includes(redirectUri)) {
    return { kind: "page_error", message: "redirect_uri 与注册值不匹配" };
  }

  const redirectError = (error: string, description?: string): AuthorizeOutcome => {
    const u = new URL(redirectUri);
    u.searchParams.set("error", error);
    if (description) u.searchParams.set("error_description", description);
    if (query.state) u.searchParams.set("state", query.state);
    return { kind: "redirect_error", location: u.toString() };
  };

  if (query.response_type !== "code") return redirectError("unsupported_response_type");
  if (!query.state) return redirectError("invalid_request", "state is required");
  const scopes = (query.scope ?? "").split(" ").filter(Boolean);
  if (!scopes.includes("openid")) return redirectError("invalid_scope", "openid scope is required");
  if (query.code_challenge && query.code_challenge_method !== "S256") {
    return redirectError("invalid_request", "only S256 code_challenge_method is supported");
  }

  const reqId = randomToken(16);
  await createAuthRequest({
    id: reqId,
    clientId: client.client_id,
    redirectUri,
    scope: scopes.join(" "),
    state: query.state,
    codeChallenge: query.code_challenge ?? null,
    nonce: query.nonce ?? null,
  });

  return authenticated ? { kind: "consent", reqId } : { kind: "login", reqId };
}

export async function getAuthRequestInfo(
  reqId: string
): Promise<{ clientName: string; scopes: string[] } | null> {
  const authReq = await getAuthRequest(reqId);
  if (!authReq) return null;
  const client = await getClientByClientId(authReq.client_id);
  return {
    clientName: client?.name ?? authReq.client_id,
    scopes: authReq.scope.split(" "),
  };
}

export type ConsentOutcome =
  | { kind: "expired" }
  | { kind: "bad_action" }
  | { kind: "not_setup" }
  | { kind: "redirect"; location: string };

/** 确认/取消：消费授权请求；确认时签发一次性授权码 */
export async function consent(
  reqId: string,
  action: string,
  authTime: Date | null
): Promise<ConsentOutcome> {
  const authReq: OidcAuthRequestRow | null = await consumeAuthRequest(reqId);
  if (!authReq) return { kind: "expired" };

  const target = new URL(authReq.redirect_uri);
  if (action === "cancel") {
    target.searchParams.set("error", "access_denied");
    target.searchParams.set("state", authReq.state);
    return { kind: "redirect", location: target.toString() };
  }
  if (action !== "confirm") return { kind: "bad_action" };

  const profile = await getProfile();
  if (!profile) return { kind: "not_setup" };

  const code = randomToken(32);
  await createAuthorizationCode({
    codeHash: sha256(code),
    clientId: authReq.client_id,
    redirectUri: authReq.redirect_uri,
    scope: authReq.scope,
    codeChallenge: authReq.code_challenge,
    nonce: authReq.nonce,
    subject: profile.subject,
    authTime: authTime ?? new Date(),
  });
  target.searchParams.set("code", code);
  target.searchParams.set("state", authReq.state);
  return { kind: "redirect", location: target.toString() };
}

export type TokenInput = {
  clientId: string;
  clientSecret?: string;
  code: string;
  redirectUri: string;
  verifier: string;
};

export type TokenResult = { status: 200 | 400 | 401; body: Record<string, unknown> };

/** /token 核心逻辑：client 校验 → code 单次消费 → PKCE → 签发 token */
export async function issueTokens(config: AppConfig, input: TokenInput): Promise<TokenResult> {
  const oauthError = (error: string, description: string, status: 400 | 401 = 400): TokenResult => ({
    status,
    body: { error, error_description: description },
  });

  if (!input.clientId || !input.code || !input.redirectUri) {
    return oauthError("invalid_request", "client_id, code, redirect_uri are required");
  }

  const client = await getClientByClientId(input.clientId);
  if (!client) return oauthError("invalid_client", "unknown client", 401);
  if (client.client_secret) {
    if (!input.clientSecret || !stringsEqual(client.client_secret, input.clientSecret)) {
      return oauthError("invalid_client", "client_secret mismatch", 401);
    }
  }

  const payload = await consumeAuthorizationCode(sha256(input.code));
  if (!payload || payload.client_id !== input.clientId || payload.redirect_uri !== input.redirectUri) {
    return oauthError("invalid_grant", "code is invalid, expired, or replayed");
  }
  if (payload.code_challenge) {
    if (!input.verifier) {
      return oauthError("invalid_request", "code_verifier is required for this authorization code");
    }
    const derived = await sha256Async(input.verifier);
    if (!stringsEqual(derived, payload.code_challenge)) {
      return oauthError("invalid_grant", "PKCE verification failed");
    }
  }

  const scopes = payload.scope.split(" ");
  const accessToken = randomToken(32);
  await createAccessToken({
    tokenHash: sha256(accessToken),
    subject: payload.subject,
    scope: payload.scope,
    clientId: input.clientId,
  });

  const profile = scopes.includes("email") ? await getProfile() : null;
  const email = scopes.includes("email") ? profile?.email ?? undefined : undefined;
  const idToken = await signIdToken({
    iss: issuerOf(config),
    sub: payload.subject,
    aud: input.clientId,
    email,
    nonce: payload.nonce ?? undefined,
    authTime: Math.floor(payload.auth_time.getTime() / 1000),
  });

  return {
    status: 200,
    body: {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
      id_token: idToken,
      scope: payload.scope,
    },
  };
}

export async function userinfo(bearer: string | undefined): Promise<Record<string, unknown> | null> {
  if (!bearer) return null;
  const at = await getAccessToken(sha256(bearer));
  if (!at) return null;

  const profile = await getProfile();
  if (!profile) return null;

  const scopes = at.scope.split(" ");
  const claims: Record<string, unknown> = { sub: at.subject };
  if (scopes.includes("profile")) {
    claims.name = displayNameOf({ displayName: profile.display_name });
    claims.preferred_username = profile.subject;
  }
  if (scopes.includes("email") && profile.email) claims.email = profile.email;
  return claims;
}
