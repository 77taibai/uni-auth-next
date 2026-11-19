import { query, withTransaction } from "../pool.js";

export type OidcAuthRequestRow = {
  id: string;
  client_id: string;
  redirect_uri: string;
  scope: string;
  state: string;
  code_challenge: string | null;
  code_challenge_method: string | null;
  nonce: string | null;
  created_at: Date;
  expires_at: Date;
};

/** 授权请求 15 分钟有效 */
export const AUTH_REQUEST_TTL_SECONDS = 900;

export async function createAuthRequest(input: {
  id: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string;
  codeChallenge?: string | null;
  nonce?: string | null;
}): Promise<void> {
  await query(
    `INSERT INTO oidc_auth_requests
       (id, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, nonce, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    [
      input.id,
      input.clientId,
      input.redirectUri,
      input.scope,
      input.state,
      input.codeChallenge ?? null,
      input.codeChallenge ? "S256" : null,
      input.nonce ?? null,
      new Date(Date.now() + AUTH_REQUEST_TTL_SECONDS * 1000),
    ]
  );
}

export async function getAuthRequest(id: string): Promise<OidcAuthRequestRow | null> {
  const { rows } = await query<OidcAuthRequestRow>(
    "SELECT * FROM oidc_auth_requests WHERE id = $1 AND expires_at > now()",
    [id]
  );
  return rows[0] ?? null;
}

/** 单次消费：事务 + 行锁，避免并发双花 */
export async function consumeAuthRequest(id: string): Promise<OidcAuthRequestRow | null> {
  return withTransaction(async (client) => {
    const { rows } = await client.query<OidcAuthRequestRow>(
      "SELECT * FROM oidc_auth_requests WHERE id = $1 AND expires_at > now() FOR UPDATE",
      [id]
    );
    const row = rows[0];
    if (!row) return null;
    await client.query("DELETE FROM oidc_auth_requests WHERE id = $1", [id]);
    return row;
  });
}

export async function deleteExpiredAuthRequests(): Promise<void> {
  await query("DELETE FROM oidc_auth_requests WHERE expires_at <= now()");
}
