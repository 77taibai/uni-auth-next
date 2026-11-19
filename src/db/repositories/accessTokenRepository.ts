import { query } from "../pool.js";

export type AccessTokenRow = {
  token_hash: string;
  subject: string;
  scope: string;
  client_id: string;
  created_at: Date;
  expires_at: Date;
};

/** access token 10 分钟有效 */
export const ACCESS_TOKEN_TTL_SECONDS = 600;

export async function createAccessToken(input: {
  tokenHash: string;
  subject: string;
  scope: string;
  clientId: string;
}): Promise<void> {
  await query(
    `INSERT INTO oidc_access_tokens (token_hash, subject, scope, client_id, expires_at)
     VALUES ($1, $2, $3, $4, $5)`,
    [input.tokenHash, input.subject, input.scope, input.clientId, new Date(Date.now() + ACCESS_TOKEN_TTL_SECONDS * 1000)]
  );
}

export async function getAccessToken(tokenHash: string): Promise<AccessTokenRow | null> {
  const { rows } = await query<AccessTokenRow>(
    "SELECT * FROM oidc_access_tokens WHERE token_hash = $1 AND expires_at > now()",
    [tokenHash]
  );
  return rows[0] ?? null;
}

export async function deleteExpiredAccessTokens(): Promise<void> {
  await query("DELETE FROM oidc_access_tokens WHERE expires_at <= now()");
}
