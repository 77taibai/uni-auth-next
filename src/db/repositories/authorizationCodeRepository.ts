import { query, withTransaction } from "../pool";

export type AuthorizationCodeRow = {
  code_hash: string;
  client_id: string;
  redirect_uri: string;
  scope: string;
  code_challenge: string | null;
  nonce: string | null;
  subject: string;
  auth_time: Date;
  created_at: Date;
  expires_at: Date;
  consumed_at: Date | null;
};

/** 授权码 2 分钟有效 */
export const AUTH_CODE_TTL_SECONDS = 120;

/** 数据库中只保存 code 的 SHA-256 哈希 */
export async function createAuthorizationCode(input: {
  codeHash: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  codeChallenge: string | null;
  nonce: string | null;
  subject: string;
  authTime: Date;
}): Promise<void> {
  await query(
    `INSERT INTO oidc_authorization_codes
       (code_hash, client_id, redirect_uri, scope, code_challenge, nonce, subject, auth_time, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    [
      input.codeHash,
      input.clientId,
      input.redirectUri,
      input.scope,
      input.codeChallenge,
      input.nonce,
      input.subject,
      input.authTime,
      new Date(Date.now() + AUTH_CODE_TTL_SECONDS * 1000),
    ]
  );
}

/**
 * 单次消费：事务 + 行锁。已消费、过期或不存在都返回 null，重放必然失败。
 * 返回行后立即标记 consumed_at。
 */
export async function consumeAuthorizationCode(codeHash: string): Promise<AuthorizationCodeRow | null> {
  return withTransaction(async (client) => {
    const { rows } = await client.query<AuthorizationCodeRow>(
      `SELECT * FROM oidc_authorization_codes
       WHERE code_hash = $1 AND consumed_at IS NULL AND expires_at > now()
       FOR UPDATE`,
      [codeHash]
    );
    const row = rows[0];
    if (!row) return null;
    await client.query("UPDATE oidc_authorization_codes SET consumed_at = now() WHERE code_hash = $1", [codeHash]);
    return row;
  });
}

export async function deleteExpiredAuthorizationCodes(): Promise<void> {
  await query("DELETE FROM oidc_authorization_codes WHERE expires_at <= now()");
}
