import { query } from "../pool.js";

export type TotpRow = {
  id: string;
  secret_encrypted: string;
  digits: number;
  period: number;
  confirmed: boolean;
  created_at: Date;
};

/** 单用户：TOTP 凭证固定单行 */
export const TOTP_ID = "totp";

export async function getTotp(): Promise<TotpRow | null> {
  const { rows } = await query<TotpRow>("SELECT * FROM totp_credentials WHERE id = $1", [TOTP_ID]);
  return rows[0] ?? null;
}

export async function getConfirmedTotp(): Promise<TotpRow | null> {
  const { rows } = await query<TotpRow>("SELECT * FROM totp_credentials WHERE confirmed = true LIMIT 1");
  return rows[0] ?? null;
}

/** 开通/重新开通：写入未确认的加密密钥（确认后才生效） */
export async function upsertPendingTotp(secretEncrypted: string): Promise<void> {
  await query(
    `INSERT INTO totp_credentials (id, secret_encrypted, digits, period, confirmed)
     VALUES ($1, $2, 6, 30, false)
     ON CONFLICT (id) DO UPDATE SET secret_encrypted = EXCLUDED.secret_encrypted, confirmed = false`,
    [TOTP_ID, secretEncrypted]
  );
}

export async function confirmTotp(): Promise<void> {
  await query("UPDATE totp_credentials SET confirmed = true WHERE id = $1", [TOTP_ID]);
}

export async function deleteTotp(): Promise<void> {
  await query("DELETE FROM totp_credentials WHERE id = $1", [TOTP_ID]);
}
