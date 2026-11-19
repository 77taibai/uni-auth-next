import { query } from "../pool.js";

export type ProfileRow = {
  id: boolean;
  subject: string;
  display_name: string;
  email: string | null;
  password_hash: string;
  created_at: Date;
  updated_at: Date;
};

/** 单管理员：固定单行 */
export async function getProfile(): Promise<ProfileRow | null> {
  const { rows } = await query<ProfileRow>("SELECT * FROM admin_profile LIMIT 1");
  return rows[0] ?? null;
}

/** 首次初始化：已存在则返回 false（只能创建一次） */
export async function createProfile(input: {
  subject: string;
  displayName: string;
  email: string | null;
  passwordHash: string;
}): Promise<boolean> {
  const { rowCount } = await query(
    `INSERT INTO admin_profile (subject, display_name, email, password_hash)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (id) DO NOTHING`,
    [input.subject, input.displayName, input.email, input.passwordHash]
  );
  return (rowCount ?? 0) > 0;
}

export async function updateProfile(input: { displayName: string; email: string | null }): Promise<boolean> {
  const { rowCount } = await query(
    "UPDATE admin_profile SET display_name = $1, email = $2, updated_at = now() WHERE id = true",
    [input.displayName, input.email]
  );
  return (rowCount ?? 0) > 0;
}

export async function updatePasswordHash(passwordHash: string): Promise<boolean> {
  const { rowCount } = await query(
    "UPDATE admin_profile SET password_hash = $1, updated_at = now() WHERE id = true",
    [passwordHash]
  );
  return (rowCount ?? 0) > 0;
}
