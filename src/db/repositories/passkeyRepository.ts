import { query } from "../pool.js";

export type PasskeyRow = {
  id: string;
  credential_id: string;
  public_key: string;
  counter: string | number;
  transports: string[];
  name: string;
  created_at: Date;
  last_used_at: Date | null;
};

export async function listPasskeys(): Promise<PasskeyRow[]> {
  const { rows } = await query<PasskeyRow>("SELECT * FROM passkey_credentials ORDER BY created_at");
  return rows;
}

export async function getPasskeyByCredentialId(credentialId: string): Promise<PasskeyRow | null> {
  const { rows } = await query<PasskeyRow>("SELECT * FROM passkey_credentials WHERE credential_id = $1", [
    credentialId,
  ]);
  return rows[0] ?? null;
}

export async function getPasskeyById(id: string): Promise<PasskeyRow | null> {
  const { rows } = await query<PasskeyRow>("SELECT * FROM passkey_credentials WHERE id = $1", [id]);
  return rows[0] ?? null;
}

export async function createPasskey(input: {
  credentialId: string;
  publicKey: string;
  counter: number;
  transports: string[];
  name: string;
}): Promise<void> {
  await query(
    `INSERT INTO passkey_credentials (credential_id, public_key, counter, transports, name)
     VALUES ($1, $2, $3, $4, $5)`,
    [input.credentialId, input.publicKey, input.counter, input.transports, input.name]
  );
}

export async function updatePasskeyCounter(id: string, counter: number): Promise<void> {
  await query("UPDATE passkey_credentials SET counter = $2, last_used_at = now() WHERE id = $1", [id, counter]);
}

export async function renamePasskey(id: string, name: string): Promise<boolean> {
  const result = await query("UPDATE passkey_credentials SET name = $2 WHERE id = $1", [id, name]);
  return (result.rowCount ?? 0) > 0;
}

export async function deletePasskey(id: string): Promise<void> {
  await query("DELETE FROM passkey_credentials WHERE id = $1", [id]);
}
