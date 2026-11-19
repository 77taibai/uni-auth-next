import type { JWK } from "jose";
import { query } from "../pool.js";

export type SigningKeyRow = {
  id: boolean;
  kid: string;
  private_jwk: JWK;
  public_jwk: JWK;
  created_at: Date;
};

export async function getSigningKeyRow(): Promise<SigningKeyRow | null> {
  const { rows } = await query<SigningKeyRow>("SELECT * FROM oidc_signing_keys LIMIT 1");
  return rows[0] ?? null;
}

export async function insertSigningKey(input: { kid: string; privateJwk: JWK; publicJwk: JWK }): Promise<void> {
  await query(
    `INSERT INTO oidc_signing_keys (kid, private_jwk, public_jwk)
     VALUES ($1, $2, $3)
     ON CONFLICT (id) DO NOTHING`,
    [input.kid, JSON.stringify(input.privateJwk), JSON.stringify(input.publicJwk)]
  );
}
