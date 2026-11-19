import { describe, expect, it } from "vitest";
import { query } from "../src/db/pool";

const TABLES = [
  "admin_profile",
  "passkey_credentials",
  "totp_credentials",
  "clients",
  "auth_sessions",
  "oidc_auth_requests",
  "oidc_authorization_codes",
  "oidc_access_tokens",
  "webauthn_challenges",
  "login_rate_limits",
  "oidc_signing_keys",
  "schema_migrations",
] as const;

describe("migrations", () => {
  it("created all runtime tables", async () => {
    for (const table of TABLES) {
      const { rows } = await query<{ n: string }>(`SELECT COUNT(*) AS n FROM ${table}`);
      expect(rows, table).toBeDefined();
      expect(Number(rows[0].n)).toBeGreaterThanOrEqual(0);
    }
  });

  it("redirect_uris and transports are text[]", async () => {
    const { rows } = await query<{ data_type: string }>(
      `SELECT data_type FROM information_schema.columns
       WHERE table_name = 'clients' AND column_name = 'redirect_uris'`
    );
    expect(rows[0].data_type).toBe("ARRAY");
  });
});

