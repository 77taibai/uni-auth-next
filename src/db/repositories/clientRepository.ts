import { query } from "../pool";

export type ClientRow = {
  id: string;
  client_id: string;
  name: string;
  redirect_uris: string[];
  client_secret: string | null;
  created_at: Date;
};

export async function listClients(): Promise<ClientRow[]> {
  const { rows } = await query<ClientRow>("SELECT * FROM clients ORDER BY created_at");
  return rows;
}

export async function getClientByClientId(clientId: string): Promise<ClientRow | null> {
  const { rows } = await query<ClientRow>("SELECT * FROM clients WHERE client_id = $1", [clientId]);
  return rows[0] ?? null;
}

export async function getClientById(id: string): Promise<ClientRow | null> {
  const { rows } = await query<ClientRow>("SELECT * FROM clients WHERE id = $1", [id]);
  return rows[0] ?? null;
}

export async function createClient(input: {
  clientId: string;
  name: string;
  redirectUris: string[];
  secret: string | null;
}): Promise<void> {
  await query(
    "INSERT INTO clients (client_id, name, redirect_uris, client_secret) VALUES ($1, $2, $3, $4)",
    [input.clientId, input.name, input.redirectUris, input.secret]
  );
}

export async function updateClientName(id: string, name: string): Promise<boolean> {
  const result = await query("UPDATE clients SET name = $2 WHERE id = $1", [id, name]);
  return (result.rowCount ?? 0) > 0;
}

export async function updateClientRedirectUris(id: string, redirectUris: string[]): Promise<boolean> {
  const result = await query("UPDATE clients SET redirect_uris = $2 WHERE id = $1", [id, redirectUris]);
  return (result.rowCount ?? 0) > 0;
}

export async function deleteClient(id: string): Promise<void> {
  await query("DELETE FROM clients WHERE id = $1", [id]);
}
