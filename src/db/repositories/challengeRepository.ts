import { withTransaction } from "../pool.js";

export type ChallengeKind = "register" | "login";

/** 挑战有效 120 秒 */
export const CHALLENGE_TTL_SECONDS = 120;

export async function createChallenge(id: string, kind: ChallengeKind, challenge: string): Promise<void> {
  await withTransaction(async (client) => {
    await client.query(
      `INSERT INTO webauthn_challenges (id, kind, challenge, expires_at) VALUES ($1, $2, $3, $4)`,
      [id, kind, challenge, new Date(Date.now() + CHALLENGE_TTL_SECONDS * 1000)]
    );
  });
}

/** 单次消费：事务 + 行锁 */
export async function takeChallenge(
  id: string,
  kind: ChallengeKind
): Promise<{ challenge: string; kind: ChallengeKind } | null> {
  return withTransaction(async (client) => {
    const { rows } = await client.query<{ challenge: string; kind: ChallengeKind }>(
      `SELECT challenge, kind FROM webauthn_challenges
       WHERE id = $1 AND expires_at > now()
       FOR UPDATE`,
      [id]
    );
    const row = rows[0];
    if (!row) return null;
    await client.query("DELETE FROM webauthn_challenges WHERE id = $1", [id]);
    return row.kind === kind ? row : null;
  });
}
