import { deleteExpiredSessions } from "./repositories/sessionRepository";
import { deleteExpiredAuthRequests } from "./repositories/authRequestRepository";
import { deleteExpiredAuthorizationCodes } from "./repositories/authorizationCodeRepository";
import { deleteExpiredAccessTokens } from "./repositories/accessTokenRepository";
import { query } from "./pool";

/**
 * 清理过期行。Vercel 没有可靠的常驻定时任务，因此采用
 * “读取时判断过期 + 机会式定期清理”的组合：
 * - 写入会话时按概率触发（见 sessionService）
 * - 也可由外部 cron 执行 scripts/cleanup.ts
 */
export async function cleanupExpired(): Promise<void> {
  await Promise.all([
    deleteExpiredSessions(),
    deleteExpiredAuthRequests(),
    deleteExpiredAuthorizationCodes(),
    deleteExpiredAccessTokens(),
    query("DELETE FROM webauthn_challenges WHERE expires_at <= now()"),
    query("DELETE FROM login_rate_limits WHERE expires_at <= now()"),
  ]);
}
