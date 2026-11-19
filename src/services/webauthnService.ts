import type { AppConfig } from "../config/env.js";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { fromB64Url, randomToken, toB64Url } from "../security/crypto.js";
import {
  createPasskey,
  getPasskeyByCredentialId,
  listPasskeys,
  updatePasskeyCounter,
} from "../db/repositories/passkeyRepository.js";
import { createChallenge, takeChallenge } from "../db/repositories/challengeRepository.js";
import { clearFailures, isLocked, recordFailure } from "../db/repositories/rateLimitRepository.js";
import {
  markAuthenticated,
  setPersistence,
  startSession,
  type LoginSession,
} from "./sessionService.js";

export function rpContext(publicOrigin: string): { rpID: string; origin: string } {
  const u = new URL(publicOrigin);
  return { rpID: u.hostname, origin: u.origin };
}

export async function registrationOptions(config: AppConfig) {
  const { rpID } = rpContext(config.publicOrigin);
  const existing = await listPasskeys();
  const options = await generateRegistrationOptions({
    rpName: "uni-auth",
    rpID,
    userName: "admin",
    attestationType: "none",
    excludeCredentials: existing.map((p) => ({ id: p.credential_id })),
    authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
  });
  const challengeId = randomToken(16);
  await createChallenge(challengeId, "register", options.challenge);
  return { options, challengeId };
}

export async function registerPasskey(
  config: AppConfig,
  input: { challengeId?: string; name?: string; response?: RegistrationResponseJSON }
): Promise<{ ok: true } | { error: "bad_challenge" | "bad_request" | "verification_failed" }> {
  const ch = input.challengeId ? await takeChallenge(input.challengeId, "register") : null;
  if (!ch) return { error: "bad_challenge" };
  if (!input.response) return { error: "bad_request" };

  const { rpID, origin } = rpContext(config.publicOrigin);
  try {
    const result = await verifyRegistrationResponse({
      response: input.response,
      expectedChallenge: ch.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: false,
    });
    if (!result.verified || !result.registrationInfo) return { error: "verification_failed" };
    const credential = result.registrationInfo.credential;
    await createPasskey({
      credentialId: credential.id,
      publicKey: toB64Url(credential.publicKey),
      counter: credential.counter,
      transports: credential.transports ?? [],
      name: input.name?.trim() || "Passkey",
    });
    return { ok: true };
  } catch {
    return { error: "verification_failed" };
  }
}

export async function authenticationOptions(
  config: AppConfig
): Promise<{ options: unknown; challengeId: string } | { error: "no_passkeys" }> {
  const creds = await listPasskeys();
  if (creds.length === 0) return { error: "no_passkeys" };
  const { rpID } = rpContext(config.publicOrigin);
  const options = await generateAuthenticationOptions({
    rpID,
    userVerification: "preferred",
    allowCredentials: creds.map((p) => ({ id: p.credential_id })),
  });
  const challengeId = randomToken(16);
  await createChallenge(challengeId, "login", options.challenge);
  return { options, challengeId };
}

export type PasskeyLoginOutcome =
  | { kind: "failed"; error: "locked"; status: 429 }
  | { kind: "failed"; error: "bad_challenge" | "bad_request" | "unknown_credential" | "verification_failed"; status: 400 | 401 }
  | { kind: "ok"; session: LoginSession };

/** Passkey 登录：无需已有会话；成功后递增 counter 并建立会话 */
export async function loginWithPasskey(
  config: AppConfig,
  ip: string,
  input: { challengeId?: string; remember?: boolean; response?: AuthenticationResponseJSON },
  existing: LoginSession | null
): Promise<PasskeyLoginOutcome> {
  if (await isLocked(ip)) return { kind: "failed", error: "locked", status: 429 };

  const ch = input.challengeId ? await takeChallenge(input.challengeId, "login") : null;
  if (!ch) return { kind: "failed", error: "bad_challenge", status: 400 };
  if (!input.response?.id) return { kind: "failed", error: "bad_request", status: 400 };

  const row = await getPasskeyByCredentialId(input.response.id);
  if (!row) {
    await recordFailure(ip);
    return { kind: "failed", error: "unknown_credential", status: 401 };
  }

  const { rpID, origin } = rpContext(config.publicOrigin);
  try {
    const result = await verifyAuthenticationResponse({
      response: input.response,
      expectedChallenge: ch.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: false,
      credential: {
        id: row.credential_id,
        publicKey: fromB64Url(row.public_key),
        counter: Number(row.counter),
        transports: row.transports ?? undefined,
      },
    });
    if (!result.verified || result.authenticationInfo.newCounter === undefined) {
      await recordFailure(ip);
      return { kind: "failed", error: "verification_failed", status: 401 };
    }
    await clearFailures(ip);
    await updatePasskeyCounter(row.id, result.authenticationInfo.newCounter);

    const persistent = input.remember === true;
    const session = existing ?? (await startSession(persistent));
    if (existing) await setPersistence(existing, persistent);
    const signedIn = await markAuthenticated(session);
    return { kind: "ok", session: signedIn };
  } catch {
    await recordFailure(ip);
    return { kind: "failed", error: "verification_failed", status: 401 };
  }
}
