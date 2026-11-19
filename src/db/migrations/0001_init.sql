-- 0001_init: 管理员身份资料、运行时凭证、OIDC 客户端与全部带 TTL 的会话/协议状态
-- 单管理员身份（subject/display_name/email/password_hash）存于 admin_profile，由 /setup 初始化。

CREATE TABLE IF NOT EXISTS passkey_credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  credential_id text NOT NULL UNIQUE,
  public_key text NOT NULL,
  counter bigint NOT NULL DEFAULT 0,
  transports text[] NOT NULL DEFAULT '{}',
  name text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz
);

CREATE TABLE IF NOT EXISTS totp_credentials (
  id text PRIMARY KEY,
  secret_encrypted text NOT NULL,
  digits smallint NOT NULL DEFAULT 6,
  period smallint NOT NULL DEFAULT 30,
  confirmed boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS clients (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id text NOT NULL UNIQUE,
  name text NOT NULL,
  redirect_uris text[] NOT NULL,
  client_secret text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS passkey_credentials_created_at_idx ON passkey_credentials(created_at);
CREATE INDEX IF NOT EXISTS clients_created_at_idx ON clients(created_at);

-- 服务端会话（替代 KV login:*）
CREATE TABLE IF NOT EXISTS auth_sessions (
  sid text PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  persistent boolean NOT NULL DEFAULT false,
  password_ok boolean NOT NULL DEFAULT false,
  authenticated boolean NOT NULL DEFAULT false,
  auth_time timestamptz
);

CREATE INDEX IF NOT EXISTS auth_sessions_expires_at_idx ON auth_sessions(expires_at);

-- 授权请求（替代 KV authreq:*）
CREATE TABLE IF NOT EXISTS oidc_auth_requests (
  id text PRIMARY KEY,
  client_id text NOT NULL,
  redirect_uri text NOT NULL,
  scope text NOT NULL,
  state text NOT NULL,
  code_challenge text,
  code_challenge_method text,
  nonce text,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS oidc_auth_requests_expires_at_idx ON oidc_auth_requests(expires_at);

-- 授权码（只存 SHA-256 哈希）
CREATE TABLE IF NOT EXISTS oidc_authorization_codes (
  code_hash text PRIMARY KEY,
  client_id text NOT NULL,
  redirect_uri text NOT NULL,
  scope text NOT NULL,
  code_challenge text,
  nonce text,
  subject text NOT NULL,
  auth_time timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz
);

CREATE INDEX IF NOT EXISTS oidc_authorization_codes_expires_at_idx ON oidc_authorization_codes(expires_at);

-- 不透明 access token（只存 SHA-256 哈希）
CREATE TABLE IF NOT EXISTS oidc_access_tokens (
  token_hash text PRIMARY KEY,
  subject text NOT NULL,
  scope text NOT NULL,
  client_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS oidc_access_tokens_expires_at_idx ON oidc_access_tokens(expires_at);

-- WebAuthn 挑战（单次消费）
CREATE TABLE IF NOT EXISTS webauthn_challenges (
  id text PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('register', 'login')),
  challenge text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS webauthn_challenges_expires_at_idx ON webauthn_challenges(expires_at);

-- 登录失败限速（按 IP）
CREATE TABLE IF NOT EXISTS login_rate_limits (
  ip text PRIMARY KEY,
  failures integer NOT NULL,
  expires_at timestamptz NOT NULL
);

-- OIDC 签名密钥（单行）
CREATE TABLE IF NOT EXISTS oidc_signing_keys (
  id boolean PRIMARY KEY DEFAULT true,
  kid text NOT NULL,
  private_jwk jsonb NOT NULL,
  public_jwk jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- 管理员身份资料（单行）：首次使用由 /setup 初始化
CREATE TABLE IF NOT EXISTS admin_profile (
  id boolean PRIMARY KEY DEFAULT true,
  subject text NOT NULL,
  display_name text NOT NULL DEFAULT '',
  email text,
  password_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
