import { z } from "zod";

/** 哈希格式与旧系统保持一致：pbkdf2$sha256$<iter>$<salt>$<hash> */
export const PASSWORD_HASH_RE = /^pbkdf2\$sha256\$(\d+)\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$/;

/**
 * 环境变量只承载运行时基础设施配置。
 * 身份资料与密码全部存于数据库 admin_profile，不再由环境变量提供。
 */
const schema = z.object({
  DATABASE_URL: z.string().min(1, "DATABASE_URL is required"),
  PUBLIC_ORIGIN: z
    .string()
    .url("PUBLIC_ORIGIN must be an absolute URL")
    .refine((v) => {
      const u = new URL(v);
      return u.origin === v.replace(/\/$/, "");
    }, "PUBLIC_ORIGIN must be an origin without path, query or trailing slash"),
  MASTER_KEY: z
    .string()
    .min(1, "MASTER_KEY is required")
    .refine((v) => {
      try {
        return Buffer.from(v, "base64").length === 32;
      } catch {
        return false;
      }
    }, "MASTER_KEY must be 32 bytes encoded as base64"),
  PBKDF2_ITERATIONS: z
    .string()
    .optional()
    .transform((v) => {
      const n = parseInt(v ?? "", 10);
      return Number.isFinite(n) && n >= 1000 ? n : 100000;
    }),
  NODE_ENV: z.string().optional().default("development"),
});

export type AppConfig = {
  databaseUrl: string;
  publicOrigin: string;
  isProduction: boolean;
  masterKey: string;
  pbkdf2Iterations: number;
  publicOriginUrl: URL;
};

let cached: AppConfig | null = null;

function formatIssues(err: z.ZodError): string {
  return err.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; ");
}

/**
 * 启动校验：只校验基础设施配置是否完整。
 * 身份资料存在数据库，首次使用由 /setup 初始化。
 * 结果按进程缓存（Vercel 实例复用时避免重复解析）。
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const parsed = schema.safeParse(env);
  if (!parsed.success) throw new Error(`Invalid environment configuration: ${formatIssues(parsed.error)}`);

  const raw = parsed.data;
  const origin = raw.PUBLIC_ORIGIN.replace(/\/$/, "");
  const url = new URL(origin);
  if (/^https?:$/.test(url.protocol) === false) {
    throw new Error("PUBLIC_ORIGIN must use http or https");
  }

  return {
    databaseUrl: raw.DATABASE_URL,
    publicOrigin: origin,
    publicOriginUrl: url,
    isProduction: raw.NODE_ENV === "production",
    masterKey: raw.MASTER_KEY,
    pbkdf2Iterations: raw.PBKDF2_ITERATIONS,
  };
}

export function getConfig(): AppConfig {
  if (!cached) cached = loadConfig();
  return cached;
}

/** 仅供测试重置缓存 */
export function resetConfigCache(): void {
  cached = null;
}
