import { z } from "zod";

export const passwordLoginSchema = z.object({
  password: z.string(),
  remember: z.boolean().optional().default(false),
});

export const totpLoginSchema = z.object({
  code: z.string(),
});

export const passkeyVerifySchema = z.object({
  challengeId: z.string().min(1),
  remember: z.boolean().optional().default(false),
  response: z.record(z.unknown()),
});

export const setupSchema = z.object({
  password: z.string().min(8),
});

export const totpConfirmSchema = z.object({
  code: z.string(),
});

export const passkeyRegisterSchema = z.object({
  challengeId: z.string().min(1),
  name: z.string().optional(),
  response: z.record(z.unknown()),
});

export const passkeyRenameSchema = z.object({
  name: z.string().min(1),
});

export const consentSchema = z.object({
  req: z.string().min(1),
});

/** 仅允许 http/https，且必须可解析（与旧系统一致） */
export const redirectUrisSchema = z
  .array(z.string())
  .min(1, "at least one redirect_uri is required")
  .refine(
    (uris) =>
      uris.every((u) => {
        try {
          const parsed = new URL(u);
          return parsed.protocol === "https:" || parsed.protocol === "http:";
        } catch {
          return false;
        }
      }),
    "redirect_uris must be valid http or https URLs"
  );

export const clientCreateSchema = z.object({
  name: z.string().min(1),
  redirect_uris: redirectUrisSchema,
  client_secret: z.string().optional(),
});

export const clientUpdateSchema = z
  .object({
    name: z.string().min(1).optional(),
    redirect_uris: redirectUrisSchema.optional(),
  })
  .refine((v) => v.name !== undefined || v.redirect_uris !== undefined, "nothing to update");

/** 资料修改：display_name 必填 <= 80；email 可选 <= 254 且格式校验 */
export const profileUpdateSchema = z.object({
  display_name: z.string().trim().min(1, "display_name is required").max(80),
  email: z
    .string()
    .trim()
    .max(254)
    .optional()
    .default("")
    .refine((v) => v === "" || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v), "invalid email"),
});

/** 改密：需旧密码，新密码 >= 8 */
export const passwordChangeSchema = z.object({
  old_password: z.string().min(1),
  new_password: z.string().min(8),
});

export const tokenRequestSchema = z.object({
  grant_type: z.string(),
  code: z.string().optional().default(""),
  redirect_uri: z.string().optional().default(""),
  client_id: z.string().optional().default(""),
  client_secret: z.string().optional(),
  code_verifier: z.string().optional().default(""),
});

/** 安全解析请求体，失败返回 null（由 controller 映射 400） */
export function parseBody<S extends z.ZodTypeAny>(schema: S, body: unknown): z.output<S> | null {
  const result = schema.safeParse(body ?? {});
  return result.success ? (result.data as z.output<S>) : null;
}
