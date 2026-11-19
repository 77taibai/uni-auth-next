import { closePool } from "../src/db/pool";
import { loadDotenv } from "../src/config/dotenv";
import { loadConfig } from "../src/config/env";
import { createProfile, updateProfile, updatePasswordHash, getProfile } from "../src/db/repositories/profileRepository";
import { PASSWORD_HASH_RE } from "../src/config/env";

/**
 * 初始化/更新管理员身份（写入数据库 admin_profile）。
 *
 * 用法：
 *   npx tsx scripts/set-admin.ts --password "你的密码"            # 首次创建
 *   npx tsx scripts/set-admin.ts --name 太白 --email a@b.com      # 修改资料
 *   npx tsx scripts/set-admin.ts --password "新密码" --reset      # 重置密码
 *
 * 日常使用请优先走 /setup 与管理台；此脚本用于无浏览器环境或运维场景。
 */
type Args = { password?: string; name?: string; email?: string; reset: boolean; subject?: string };

function parseArgs(argv: string[]): Args {
  const args: Args = { reset: false };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--password") args.password = argv[++i];
    else if (flag === "--name") args.name = argv[++i];
    else if (flag === "--email") args.email = argv[++i];
    else if (flag === "--subject") args.subject = argv[++i];
    else if (flag === "--reset") args.reset = true;
  }
  return args;
}

async function main(): Promise<void> {
  loadDotenv();
  const config = loadConfig();
  const args = parseArgs(process.argv.slice(2));
  const existing = await getProfile();

  if (args.password && args.password.length < 8) throw new Error("password must be at least 8 characters");

  if (!existing) {
    if (!args.password) throw new Error("no profile yet: provide --password to initialize");
    const { hashPassword } = await import("../src/security/crypto");
    await createProfile({
      subject: args.subject ?? "me",
      displayName: args.name ?? "管理员",
      email: args.email ?? null,
      passwordHash: hashPassword(args.password, config.pbkdf2Iterations),
    });
    console.log("profile created");
    return;
  }

  if (args.name !== undefined || args.email !== undefined) {
    await updateProfile({
      displayName: args.name ?? existing.display_name,
      email: args.email !== undefined ? args.email || null : existing.email,
    });
    console.log("profile updated");
  }

  if (args.password) {
    if (!args.reset) throw new Error("use --reset together with --password to change the password");
    const { hashPassword } = await import("../src/security/crypto");
    if (!PASSWORD_HASH_RE.test(existing.password_hash)) throw new Error("existing password_hash is malformed");
    await updatePasswordHash(hashPassword(args.password, config.pbkdf2Iterations));
    console.log("password updated");
  }

  if (!args.name && args.email === undefined && !args.password) {
    console.log("nothing to do; pass --password / --name / --email");
  }
}

main()
  .catch((err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exitCode = 1;
  })
  .finally(() => closePool());
