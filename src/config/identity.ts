export type Identity = {
  subject: string;
  displayName: string;
  email: string | null;
  passwordHash: string;
};

/** profile 范围下 name 的回退值（与旧系统一致） */
export function displayNameOf(identity: Pick<Identity, "displayName">): string {
  return identity.displayName || "管理员";
}
