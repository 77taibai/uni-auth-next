import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

/**
 * 页面模板目录。模板通过 readFileSync 读取，因此必须在 vercel.json 的
 * functions.includeFiles 中显式包含（Vercel 的 Node File Trace 追踪不到运行时读取）。
 */
export const VIEWS_DIR = path.resolve(fileURLToPath(new URL("../views/html", import.meta.url)));

export type ViewName = "login" | "setup" | "consent" | "admin";

const cache = new Map<ViewName, string>();

export function renderView(name: ViewName): string {
  const cached = cache.get(name);
  if (cached) return cached;
  const html = readFileSync(path.join(VIEWS_DIR, `${name}.html`), "utf8");
  cache.set(name, html);
  return html;
}

