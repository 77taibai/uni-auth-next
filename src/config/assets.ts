import path from "node:path";
import { fileURLToPath } from "node:url";

/** 仅存放 CSS/JS 等静态资源；页面模板在 src/views/html 并由源码静态导入 */
export const PUBLIC_DIR = path.resolve(fileURLToPath(new URL("../../public", import.meta.url)));
