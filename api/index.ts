import { createApp } from "../src/app";
import { loadConfig } from "../src/config/env";

// Vercel 入口：只负责导出 app，不调用 listen；配置在模块加载时校验一次
const app = createApp(loadConfig());

export default app;
