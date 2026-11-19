import { createApp } from "../src/createApp.js";
import { loadConfig } from "../src/config/env.js";

// Vercel 入口：只负责导出 app，不调用 listen；配置在模块加载时校验一次
const app = createApp(loadConfig());

export default app;
