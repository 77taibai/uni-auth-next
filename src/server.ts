import { createApp } from "./app";
import { loadDotenv } from "./config/dotenv";
import { loadConfig } from "./config/env";

// 本地开发入口：Vercel 不会调用 listen
loadDotenv();
const config = loadConfig();
const app = createApp(config);
const port = Number(process.env.PORT ?? 3000);

app.listen(port, () => {
  console.log(`uni-auth listening on ${config.publicOrigin} (local port ${port})`);
});
