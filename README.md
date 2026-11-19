# uni-auth

单管理员 **OIDC 身份提供方（IdP）**，运行在 **Vercel Node.js + Express + PostgreSQL** 上，为「个人自建平台 / 内部工具」提供统一登录。

身份资料与密码存于数据库（`admin_profile` 单行），首次使用通过 `/setup` 初始化；会话、授权请求、授权码、access token、WebAuthn 挑战、限速与签名密钥全部落在 PostgreSQL，Function 实例保持无状态。

## 特性

- **协议**：OAuth 2.0 Authorization Code + OIDC，PKCE（S256），ES256 签名 id_token，标准 discovery 与 JWKS
- **登录因素**：密码（PBKDF2）、TOTP（`otpauth` 兼容，密钥加密存储）、Passkey / WebAuthn（多设备）
- **安全基线**：Origin/CSRF 校验、按 IP 限速（5 次失败锁 15 分钟）、一次性授权码、`HttpOnly` + `SameSite=Lax` + 生产 `Secure` Cookie
- **管理台**：应用（OIDC 客户端）增删改查、个人信息、改密、TOTP、Passkey

## 目录结构

```text
uni-auth/
├─ api/index.ts               # Vercel 入口，只导出 app
├─ src/
│  ├─ app.ts                  # Express 装配与中间件顺序
│  ├─ server.ts               # 本地 listen
│  ├─ config/                 # env 校验、路径、dotenv
│  ├─ db/
│  │  ├─ pool.ts              # pg Pool（模块顶层复用）+ 事务助手
│  │  ├─ migrate.ts           # SQL runner（幂等）
│  │  ├─ migrations/          # PostgreSQL 迁移（单一 0001_init.sql）
│  │  └─ repositories/        # 各表的读写与单次消费
│  ├─ http/
│  │  ├─ controllers/         # 请求解析 → service → 响应映射
│  │  ├─ routes/              # web / setup / session / admin / oauth / health
│  │  ├─ middleware/          # Origin/CSRF、会话、认证 guard、Cookie
│  │  └─ validators/          # zod schema
│  ├─ services/               # auth、session、setup、totp、webauthn、oauth
│  ├─ security/               # crypto、密码、加密、JWT、TOTP
│  └─ views/                  # 页面模板（html/）与服务端错误页
├─ public/                    # 仅静态资源（assets/app.css、app.js），由 Vercel 托管
├─ scripts/                   # migrate、cleanup、set-admin
└─ test/                      # vitest + supertest（连接真实 PostgreSQL）
```

## 快速开始

前置：Node.js 20+，一个可用的 PostgreSQL。

```powershell
npm install

# 1. 配置环境变量
Copy-Item .env.example .env
# 编辑 .env：填入 DATABASE_URL、PUBLIC_ORIGIN、MASTER_KEY

# 2. 应用数据库迁移
npm run migrate

# 3. 本地启动
npm run dev
```

启动后访问 `http://localhost:3000/setup` 完成首次初始化（设置管理员密码），随后 `/login` 登录、`/admin` 管理。

### 常用脚本

| 脚本 | 说明 |
| --- | --- |
| `npm run dev` | `tsx watch` 本地服务器 |
| `npm run migrate` | 应用 `src/db/migrations/`（幂等） |
| `npm run set-admin -- --password "密码"` | 无浏览器环境下创建/修改管理员身份 |
| `npm run typecheck` | TypeScript 类型检查 |
| `npm test` | 运行测试（需要数据库） |

## 配置

| 名称 | 必填 | 说明 |
| --- | --- | --- |
| `DATABASE_URL` | ✅ | PostgreSQL 连接串；生产建议使用提供商的 pooled URL |
| `PUBLIC_ORIGIN` | ✅ | 站点对外源，例如 `https://auth.example.com`；**不依赖 Host 头** |
| `MASTER_KEY` | ✅ | 32 字节 base64，用于加密 TOTP 密钥。**丢失即无法解密既有 TOTP** |
| `PBKDF2_ITERATIONS` | ⬜ | `/setup` 与改密时使用的默认迭代次数，默认 `100000` |
| `DATABASE_SSL` | ⬜ | `require` / `disable`；也可用连接串 `sslmode` |
| `NODE_ENV` | ⬜ | `production` 时 Cookie 带 `Secure` 并启用 trust proxy |

> 环境变量只承载基础设施配置；身份资料与密码全部存于数据库 `admin_profile`，首次使用由 `/setup` 创建。
> 连接或密钥配置不完整会在启动时抛出错误。`MASTER_KEY`、`DATABASE_URL` 不得提交仓库，也不得写入 `vercel.json`。

## HTTP API

### 页面

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/` | 有会话跳 `/admin`，否则 `/login`；非 HTML 客户端 308 到 `/auth` |
| GET | `/setup` | 首次初始化页面；已初始化则跳 `/login` |
| GET | `/login` | 登录页面；未初始化时跳 `/setup` |
| GET | `/admin` | 管理控制台（需认证） |
| GET | `/oauth/consent` | 授权确认页（需认证） |

### 会话 / 管理 API

| 方法 | 路径 | 鉴权 | 说明 |
| --- | --- | --- | --- |
| GET | `/health` | — | 健康检查（含数据库探测） |
| POST | `/api/v1/setup` | Origin | 首次初始化（只能一次，密码 ≥ 8 位） |
| POST | `/api/v1/admin/profile` | Origin+会话 | 更新显示名与邮箱 |
| POST | `/api/v1/admin/password` | Origin+会话 | 改密（需旧密码；成功后作废当前会话） |
| POST | `/api/v1/session/password` | Origin | 密码登录，启用 TOTP 时返回 `{ "requires_totp": true }` |
| POST | `/api/v1/session/totp` | Origin+临时会话 | 完成 TOTP 二次认证 |
| POST | `/api/v1/session/passkey/options` | Origin | Passkey 登录选项 |
| POST | `/api/v1/session/passkey/verify` | Origin | 校验 Passkey 并建立会话 |
| DELETE | `/api/v1/session` | Origin+会话 | 注销 |
| GET | `/api/v1/admin/overview` | 会话 | 身份摘要、TOTP、Passkey、client、OIDC 地址 |
| POST | `/api/v1/admin/password` | Origin+会话 | 改密（需旧密码；成功后作废当前会话） |
| POST | `/api/v1/admin/totp/enroll` | Origin+会话 | 生成 TOTP（未确认） |
| POST | `/api/v1/admin/totp/confirm` | Origin+会话 | 确认 TOTP |
| DELETE | `/api/v1/admin/totp` | Origin+会话 | 停用 TOTP |
| POST | `/api/v1/admin/passkeys/options` | Origin+会话 | 注册选项 |
| POST | `/api/v1/admin/passkeys` | Origin+会话 | 保存 Passkey |
| PATCH | `/api/v1/admin/passkeys/:id` | Origin+会话 | 改名 |
| DELETE | `/api/v1/admin/passkeys/:id` | Origin+会话 | 删除 |
| POST | `/api/v1/admin/clients` | Origin+会话 | 创建 client |
| PATCH | `/api/v1/admin/clients/:id` | Origin+会话 | 修改名称 / 回调地址 |
| DELETE | `/api/v1/admin/clients/:id` | Origin+会话 | 删除 client |

所有 `POST`/`PATCH`/`DELETE` 均校验 `Origin === PUBLIC_ORIGIN`，不匹配返回 `403 { "error": "bad_origin" }`。

### OAuth / OIDC

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/.well-known/openid-configuration` | discovery |
| GET | `/oauth/authorize` | 创建授权请求 |
| POST | `/oauth/token` | authorization code 换 token |
| GET | `/oauth/userinfo` | Bearer access token |
| GET | `/oauth/jwks.json` | ES256 公钥 |
| GET | `/oauth/consent` | 确认页 |
| GET | `/oauth/consent/info?req=` | 应用名与 scope（不消费请求） |
| POST | `/oauth/consent/approve` | 确认并生成 code |
| POST | `/oauth/consent/deny` | 拒绝，回传 `error=access_denied` |

Discovery 中的 endpoint 使用上面的 `/oauth/*` 路径，`issuer` 为 `<PUBLIC_ORIGIN>/auth`。

- 授权码 **2 分钟**有效、**单次使用**；重放返回 `invalid_grant`。
- access token 不透明，**10 分钟**有效，服务端只存 SHA-256 哈希。
- id_token ES256，**5 分钟**有效，含 `iss/sub/aud/exp/iat/auth_time`，有 `nonce` 时写入，申请 `email` 且已配置邮箱时追加 `email`。
- PKCE 仅支持 `S256`；未带 challenge 的授权码不要求 `code_verifier`。
- client 有 secret 时支持 `client_secret_basic` 与 `client_secret_post`，Basic 优先。

## 安全设计

- 密码 PBKDF2-SHA256，常量时间比较；哈希格式带版本前缀。
- TOTP：6 位、30 秒、±1 窗口；密钥 AES-256-GCM 加密，AAD 绑定 `totp:totp`；确认后才生效。
- 会话：随机 sid，`HttpOnly` + `SameSite=Lax` + 生产 `Secure`；单次登录 24 小时兜底、永久登录一年。
- 登录限速：按可信代理解析的客户端 IP，连续 5 次失败锁定 15 分钟，成功清零；密码 / TOTP / Passkey 共用。
- 一次性消费全部使用事务 + `FOR UPDATE` 行锁，避免并发双花。
- WebAuthn 校验 RP ID、origin、challenge、签名与 counter 递增；挑战单次消费。
- 数据库只存授权码与 access token 的哈希，泄漏不直接得到可用凭据。
- 统一错误处理器记录 request ID，对客户端只返回稳定错误码。
- 首次初始化：`/setup` 只能创建一次（并发下由 `admin_profile` 单行约束保证），密码以 PBKDF2 哈希落库。
- 身份资料与密码只存于数据库；环境变量不再承载任何身份信息，因此不存在“环境变量覆盖数据库”的歧义。

## 测试

测试连接真实 PostgreSQL（默认读取 `.env` 的 `DATABASE_URL`，可在 CI 用环境变量覆盖）：

```powershell
npm test
```

覆盖面：密码哈希、AES-GCM、限速与锁定、Cookie 属性、discovery、authorize 校验分支、consent、PKCE、client secret（Basic/form）、token 重放、userinfo claims、TOTP 全流程、Passkey 注册/登录/限速、管理台 CRUD、页面与静态兜底。

> 测试会 `TRUNCATE` 业务表；请使用独立数据库或独立 schema，不要指向生产库。

## 部署到 Vercel

1. 在 Vercel 项目设置中配置上表全部环境变量（Preview 与 Production 使用**独立数据库**）。
2. **构建期自动建表**：`vercel.json` 的 `buildCommand` 为 `npm run typecheck && npm run migrate`，部署时会自动执行迁移；`migrate` 只需要 `DATABASE_URL`。
3. 使用 Vercel / 自定义域名作为 `PUBLIC_ORIGIN`；不要用 Preview 域名作为生产 issuer。
4. HTTPS 由平台终止，应用按 `PUBLIC_ORIGIN` 生成 issuer，并正确处理代理协议。

### ESM 导入必须带 `.js` 扩展名

项目是 `"type": "module"`，Vercel 的 Node 运行时按原生 ESM 解析，**不会**自动补全扩展名。
因此所有相对导入都要写成编译后的文件名：

```ts
import { createApp } from "./app.js";        // 源码是 app.ts，但必须写 .js
import { PUBLIC_DIR } from "./config/assets.js";
```

`tsconfig.json` 使用 `module`/`moduleResolution` = `NodeNext`，缺失扩展名会直接在
`npm run typecheck` 阶段报错，避免部署后才出现 `ERR_MODULE_NOT_FOUND`。
`tsx`、`vitest`、`tsc` 都会把 `.js` 映射回 `.ts`，因此本地开发与测试不受影响。

### 路由与静态资源

`vercel.json` 把以下路径重写到单一函数 `api/index.ts`：`/api/*`、`/oauth/*`、`/.well-known/*`、
`/setup`、`/login`、`/admin`、`/auth`、`/auth/*`、`/authorize`、`/token`、`/userinfo`、`/jwks`、
`/confirm`、`/health`。

- **页面模板**在 `src/views/html/`，由源码读取，并通过 `functions["api/index.ts"].includeFiles`
  显式打进函数包（Vercel 的 Node File Trace 追踪不到运行时读取的文件）。
- **`public/` 只放静态资源**（`assets/app.css`、`assets/app.js`），由 Vercel 静态托管并走 CDN。
  页面模板不放 `public/`，否则会被按路径直接对外输出、绕过会话校验。
- 数据库表尚未创建时（例如未配置 `DATABASE_URL` 导致 migrate 未执行），页面返回 500 而不会使
  函数实例崩溃；统一错误处理器会把异常转为稳定错误响应。

## 已知取舍

- 单管理员身份服务，多租户不是目标场景。
- 无刷新令牌；access token 10 分钟、id_token 5 分钟过期后重新走授权流程。
- `client_secret` 创建后不可修改，需要更换时删除并重建 client。
- 限速基于 IP，按数据库写入计费，不适合大规模流量。


