// uni-auth 共享客户端工具（无构建步骤，各页面 <script src> 直接引用）

/** 按 id 取元素 */
function $(id) {
  return document.getElementById(id);
}

/** HTML 转义 */
function esc(s) {
  return String(s).replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
}

/** unix 秒 → 本地时间 */
function fmtTime(unix) {
  return unix ? new Date(unix * 1000).toLocaleString() : "未使用";
}

/** 处理 JSON 请求：未认证会话跳转登录，并在登录后回到当前页面 */
async function requestJson(path, options = {}) {
  const res = await fetch(path, options);
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && data.error === "unauthorized") {
    const returnTo = location.pathname + location.search + location.hash;
    location.href = "/login?expired=1&return_to=" + encodeURIComponent(returnTo);
  }
  if (!res.ok) throw new Error(data.error || res.status);
  return data;
}

/** JSON POST 助手：非 2xx 抛 Error(message=data.error) */
async function api(path, body) {
  return requestJson(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body || {}),
  });
}

// —— base64url ↔ ArrayBuffer ——
function b64uToBuf(s) {
  const b = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b + "=".repeat((4 - (b.length % 4)) % 4));
  const a = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
  return a.buffer;
}

function bufToB64u(buf) {
  const u = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** base64url → JSON（解析 id_token 分段等） */
function b64uJson(s) {
  const b = s.replace(/-/g, "+").replace(/_/g, "/");
  return JSON.parse(atob(b + "=".repeat((4 - (b.length % 4)) % 4)));
}

/** WebAuthn options 预处理：challenge/凭证 id 转 ArrayBuffer */
function preflight(opts) {
  opts.challenge = b64uToBuf(opts.challenge);
  for (const key of ["allowCredentials", "excludeCredentials"]) {
    if (opts[key]) opts[key].forEach((c) => (c.id = b64uToBuf(c.id)));
  }
  if (opts.user) opts.user.id = b64uToBuf(opts.user.id);
  return opts;
}
