/** HTML 转义（服务端动态错误页专用） */
export function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** 服务端动态错误响应（其余页面均为 public/ 静态资源） */
export function errorPage(title: string, message: string): string {
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>uni-auth</title>
<link rel="icon" type="image/png" href="/favicon.png">
<link rel="stylesheet" href="/assets/app.css">
</head>
<body><main><h1>${esc(title)}</h1><p>${esc(message)}</p></main></body>
</html>`;
}
