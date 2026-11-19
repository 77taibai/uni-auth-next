import type { RequestHandler } from "express";

/** Express 4 无法捕获 async handler 的 rejection；统一包装后转交错误处理器 */
export function asyncHandler(fn: (...args: any[]) => unknown): RequestHandler {
  return (req, res, next) => {
    try {
      Promise.resolve(fn(req, res, next)).catch(next);
    } catch (err) {
      next(err);
    }
  };
}

/** 批量包装 controller 返回的 handler 映射 */
export function wrapHandlers<T extends Record<string, unknown>>(handlers: T): Record<string, RequestHandler> {
  const out: Record<string, RequestHandler> = {};
  for (const [key, handler] of Object.entries(handlers)) {
    out[key] = asyncHandler(handler as (...args: any[]) => unknown);
  }
  return out;
}
