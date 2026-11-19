import type { NextFunction, Request, Response } from "express";

/** 结构化访问日志：只记录非敏感字段，不记录 body、Cookie、token */
export function requestLogger(enabled = process.env.NODE_ENV !== "test") {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!enabled) return next();
    const startedAt = process.hrtime.bigint();
    res.on("finish", () => {
      const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
      console.log(
        JSON.stringify({
          level: "info",
          requestId: req.id,
          method: req.method,
          path: req.path,
          status: res.statusCode,
          durationMs: Math.round(durationMs),
        })
      );
    });
    next();
  };
}
