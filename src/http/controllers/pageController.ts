import type { Request, RequestHandler, Response } from "express";
import { renderView } from "../../config/paths";
import { errorPage } from "../../views/pages";
import { isInitialized } from "../../services/setupService";
import { getAuthRequest } from "../../db/repositories/authRequestRepository";
import { wrapHandlers } from "../middleware/async";

/** 页面路由：浏览器命中页面；根路径对非 HTML 客户端 308 到 discovery */
export function pageController() {
  return wrapHandlers({
    root: async (req: Request, res: Response) => {
      const acceptsHtml = req.headers.accept?.includes("text/html");
      if (!acceptsHtml) return res.redirect(308, "/auth");
      return res.redirect(req.session?.authenticated ? "/admin" : "/login");
    },

    loginPage: async (req: Request, res: Response) => {
      const reqId = typeof req.query.req === "string" ? req.query.req : undefined;
      const returnTo = typeof req.query.return_to === "string" ? req.query.return_to : undefined;

      if (req.session?.authenticated) {
        if (reqId) return res.redirect(`/oauth/consent?req=${encodeURIComponent(reqId)}`);
        if (returnTo && isSafeReturnTo(returnTo)) return res.redirect(returnTo);
        return res.redirect("/admin");
      }

      // 待确认的授权请求必须仍然有效，否则回错误页
      if (reqId && !(await getAuthRequest(reqId))) {
        return res
          .status(400)
          .type("html")
          .send(errorPage("链接已过期", "登录请求已过期或无效，请回到应用重新发起登录。"));
      }

      // 未初始化时先进入 /setup，并在成功后回到原授权请求
      if (!(await isInitialized())) {
        return res.redirect(withReq("/setup", reqId));
      }
      return res.type("html").send(renderView("login"));
    },

    adminPage: (_req: Request, res: Response) => {
      return res.type("html").send(renderView("admin"));
    },
  });
}

function withReq(path: string, req: string | undefined): string {
  return req ? `${path}?req=${encodeURIComponent(req)}` : path;
}

function isSafeReturnTo(value: string): boolean {
  return value.startsWith("/") && !value.startsWith("//");
}
