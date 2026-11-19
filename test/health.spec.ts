import { expect, it } from "vitest";
import { api } from "./helpers";

it("GET /health returns ok", async () => {
  const res = await api.get("/health");
  expect(res.status).toBe(200);
  expect(res.body).toEqual({ ok: true, name: "uni-auth" });
});

it("GET /healthz (legacy) is not served", async () => {
  const res = await api.get("/healthz");
  expect(res.status).toBe(404);
});
