import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";

import { ApiError, operatorApi } from "./client";
import { fixtureSession, fixtureSnapshot } from "../test-fixtures";

const server = setupServer();
const nativeFetch = globalThis.fetch;

beforeAll(() => {
  globalThis.fetch = (input, init) => {
    const absolute =
      typeof input === "string" ? new URL(input, "http://localhost").toString() : input;
    return nativeFetch(absolute, init);
  };
  server.listen({ onUnhandledRequest: "error" });
});
afterEach(() => server.resetHandlers());
afterAll(() => {
  server.close();
  globalThis.fetch = nativeFetch;
});

describe("typed BFF client", () => {
  it("runtime-validates session and snapshot responses", async () => {
    server.use(
      http.get("*/operator/session", () => HttpResponse.json(fixtureSession)),
      http.get("*/operator/api/snapshot", () => HttpResponse.json(fixtureSnapshot))
    );
    await expect(operatorApi.session()).resolves.toEqual(fixtureSession);
    await expect(operatorApi.snapshot()).resolves.toEqual(fixtureSnapshot);
  });

  it("fails closed on schema drift and oversized responses", async () => {
    server.use(
      http.get("*/operator/session", () =>
        HttpResponse.json({ ...fixtureSession, bearer_token: "forbidden" })
      )
    );
    await expect(operatorApi.session()).rejects.toMatchObject({
      kind: "invalid-response",
      retryable: false
    });
    server.use(
      http.get(
        "*/operator/api/snapshot",
        () =>
          new HttpResponse("{}", {
            headers: { "content-length": "1048577" }
          })
      )
    );
    await expect(operatorApi.snapshot()).rejects.toBeInstanceOf(ApiError);
  });

  it("maps denial, conflict, and authentication without success fallbacks", async () => {
    for (const [status, kind] of [
      [401, "authentication"],
      [403, "authorization"],
      [409, "conflict"]
    ] as const) {
      server.use(
        http.get("*/operator/session", () => new HttpResponse(null, { status }))
      );
      await expect(operatorApi.session()).rejects.toMatchObject({ kind });
      server.resetHandlers();
    }
  });

  it("binds login state and sends CSRF/idempotency mutation headers", async () => {
    const state = "s".repeat(43);
    const approval = fixtureSnapshot.approvals[0];
    if (approval === undefined) throw new Error("approval fixture is unavailable");
    server.use(
      http.post("*/operator/session/authorization", () =>
        HttpResponse.json({
          authorization_url: `/operator/session/callback?code=demo&state=${state}`,
          state,
          nonce: "n".repeat(43),
          code_challenge: "p".repeat(43),
          code_challenge_method: "S256",
          expires_at: fixtureSession.expires_at
        })
      ),
      http.post("*/operator/session/callback", async ({ request }) => {
        await expect(request.json()).resolves.toEqual({ code: "demo", state });
        return HttpResponse.json(fixtureSession);
      }),
      http.post("*/operator/session/tenant", async ({ request }) => {
        expect(request.headers.get("x-csrf-token")).toBe(fixtureSession.csrf_token);
        await expect(request.json()).resolves.toEqual({ tenant_id: "tenant-beta" });
        return HttpResponse.json({ ...fixtureSession, tenant_id: "tenant-beta" });
      }),
      http.post("*/operator/api/approvals/approval-1/decisions", ({ request }) => {
        expect(request.headers.get("idempotency-key")).toBe("command-1");
        return HttpResponse.json({
          command_id: "command-1",
          outcome: "denied",
          message: "Server authority denied the request.",
          server_time: fixtureSession.server_time
        });
      }),
      http.post(
        "*/operator/session/logout",
        () => new HttpResponse(null, { status: 204 })
      )
    );
    await expect(operatorApi.login()).resolves.toEqual(fixtureSession);
    await expect(
      operatorApi.switchTenant("tenant-beta", fixtureSession.csrf_token)
    ).resolves.toMatchObject({ tenant_id: "tenant-beta" });
    await expect(
      operatorApi.decideApproval(
        approval,
        {
          command_id: "command-1",
          disposition: "grant",
          rationale: "Independent exact-scope review.",
          expected_status: "pending",
          plan_digest: approval.plan_digest,
          approval_digest: approval.approval_digest,
          typed_confirmation: "APPROVE CHECKOUT-API"
        },
        fixtureSession.csrf_token
      )
    ).resolves.toMatchObject({ outcome: "denied" });
    await expect(operatorApi.logout(fixtureSession.csrf_token)).resolves.toBeUndefined();
  });

  it("rejects invalid JSON responses", async () => {
    server.use(
      http.get("*/operator/session", () => new HttpResponse("not-json", { status: 200 }))
    );
    await expect(operatorApi.session()).rejects.toMatchObject({
      kind: "invalid-response"
    });
  });

  it("rejects responses that are not declared as application/json", async () => {
    server.use(
      http.get(
        "*/operator/session",
        () =>
          new HttpResponse(JSON.stringify(fixtureSession), {
            status: 200,
            headers: { "content-type": "text/plain" }
          })
      )
    );
    await expect(operatorApi.session()).rejects.toMatchObject({
      kind: "invalid-response",
      message: "The response content type was not application/json."
    });
  });
});
