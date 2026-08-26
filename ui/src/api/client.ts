import type { z } from "zod";

import {
  authorizationStartSchema,
  mutationReceiptSchema,
  sessionSchema,
  snapshotSchema,
  type ApprovalItem,
  type MutationReceipt,
  type OperatorSession,
  type OperatorSnapshot
} from "../contracts/schemas";

const MAX_RESPONSE_BYTES = 1_048_576;
const JSON_MEDIA_TYPE = /^application\/json(?:\s*;|$)/i;

function signalOption(signal?: AbortSignal): Pick<RequestInit, "signal"> {
  return signal === undefined ? {} : { signal };
}

export type ApiErrorKind =
  | "authentication"
  | "authorization"
  | "conflict"
  | "invalid-response"
  | "network"
  | "not-found"
  | "rate-limited"
  | "server"
  | "validation";

export class ApiError extends Error {
  constructor(
    readonly kind: ApiErrorKind,
    message: string,
    readonly status: number | null,
    readonly retryable: boolean
  ) {
    super(message);
    this.name = "ApiError";
  }
}

interface ApprovalDecision {
  command_id: string;
  disposition: "grant" | "deny";
  rationale: string;
  expected_status: "pending";
  plan_digest: string;
  approval_digest: string;
  typed_confirmation: string;
}

async function request<T>(
  path: string,
  schema: z.ZodType<T>,
  options: RequestInit = {}
): Promise<T> {
  let response: Response;
  const headers = new Headers(options.headers);
  headers.set("Accept", "application/json");
  if (options.body !== undefined) headers.set("Content-Type", "application/json");
  try {
    response = await fetch(path, {
      ...options,
      credentials: "same-origin",
      headers
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw error;
    }
    throw new ApiError("network", "The operator service is unreachable.", null, true);
  }
  const declaredLength = Number(response.headers.get("content-length") ?? "0");
  if (declaredLength > MAX_RESPONSE_BYTES) {
    throw new ApiError(
      "invalid-response",
      "The response exceeded its bound.",
      502,
      false
    );
  }
  // Read the body through a streaming reader so that chunked transfers without
  // a content-length header are still capped before the full body is buffered.
  let text: string;
  const body = response.body;
  if (body != null) {
    const decoder = new TextDecoder();
    const reader = body.getReader();
    let bytesRead = 0;
    const chunks: string[] = [];
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        bytesRead += value.byteLength;
        if (bytesRead > MAX_RESPONSE_BYTES) {
          await reader.cancel();
          throw new ApiError(
            "invalid-response",
            "The response exceeded its bound.",
            502,
            false
          );
        }
        chunks.push(decoder.decode(value, { stream: true }));
      }
      chunks.push(decoder.decode());
    } finally {
      reader.releaseLock();
    }
    text = chunks.join("");
  } else {
    text = await response.text();
  }
  if (!response.ok) {
    throw fromResponse(response.status);
  }
  const contentType = response.headers.get("content-type") ?? "";
  if (!JSON_MEDIA_TYPE.test(contentType)) {
    throw new ApiError(
      "invalid-response",
      "The response content type was not application/json.",
      502,
      false
    );
  }
  let payload: unknown;
  try {
    payload = text === "" ? null : JSON.parse(text);
  } catch {
    throw new ApiError(
      "invalid-response",
      "The response was not valid JSON.",
      502,
      false
    );
  }
  const parsed = schema.safeParse(payload);
  if (!parsed.success) {
    throw new ApiError(
      "invalid-response",
      "The response did not match the reviewed contract.",
      502,
      false
    );
  }
  return parsed.data;
}

function fromResponse(status: number): ApiError {
  if (status === 401)
    return new ApiError("authentication", "Session expired.", status, false);
  if (status === 403)
    return new ApiError(
      "authorization",
      "Server authority denied the request.",
      status,
      false
    );
  if (status === 404)
    return new ApiError("not-found", "The resource is unavailable.", status, false);
  if (status === 409)
    return new ApiError(
      "conflict",
      "The resource changed. Refresh before retrying.",
      status,
      false
    );
  if (status === 422)
    return new ApiError("validation", "The server rejected the request.", status, false);
  if (status === 429)
    return new ApiError("rate-limited", "The request was rate limited.", status, true);
  return new ApiError("server", "The service failed safely.", status, status >= 500);
}

export const operatorApi = {
  session(signal?: AbortSignal): Promise<OperatorSession> {
    return request("/operator/session", sessionSchema, signalOption(signal));
  },

  async login(signal?: AbortSignal): Promise<OperatorSession> {
    const start = await request(
      "/operator/session/authorization",
      authorizationStartSchema,
      { method: "POST", ...signalOption(signal) }
    );
    const callback = new URL(start.authorization_url, window.location.origin);
    const code = callback.searchParams.get("code");
    const state = callback.searchParams.get("state");
    if (code === null || state === null || state !== start.state) {
      throw new ApiError(
        "invalid-response",
        "The authorization response was not bound to this login.",
        502,
        false
      );
    }
    return request("/operator/session/callback", sessionSchema, {
      method: "POST",
      ...signalOption(signal),
      body: JSON.stringify({ code, state, code_verifier: start.code_verifier })
    });
  },

  snapshot(signal?: AbortSignal): Promise<OperatorSnapshot> {
    return request("/operator/api/snapshot", snapshotSchema, signalOption(signal));
  },

  switchTenant(
    tenantId: string,
    csrfToken: string,
    signal?: AbortSignal
  ): Promise<OperatorSession> {
    return request("/operator/session/tenant", sessionSchema, {
      method: "POST",
      ...signalOption(signal),
      headers: { "X-CSRF-Token": csrfToken },
      body: JSON.stringify({ tenant_id: tenantId })
    });
  },

  decideApproval(
    approval: ApprovalItem,
    decision: ApprovalDecision,
    csrfToken: string,
    signal?: AbortSignal
  ): Promise<MutationReceipt> {
    return request(
      `/operator/api/approvals/${encodeURIComponent(approval.approval_id)}/decisions`,
      mutationReceiptSchema,
      {
        method: "POST",
        ...signalOption(signal),
        headers: {
          "Idempotency-Key": decision.command_id,
          "X-CSRF-Token": csrfToken
        },
        body: JSON.stringify(decision)
      }
    );
  },

  async logout(csrfToken: string, signal?: AbortSignal): Promise<void> {
    const response = await fetch("/operator/session/logout", {
      method: "POST",
      credentials: "same-origin",
      headers: { "X-CSRF-Token": csrfToken },
      ...signalOption(signal)
    });
    if (!response.ok) throw fromResponse(response.status);
  }
};
