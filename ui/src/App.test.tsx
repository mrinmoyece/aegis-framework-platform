import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { App } from "./App";
import { operatorApi } from "./api/client";
import { useOperator } from "./operator-context";
import { fixtureSession, fixtureSnapshot } from "./test-fixtures";

vi.mock("./api/client", async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  const client = actual["operatorApi"] as Record<string, unknown>;
  return { ...actual, operatorApi: { ...client } };
});

vi.mock("./api/polling", () => ({
  assertSnapshotContext: (_snap: unknown) => _snap,
  SnapshotPoller: class {
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    start() {}
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    stop() {}
  }
}));

vi.mock("./router", () => ({
  router: {
    history: { location: { pathname: "/" } },
    subscribe: () => () => undefined,
    getRouteById: () => undefined,
    buildLocation: () => ({ href: "/" }),
    isMatching: () => false,
    matchRoutes: () => [],
    state: { location: { pathname: "/" }, matches: [], status: "idle" }
  }
}));

describe("App loading and error states", () => {
  it("shows a loading indicator while the session is being fetched", async () => {
    vi.spyOn(operatorApi, "session").mockReturnValue(new Promise(() => undefined));
    render(<App />);
    expect(await screen.findByText("Checking the operator session…")).toBeVisible();
  });

  it("shows the login screen when session returns null (unauthenticated)", async () => {
    vi.spyOn(operatorApi, "session").mockRejectedValue(
      Object.assign(new Error("401"), { retryable: false })
    );
    render(<App />);
    expect(
      await screen.findByRole("button", { name: "Sign in to deterministic demo" })
    ).toBeVisible();
  });

  it("clicking Sign in calls operatorApi.login", async () => {
    const user = userEvent.setup();
    vi.spyOn(operatorApi, "session").mockRejectedValue(
      Object.assign(new Error("401"), { retryable: false })
    );
    const login = vi.spyOn(operatorApi, "login").mockResolvedValue(fixtureSession);
    render(<App />);
    await user.click(
      await screen.findByRole("button", { name: "Sign in to deterministic demo" })
    );
    expect(login).toHaveBeenCalledOnce();
  });

  it("shows a snapshot loading indicator while projections are being fetched", async () => {
    vi.spyOn(operatorApi, "session").mockResolvedValue(fixtureSession);
    vi.spyOn(operatorApi, "snapshot").mockReturnValue(new Promise(() => undefined));
    render(<App />);
    expect(await screen.findByText("Loading bounded projections…")).toBeVisible();
  });

  it("shows a failure panel when snapshot fetch errors out", async () => {
    vi.spyOn(operatorApi, "session").mockResolvedValue(fixtureSession);
    vi.spyOn(operatorApi, "snapshot").mockRejectedValue(
      Object.assign(new Error("Service unavailable"), { retryable: false })
    );
    render(<App />);
    expect(await screen.findByText("Operator data unavailable")).toBeVisible();
  });

  it("offers a Retry button in the failure panel", async () => {
    vi.spyOn(operatorApi, "session").mockResolvedValue(fixtureSession);
    vi.spyOn(operatorApi, "snapshot")
      .mockRejectedValueOnce(Object.assign(new Error("err"), { retryable: false }))
      .mockResolvedValue(fixtureSnapshot);
    render(<App />);
    expect(await screen.findByRole("button", { name: "Retry" })).toBeVisible();
  });
});

describe("useOperator null guard", () => {
  it("throws when rendered outside OperatorContext", () => {
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    function UsesOperator() {
      useOperator();
      return null;
    }
    expect(() => render(<UsesOperator />)).toThrow("operator context is unavailable");
    consoleSpy.mockRestore();
  });
});
