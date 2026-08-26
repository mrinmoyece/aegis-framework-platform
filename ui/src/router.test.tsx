import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  RouterProvider,
  createMemoryHistory,
  createRouter
} from "@tanstack/react-router";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type React from "react";

import { OperatorContext } from "./operator-context";
import { router as appRouter } from "./router";
import { fixtureSession, fixtureSnapshot } from "./test-fixtures";

// The router module exports a router with routeTree; to test RootLayout
// we use a memory history and inject OperatorContext.
function renderRouter(
  path = "/",
  ctxOverride: Partial<
    React.ComponentProps<typeof OperatorContext.Provider>["value"]
  > = {}
) {
  const history = createMemoryHistory({ initialEntries: [path] });
  const testRouter = createRouter({
    routeTree: appRouter.routeTree,
    history
  });
  return render(
    <QueryClientProvider client={new QueryClient()}>
      <OperatorContext.Provider
        value={{
          session: fixtureSession,
          snapshot: fixtureSnapshot,
          isFetching: false,
          pollingStatus: null,
          serverNow: fixtureSession.server_time,
          switchTenant: () => Promise.resolve(),
          ...ctxOverride
        }}
      >
        <RouterProvider router={testRouter} />
      </OperatorContext.Provider>
    </QueryClientProvider>
  );
}

describe("RootLayout navigation and shell", () => {
  it("renders skip-to-content link", async () => {
    renderRouter();
    expect(await screen.findByText("Skip to main content")).toBeInTheDocument();
  });

  it("renders the product name in the header", async () => {
    renderRouter();
    expect(await screen.findByText("Aegis")).toBeVisible();
  });

  it("renders navigation links for all sections", async () => {
    renderRouter();
    await screen.findByText("Overview");
    for (const label of [
      "Overview",
      "Investigation",
      "Models",
      "Approvals",
      "Effects",
      "Sandboxes",
      "Memory",
      "Evaluations",
      "Audit",
      "Replay"
    ]) {
      expect(screen.getByRole("link", { name: label })).toBeInTheDocument();
    }
  });

  it("renders the tenant switcher", async () => {
    renderRouter();
    expect(await screen.findByLabelText("Tenant")).toBeInTheDocument();
  });

  it("shows user display name in session controls", async () => {
    renderRouter();
    expect(await screen.findByText(fixtureSession.user.display_name)).toBeInTheDocument();
  });

  it("renders footer with server-authoritative disclaimer", async () => {
    renderRouter();
    expect(await screen.findByText(/server-authoritative/)).toBeInTheDocument();
  });

  it("renders freshness status region", async () => {
    renderRouter();
    // The freshness region has role="status" (aria-live="polite")
    expect(await screen.findByRole("status")).toBeInTheDocument();
  });

  it("renders tenant error when switchTenant rejects", async () => {
    const user = userEvent.setup();
    const history = createMemoryHistory({ initialEntries: ["/"] });
    const testRouter = createRouter({
      routeTree: appRouter.routeTree,
      history
    });
    const multiSession = {
      ...fixtureSession,
      tenant_id: "tenant-alpha",
      available_tenants: ["tenant-alpha", "tenant-beta"]
    };
    render(
      <QueryClientProvider client={new QueryClient()}>
        <OperatorContext.Provider
          value={{
            session: multiSession,
            snapshot: fixtureSnapshot,
            isFetching: false,
            pollingStatus: null,
            serverNow: multiSession.server_time,
            switchTenant: () => Promise.reject(new Error("switch denied"))
          }}
        >
          <RouterProvider router={testRouter} />
        </OperatorContext.Provider>
      </QueryClientProvider>
    );
    await screen.findByLabelText("Tenant");
    const select = screen.getByLabelText("Tenant");
    await user.selectOptions(select, "tenant-beta");
    // The error text is redacted for non-ApiError errors
    const statusRegion = await screen.findByRole("status");
    await vi.waitFor(() => {
      expect(statusRegion.textContent).toMatch(/operator workspace failed safely/);
    });
  });

  it("shows a pollingStatus message when provided", async () => {
    renderRouter("/", { pollingStatus: "Connection degraded – retrying…" });
    expect(await screen.findByText(/Connection degraded/)).toBeInTheDocument();
  });

  it("shows refreshing message when isFetching is true", async () => {
    renderRouter("/", { isFetching: true });
    expect(
      await screen.findByText(/Refreshing bounded server projections/)
    ).toBeInTheDocument();
  });

  it("shows stale warning when server time is past stale_after", async () => {
    const staleSnapshot = {
      ...fixtureSnapshot,
      stale_after: "2000-01-01T00:00:00Z"
    };
    renderRouter("/", {
      snapshot: staleSnapshot,
      serverNow: "2026-08-26T00:00:00Z"
    });
    expect(await screen.findByText(/Data is stale/)).toBeInTheDocument();
  });

  it("omits synthetic marker when snapshot.synthetic is false", async () => {
    renderRouter("/", {
      snapshot: { ...fixtureSnapshot, synthetic: false }
    });
    await screen.findByText("Skip to main content");
    expect(screen.queryByText(/deterministic synthetic data/)).toBeNull();
  });
});
