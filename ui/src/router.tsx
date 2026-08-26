import {
  Link,
  Outlet,
  createRootRoute,
  createRoute,
  createRouter
} from "@tanstack/react-router";
import { useState } from "react";

import { Timestamp } from "./components/Status";
import { useOperator } from "./operator-context";
import {
  ApprovalsPage,
  AuditPage,
  EffectsPage,
  EvaluationsPage,
  InvestigationPage,
  MemoryPage,
  ModelsPage,
  OverviewPage,
  ProtocolPeersPage,
  ReplayPage,
  SandboxesPage
} from "./pages";
import { redactError } from "./safety";

const navigation = [
  ["/", "Overview"],
  ["/investigation", "Investigation"],
  ["/models", "Models"],
  ["/approvals", "Approvals"],
  ["/effects", "Effects"],
  ["/sandboxes", "Sandboxes"],
  ["/memory", "Memory"],
  ["/evaluations", "Evaluations"],
  ["/audit", "Audit"],
  ["/replay", "Replay"],
  ["/protocol-peers", "Protocol peers"]
] as const;

function RootLayout() {
  const { session, snapshot, isFetching, pollingStatus, serverNow, switchTenant } =
    useOperator();
  const [tenantError, setTenantError] = useState<string | null>(null);
  const stale = Date.parse(serverNow) >= Date.parse(snapshot.stale_after);
  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>
      <header className="topbar">
        <div>
          <span className="product">Aegis</span>
          <span className="environment">Operator workspace · synthetic checkout</span>
        </div>
        <div className="session-controls">
          <label htmlFor="tenant-switcher">Tenant</label>
          <select
            id="tenant-switcher"
            value={session.tenant_id}
            onChange={(event) => {
              setTenantError(null);
              void switchTenant(event.target.value).catch((error: unknown) => {
                setTenantError(redactError(error));
              });
            }}
          >
            {session.available_tenants.map((tenant) => (
              <option key={tenant} value={tenant}>
                {tenant}
              </option>
            ))}
          </select>
          <span>{session.user.display_name}</span>
        </div>
      </header>
      <nav aria-label="Operator workspace" className="primary-nav">
        {navigation.map(([to, label]) => (
          <Link key={to} to={to} activeProps={{ "aria-current": "page" }}>
            {label}
          </Link>
        ))}
      </nav>
      <div className="freshness" aria-live="polite" role="status">
        {pollingStatus ??
          (isFetching
            ? "Refreshing bounded server projections…"
            : stale
              ? "Data is stale. Do not make decisions until refresh succeeds."
              : "Current as of ")}
        {!isFetching && pollingStatus === null && !stale ? (
          <Timestamp value={snapshot.generated_at} />
        ) : null}
        {snapshot.synthetic ? " · deterministic synthetic data" : null}
        {tenantError === null ? null : ` · ${tenantError}`}
      </div>
      <main id="main-content" tabIndex={-1}>
        <Outlet />
      </main>
      <footer>
        UI state is derived only. Policy, ledgers, approvals, and effects remain
        server-authoritative.
      </footer>
    </div>
  );
}

const rootRoute = createRootRoute({ component: RootLayout });
const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: OverviewPage
});
const investigationRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/investigation",
  component: InvestigationPage
});
const modelsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/models",
  component: ModelsPage
});
const approvalsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/approvals",
  component: ApprovalsPage
});
const effectsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/effects",
  component: EffectsPage
});
const sandboxesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sandboxes",
  component: SandboxesPage
});
const memoryRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/memory",
  component: MemoryPage
});
const evaluationsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/evaluations",
  component: EvaluationsPage
});
const auditRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/audit",
  component: AuditPage
});
const replayRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/replay",
  component: ReplayPage
});
const protocolPeersRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/protocol-peers",
  component: ProtocolPeersPage
});

const routeTree = rootRoute.addChildren([
  indexRoute,
  investigationRoute,
  modelsRoute,
  approvalsRoute,
  effectsRoute,
  sandboxesRoute,
  memoryRoute,
  evaluationsRoute,
  auditRoute,
  replayRoute,
  protocolPeersRoute
]);

export const router = createRouter({
  routeTree,
  defaultPreload: "intent",
  defaultPreloadStaleTime: 30_000
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
