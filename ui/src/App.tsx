import {
  QueryClient,
  QueryClientProvider,
  useQuery,
  useQueryClient
} from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { Component, useEffect, useRef, useState, type ReactNode } from "react";

import { ApiError, operatorApi } from "./api/client";
import { assertSnapshotContext, SnapshotPoller } from "./api/polling";
import { OperatorContext } from "./operator-context";
import { router } from "./router";
import { redactError } from "./safety";

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: (count, error) => count < 2 && error instanceof ApiError && error.retryable,
      staleTime: 10_000,
      gcTime: 60_000,
      refetchOnWindowFocus: true,
      refetchOnReconnect: true
    },
    mutations: { retry: false }
  }
});

export function App() {
  return (
    <SafeErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <SessionBoundary />
      </QueryClientProvider>
    </SafeErrorBoundary>
  );
}

function SessionBoundary() {
  const client = useQueryClient();
  const [loginError, setLoginError] = useState<string | null>(null);
  const [pollingStatus, setPollingStatus] = useState<string | null>(null);
  // Ref to the active SnapshotPoller so switchTenant can stop it explicitly
  // before cancelling query-client queries (cancelQueries cannot reach the poller).
  const pollerRef = useRef<SnapshotPoller | null>(null);
  const sessionQuery = useQuery({
    queryKey: ["operator-session"],
    queryFn: ({ signal }) => operatorApi.session(signal),
    retry: false
  });
  const session = sessionQuery.data;
  const snapshotQuery = useQuery({
    queryKey: ["operator", session?.tenant_id, session?.session_generation],
    queryFn: async ({ signal }) => {
      if (session === undefined) throw new Error("operator session is unavailable");
      return assertSnapshotContext(
        await operatorApi.snapshot(signal),
        session.tenant_id,
        session.session_generation
      );
    },
    enabled: session !== undefined
  });

  useEffect(() => {
    if (session === undefined) return undefined;
    const poller = new SnapshotPoller({
      tenantId: session.tenant_id,
      sessionGeneration: session.session_generation,
      fetchSnapshot: (signal) => operatorApi.snapshot(signal),
      onSnapshot: (snapshot) => {
        client.setQueryData(
          ["operator", session.tenant_id, session.session_generation],
          snapshot
        );
      },
      onAuthenticationExpired: () => {
        client.removeQueries({ queryKey: ["operator"] });
        client.removeQueries({ queryKey: ["operator-session"] });
      },
      onDegraded: setPollingStatus
    });
    pollerRef.current = poller;
    poller.start();
    return () => {
      poller.stop();
      pollerRef.current = null;
    };
  }, [client, session]);
  const serverNow = useServerClock(session?.server_time);

  if (sessionQuery.isPending) return <Loading message="Checking the operator session…" />;
  if (session === undefined) {
    return (
      <main className="login">
        <section className="panel" aria-labelledby="login-title">
          <h1 id="login-title">Aegis operator workspace</h1>
          <p>
            Sign in through the same-origin BFF. No bearer token is stored in browser
            storage.
          </p>
          <button
            type="button"
            onClick={() => {
              setLoginError(null);
              void operatorApi
                .login()
                .then((value) => client.setQueryData(["operator-session"], value))
                .catch((error: unknown) => setLoginError(redactError(error)));
            }}
          >
            Sign in to deterministic demo
          </button>
          <p aria-live="assertive">{loginError}</p>
        </section>
      </main>
    );
  }
  if (snapshotQuery.isPending) return <Loading message="Loading bounded projections…" />;
  if (snapshotQuery.data === undefined) {
    return (
      <Failure
        message={redactError(snapshotQuery.error)}
        retry={() => void snapshotQuery.refetch()}
      />
    );
  }

  return (
    <OperatorContext.Provider
      value={{
        session,
        snapshot: snapshotQuery.data,
        isFetching: snapshotQuery.isFetching,
        pollingStatus,
        serverNow,
        switchTenant: async (tenantId: string) => {
          if (tenantId === session.tenant_id) return;
          // Stop the snapshot poller before switching tenants; cancelQueries()
          // cannot reach the independently managed SnapshotPoller.
          pollerRef.current?.stop();
          pollerRef.current = null;
          await client.cancelQueries();
          client.removeQueries({ queryKey: ["operator"] });
          const rotated = await operatorApi.switchTenant(tenantId, session.csrf_token);
          client.setQueryData(["operator-session"], rotated);
          await client.invalidateQueries({
            queryKey: ["operator", tenantId, rotated.session_generation]
          });
        }
      }}
    >
      <RouterProvider router={router} />
    </OperatorContext.Provider>
  );
}

function useServerClock(serverTime: string | undefined): string {
  const [now, setNow] = useState(serverTime ?? "1970-01-01T00:00:00Z");
  useEffect(() => {
    if (serverTime === undefined) return undefined;
    const serverStart = Date.parse(serverTime);
    const clientStart = Date.now();
    const tick = () => {
      setNow(new Date(serverStart + Date.now() - clientStart).toISOString());
    };
    const initial = window.setTimeout(tick, 0);
    const timer = window.setInterval(tick, 1_000);
    return () => {
      window.clearTimeout(initial);
      window.clearInterval(timer);
    };
  }, [serverTime]);
  return now;
}

function Loading({ message }: { message: string }) {
  return (
    <main className="center-state" aria-busy="true">
      <p role="status">{message}</p>
    </main>
  );
}

function Failure({ message, retry }: { message: string; retry: () => void }) {
  return (
    <main className="center-state">
      <section className="panel" role="alert">
        <h1>Operator data unavailable</h1>
        <p>{message}</p>
        <p>No mutation is treated as successful while state is unavailable.</p>
        <button type="button" onClick={retry}>
          Retry
        </button>
      </section>
    </main>
  );
}

class SafeErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  override state = { failed: false };

  static getDerivedStateFromError(): { failed: boolean } {
    return { failed: true };
  }

  override componentDidCatch(): void {
    // Intentionally no third-party telemetry or payload logging.
  }

  override render(): ReactNode {
    if (this.state.failed) {
      return (
        <main className="center-state">
          <section className="panel" role="alert">
            <h1>Workspace failed safely</h1>
            <p>Reload to request fresh server-authoritative state.</p>
          </section>
        </main>
      );
    }
    return this.props.children;
  }
}
