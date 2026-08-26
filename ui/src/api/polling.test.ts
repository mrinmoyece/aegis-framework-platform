import { ApiError } from "./client";
import { SnapshotPoller } from "./polling";
import { fixtureSnapshot } from "../test-fixtures";

describe("bounded snapshot polling", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    Object.defineProperty(navigator, "onLine", { configurable: true, value: true });
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      value: "visible"
    });
  });

  afterEach(() => vi.useRealTimers());

  it("deduplicates and rejects out-of-order snapshots", async () => {
    const fetchSnapshot = vi
      .fn()
      .mockResolvedValueOnce(fixtureSnapshot)
      .mockResolvedValueOnce(fixtureSnapshot)
      .mockResolvedValueOnce({
        ...fixtureSnapshot,
        generated_at: "2026-08-17T17:00:00Z"
      });
    const onSnapshot = vi.fn();
    const poller = new SnapshotPoller({
      tenantId: "tenant-acme",
      sessionGeneration: "session-fixture-1",
      fetchSnapshot,
      onSnapshot,
      onAuthenticationExpired: vi.fn(),
      onDegraded: vi.fn(),
      intervalMs: 100
    });
    poller.start();
    await poller.pollNow();
    await poller.pollNow();
    await poller.pollNow();
    expect(onSnapshot).toHaveBeenCalledOnce();
    poller.stop();
  });

  it("stops on authentication expiry and bounds reconnect status", async () => {
    const onAuthenticationExpired = vi.fn();
    const onDegraded = vi.fn();
    const fetchSnapshot = vi
      .fn()
      .mockRejectedValue(new ApiError("authentication", "Session expired.", 401, false));
    const poller = new SnapshotPoller({
      tenantId: "tenant-acme",
      sessionGeneration: "session-fixture-1",
      fetchSnapshot,
      onSnapshot: vi.fn(),
      onAuthenticationExpired,
      onDegraded,
      intervalMs: 100
    });
    poller.start();
    await poller.pollNow();
    expect(onAuthenticationExpired).toHaveBeenCalledOnce();
    expect(fetchSnapshot).toHaveBeenCalledOnce();
  });

  it("fails closed when a cross-tab session changes tenant context", async () => {
    const onAuthenticationExpired = vi.fn();
    const onSnapshot = vi.fn();
    const poller = new SnapshotPoller({
      tenantId: "tenant-acme",
      sessionGeneration: "session-fixture-1",
      fetchSnapshot: vi.fn().mockResolvedValue({
        ...fixtureSnapshot,
        tenant_id: "tenant-beta",
        session_generation: "session-fixture-2"
      }),
      onSnapshot,
      onAuthenticationExpired,
      onDegraded: vi.fn(),
      intervalMs: 100
    });
    poller.start();
    await poller.pollNow();
    expect(onSnapshot).not.toHaveBeenCalled();
    expect(onAuthenticationExpired).toHaveBeenCalledOnce();
  });

  it("pauses offline and resumes on reconnect", async () => {
    Object.defineProperty(navigator, "onLine", { configurable: true, value: false });
    const onDegraded = vi.fn();
    const fetchSnapshot = vi.fn().mockResolvedValue(fixtureSnapshot);
    const poller = new SnapshotPoller({
      tenantId: "tenant-acme",
      sessionGeneration: "session-fixture-1",
      fetchSnapshot,
      onSnapshot: vi.fn(),
      onAuthenticationExpired: vi.fn(),
      onDegraded,
      intervalMs: 100
    });
    poller.start();
    await poller.pollNow();
    expect(fetchSnapshot).not.toHaveBeenCalled();
    expect(onDegraded).toHaveBeenCalledWith("Updates paused while offline or hidden.");
    Object.defineProperty(navigator, "onLine", { configurable: true, value: true });
    window.dispatchEvent(new Event("online"));
    await vi.advanceTimersByTimeAsync(0);
    expect(fetchSnapshot).toHaveBeenCalledOnce();
    poller.stop();
  });

  it("ignores AbortError when poll is cancelled mid-flight", async () => {
    const abortError = new DOMException("Aborted", "AbortError");
    const onDegraded = vi.fn();
    const poller = new SnapshotPoller({
      tenantId: "tenant-acme",
      sessionGeneration: "session-fixture-1",
      fetchSnapshot: vi.fn().mockRejectedValue(abortError),
      onSnapshot: vi.fn(),
      onAuthenticationExpired: vi.fn(),
      onDegraded,
      intervalMs: 100
    });
    poller.start();
    await poller.pollNow();
    // AbortError is swallowed — no degraded callback
    expect(onDegraded).not.toHaveBeenCalled();
    poller.stop();
  });

  it("exhausts retry bound after MAX_FAILURES transient errors", async () => {
    const onDegraded = vi.fn();
    const poller = new SnapshotPoller({
      tenantId: "tenant-acme",
      sessionGeneration: "session-fixture-1",
      fetchSnapshot: vi.fn().mockRejectedValue(new Error("transient")),
      onSnapshot: vi.fn(),
      onAuthenticationExpired: vi.fn(),
      onDegraded,
      intervalMs: 100
    });
    poller.start();
    // 4 = MAX_FAILURES
    for (let i = 0; i < 5; i++) {
      await poller.pollNow();
    }
    const calls = onDegraded.mock.calls.map((c) => c[0] as string | null);
    expect(calls.some((m) => m === "Live updates are reconnecting.")).toBe(true);
    expect(calls.some((m) => m === "Live updates exhausted their retry bound.")).toBe(
      true
    );
    poller.stop();
  });

  it("resumes after becoming visible", async () => {
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      value: "hidden"
    });
    const fetchSnapshot = vi.fn().mockResolvedValue(fixtureSnapshot);
    const poller = new SnapshotPoller({
      tenantId: "tenant-acme",
      sessionGeneration: "session-fixture-1",
      fetchSnapshot,
      onSnapshot: vi.fn(),
      onAuthenticationExpired: vi.fn(),
      onDegraded: vi.fn(),
      intervalMs: 100
    });
    poller.start();
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      value: "visible"
    });
    document.dispatchEvent(new Event("visibilitychange"));
    await vi.advanceTimersByTimeAsync(0);
    expect(fetchSnapshot).toHaveBeenCalledOnce();
    poller.stop();
  });
});
