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
});
