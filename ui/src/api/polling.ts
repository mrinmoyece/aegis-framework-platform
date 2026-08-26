import { ApiError } from "./client";
import type { OperatorSnapshot } from "../contracts/schemas";

const MAX_FAILURES = 4;
const MAX_DELAY_MS = 30_000;

export interface SnapshotPollerOptions {
  tenantId: string;
  sessionGeneration: string;
  fetchSnapshot: (signal: AbortSignal) => Promise<OperatorSnapshot>;
  onSnapshot: (snapshot: OperatorSnapshot) => void;
  onAuthenticationExpired: () => void;
  onDegraded: (message: string | null) => void;
  intervalMs?: number;
}

export function assertSnapshotContext(
  snapshot: OperatorSnapshot,
  tenantId: string,
  sessionGeneration: string
): OperatorSnapshot {
  if (
    snapshot.tenant_id !== tenantId ||
    snapshot.session_generation !== sessionGeneration
  ) {
    throw new ApiError(
      "authentication",
      "The operator session context changed.",
      401,
      false
    );
  }
  return snapshot;
}

export class SnapshotPoller {
  private readonly intervalMs: number;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private controller: AbortController | null = null;
  private failures = 0;
  private watermark = 0;
  private running = false;

  constructor(private readonly options: SnapshotPollerOptions) {
    this.intervalMs = options.intervalMs ?? 10_000;
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    window.addEventListener("online", this.resume);
    document.addEventListener("visibilitychange", this.visibilityChanged);
    this.schedule(this.intervalMs);
  }

  stop(): void {
    this.running = false;
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
    this.controller?.abort();
    this.controller = null;
    window.removeEventListener("online", this.resume);
    document.removeEventListener("visibilitychange", this.visibilityChanged);
  }

  async pollNow(): Promise<void> {
    if (!this.running || this.controller !== null) return;
    if (!navigator.onLine || document.visibilityState === "hidden") {
      this.options.onDegraded("Updates paused while offline or hidden.");
      this.schedule(this.intervalMs);
      return;
    }
    this.controller = new AbortController();
    try {
      const snapshot = assertSnapshotContext(
        await this.options.fetchSnapshot(this.controller.signal),
        this.options.tenantId,
        this.options.sessionGeneration
      );
      const generation = Date.parse(snapshot.generated_at);
      if (Number.isNaN(generation)) throw new Error("invalid snapshot generation");
      if (generation > this.watermark) {
        this.watermark = generation;
        this.options.onSnapshot(snapshot);
      }
      this.failures = 0;
      this.options.onDegraded(null);
      this.schedule(this.intervalMs);
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") {
        return;
      }
      if (error instanceof ApiError && error.kind === "authentication") {
        this.stop();
        this.options.onAuthenticationExpired();
        return;
      }
      this.failures += 1;
      this.options.onDegraded(
        this.failures >= MAX_FAILURES
          ? "Live updates exhausted their retry bound."
          : "Live updates are reconnecting."
      );
      const delay = Math.min(
        MAX_DELAY_MS,
        this.intervalMs * 2 ** Math.min(this.failures, MAX_FAILURES)
      );
      this.schedule(delay);
    } finally {
      this.controller = null;
    }
  }

  private readonly resume = (): void => {
    if (!this.running) return;
    this.options.onDegraded(null);
    this.schedule(0);
  };

  private readonly visibilityChanged = (): void => {
    if (document.visibilityState === "visible") this.schedule(0);
  };

  private schedule(delay: number): void {
    if (!this.running) return;
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = setTimeout(() => {
      void this.pollNow();
    }, delay);
  }
}
