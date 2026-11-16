export type ProvingPriority = 0 | 1;

interface Waiter {
  readonly priority: ProvingPriority;
  readonly resolve: (release: () => void) => void;
  readonly reject: (err: Error) => void;
  readonly cleanup: () => void;
  settled: boolean;
}

export interface SemaphoreStats {
  readonly activeProves: number;
  readonly maxConcurrency: number;
  readonly queuedHigh: number;
  readonly queuedNormal: number;
}

export class ProvingSemaphore {
  private readonly maxConcurrency: number;
  private activeCount = 0;
  private readonly highQueue: Waiter[] = [];
  private readonly normalQueue: Waiter[] = [];

  public constructor(maxConcurrency = 2) {
    if (!Number.isInteger(maxConcurrency) || maxConcurrency < 1) {
      throw new RangeError("maxConcurrency must be a positive integer");
    }
    this.maxConcurrency = maxConcurrency;
  }

  public getStats(): SemaphoreStats {
    return {
      activeProves: this.activeCount,
      maxConcurrency: this.maxConcurrency,
      queuedHigh: this.highQueue.length,
      queuedNormal: this.normalQueue.length,
    };
  }

  public async acquire(priority: ProvingPriority = 1, signal?: AbortSignal): Promise<() => void> {
    if (signal?.aborted) {
      throw new Error("PROVING_QUEUE_ABORTED");
    }

    if (this.activeCount < this.maxConcurrency) {
      this.activeCount += 1;
      return this.makeReleaseFn();
    }

    return new Promise<() => void>((resolve, reject) => {
      const targetQueue = priority === 0 ? this.highQueue : this.normalQueue;

      const onAbort = (): void => {
        if (waiter.settled) {
          return;
        }
        waiter.settled = true;
        const idx = targetQueue.indexOf(waiter);
        if (idx >= 0) {
          targetQueue.splice(idx, 1);
        }
        reject(new Error("PROVING_QUEUE_ABORTED"));
      };

      const waiter: Waiter = {
        priority,
        resolve,
        reject,
        cleanup: () => {
          signal?.removeEventListener("abort", onAbort);
        },
        settled: false,
      };

      signal?.addEventListener("abort", onAbort, { once: true });
      targetQueue.push(waiter);
    });
  }

  private makeReleaseFn(): () => void {
    let released = false;
    return () => {
      if (released) {
        return;
      }
      released = true;
      this.activeCount = Math.max(0, this.activeCount - 1);
      this.dispatchNext();
    };
  }

  private dispatchNext(): void {
    while (this.activeCount < this.maxConcurrency) {
      const nextWaiter = this.highQueue.shift() ?? this.normalQueue.shift();
      if (nextWaiter === undefined) {
        return;
      }
      if (nextWaiter.settled) {
        continue;
      }
      nextWaiter.settled = true;
      nextWaiter.cleanup();
      this.activeCount += 1;
      nextWaiter.resolve(this.makeReleaseFn());
      return;
    }
  }
}
