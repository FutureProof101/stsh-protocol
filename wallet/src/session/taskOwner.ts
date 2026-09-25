export class SessionCancelledError extends Error {
  constructor(message = "session work was cancelled") {
    super(message);
    this.name = "SessionCancelledError";
  }
}

export function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new SessionCancelledError();
}

export function raceSessionTask<T>(
  promise: Promise<T>,
  signal: AbortSignal | undefined,
  message = "session work was cancelled",
): Promise<T> {
  if (signal === undefined) return promise;
  if (signal.aborted) {
    void promise.catch(() => undefined);
    return Promise.reject(new SessionCancelledError(message));
  }
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const settle = (fn: () => void) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      fn();
    };
    const onAbort = () => settle(() => reject(new SessionCancelledError(message)));
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) {
      onAbort();
      return;
    }
    promise.then(
      (value) => settle(() => resolve(value)),
      (error: unknown) => settle(() => reject(error)),
    );
  });
}

/** Owns cancellable work for exactly one authenticated session era. */
export class SessionTaskOwner {
  private controller = new AbortController();
  private disposers = new Set<() => void>();
  private generation = 0;

  get signal(): AbortSignal {
    return this.controller.signal;
  }

  get size(): number {
    return this.disposers.size;
  }

  register(disposer: () => void): () => void {
    let active = true;
    const disposeOnce = () => {
      if (!active) return;
      active = false;
      this.disposers.delete(disposeOnce);
      disposer();
    };
    if (this.controller.signal.aborted) {
      disposeOnce();
      return () => undefined;
    }
    this.disposers.add(disposeOnce);
    return () => {
      if (!active) return;
      active = false;
      this.disposers.delete(disposeOnce);
    };
  }

  run<T>(work: (signal: AbortSignal) => Promise<T>, expectedSignal: AbortSignal = this.signal): Promise<T> {
    if (expectedSignal !== this.signal || expectedSignal.aborted) {
      return Promise.reject(new SessionCancelledError());
    }
    const signal = expectedSignal;
    const generation = this.generation;
    return new Promise<T>((resolve, reject) => {
      let settled = false;
      let unregister: () => void = () => undefined;
      const settle = (fn: () => void) => {
        if (settled) return;
        settled = true;
        unregister();
        fn();
      };
      unregister = this.register(() =>
        settle(() => reject(new SessionCancelledError())),
      );
      if (settled) return;
      Promise.resolve()
        .then(() => {
          throwIfAborted(signal);
          if (generation !== this.generation) throw new SessionCancelledError();
          return work(signal);
        })
        .then(
          (value) => settle(() => resolve(value)),
          (error: unknown) => settle(() => reject(error)),
        );
    });
  }
  cancel(): void {
    if (!this.controller.signal.aborted) this.controller.abort();
    for (const dispose of [...this.disposers]) {
      try {
        dispose();
      } catch {
        // One faulty cleanup must not preserve any later session resource.
      }
    }
  }

  renew(): void {
    // Advance this local-work epoch before aborting the prior generation.
    this.generation += 1;
    this.cancel();
    this.controller = new AbortController();
    this.disposers.clear();
  }
}
