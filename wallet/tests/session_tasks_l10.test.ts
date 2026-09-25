// @vitest-environment node
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  SessionCancelledError,
  SessionTaskOwner,
} from "../src/session/taskOwner";
import { fetchCapped } from "../src/zk/artifacts";

afterEach(() => { vi.restoreAllMocks(); });

describe("L10 session task ownership", () => {
  it("cancels a hung callback promptly, deregisters it, and allows a fresh generation", async () => {
    const owner = new SessionTaskOwner();
    let started = false;
    const hung = owner.run(async () => {
      started = true;
      return await new Promise<number>(() => undefined);
    });
    await vi.waitFor(() => expect(started).toBe(true));
    expect(owner.size).toBe(1);

    owner.renew();
    await expect(hung).rejects.toBeInstanceOf(SessionCancelledError);
    expect(owner.size).toBe(0);
    await expect(owner.run(async () => 7)).resolves.toBe(7);
    expect(owner.size).toBe(0);
  });

  it("cancellation before callback creation never starts it", async () => {
    const owner = new SessionTaskOwner();
    owner.cancel();
    const work = vi.fn(async () => 1);
    await expect(owner.run(work)).rejects.toBeInstanceOf(SessionCancelledError);
    expect(work).not.toHaveBeenCalled();
  });

  it("refuses an old captured generation before starting newly registered work", async () => {
    const owner = new SessionTaskOwner();
    const captured = owner.signal;
    owner.renew();
    const work = vi.fn(async () => 1);
    await expect(owner.run(work, captured)).rejects.toBeInstanceOf(SessionCancelledError);
    expect(work).not.toHaveBeenCalled();
    expect(owner.size).toBe(0);
  });

  it("registration after cancellation disposes immediately and cleanup remains reentrant", () => {
    const owner = new SessionTaskOwner();
    owner.cancel();
    const dispose = vi.fn();
    const unregister = owner.register(dispose);
    unregister();
    owner.cancel();
    expect(dispose).toHaveBeenCalledTimes(1);
    expect(owner.size).toBe(0);
  });

  it("one throwing disposer cannot preserve later resources", () => {
    const owner = new SessionTaskOwner();
    const later = vi.fn();
    owner.register(() => {
      throw new Error("cleanup failed");
    });
    owner.register(later);
    expect(() => owner.cancel()).not.toThrow();
    expect(later).toHaveBeenCalledOnce();
    expect(owner.size).toBe(0);
  });
});

describe("L10 artifact cancellation", () => {
  it("settles a hung fetch even when the fetch implementation ignores AbortSignal", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(
      async () => await new Promise<Response>(() => undefined),
    );
    const controller = new AbortController();
    const pending = fetchCapped("/hung", 16, controller.signal);
    controller.abort();
    await expect(pending).rejects.toBeInstanceOf(SessionCancelledError);
  });

  it("does not await a stalled reader cancel and releases the reader on abort", async () => {
    const reader = {
      read: vi.fn(async () => await new Promise<ReadableStreamReadResult<Uint8Array>>(() => undefined)),
      cancel: vi.fn(() => new Promise<void>(() => undefined)),
      releaseLock: vi.fn(),
    };
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      body: { getReader: () => reader },
    } as unknown as Response);
    const controller = new AbortController();
    const pending = fetchCapped("/hung-stream", 16, controller.signal);
    await vi.waitFor(() => expect(reader.read).toHaveBeenCalledOnce());
    controller.abort();
    await expect(pending).rejects.toBeInstanceOf(SessionCancelledError);
    expect(reader.cancel).toHaveBeenCalledOnce();
    expect(reader.releaseLock).toHaveBeenCalledOnce();
  });
});
