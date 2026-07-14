import { describe, test, expect, mock, beforeEach } from "bun:test";
import { APIError } from "better-auth/api";
import { MemoryStorage } from "../src/adapters/memory";
import { auditLog } from "../src/plugin";
import type { HookEndpointContext } from "@better-auth/core";

describe("hook execution", () => {
  let storage: MemoryStorage;

  beforeEach(() => {
    storage = new MemoryStorage();
  });

  function makeHandlerArg(
    path: string,
    overrides: Record<string, unknown> = {},
  ) {
    const backgroundTasks: Promise<unknown>[] = [];
    return {
      path,
      request: new Request("http://localhost" + path),
      headers: new Headers({ "user-agent": "test-agent" }),
      body: undefined,
      context: {
        session: { user: { id: "user-1" } },
        newSession: undefined,
        returned: undefined,
        logger: {
          error: mock(() => {}),
          warn: mock(() => {}),
          info: mock(() => {}),
          debug: mock(() => {}),
        },
        runInBackground: (p: Promise<unknown>) => backgroundTasks.push(p),
        options: {},
        ...overrides,
      },
      _backgroundTasks: backgroundTasks,
    };
  }

  test("after hook creates a log entry for sign-in", async () => {
    const plugin = auditLog({ storage });
    const [afterHook] = plugin.hooks.after;

    const arg = makeHandlerArg("/sign-in/email");
    expect(afterHook!.matcher(arg as unknown as HookEndpointContext)).toBe(true);

    await (afterHook!.handler as Function)(arg);

    expect(storage.entries).toHaveLength(1);
    expect(storage.entries[0]?.action).toBe("sign-in:email");
    expect(storage.entries[0]?.userId).toBe("user-1");
    expect(storage.entries[0]?.status).toBe("success");
  });

  test("after hook defensively records failed when returned is a non-APIError Error", async () => {
    // Defensive path: better-auth re-throws unhandled non-APIErrors before the after hook runs,
    // so `returned` is never a plain Error in practice (see the hook's comment). This locks in the
    // safety net — if such an error ever did surface here, it's logged as a failure, not a success.
    const plugin = auditLog({ storage });
    const [afterHook] = plugin.hooks.after;

    const arg = makeHandlerArg("/sign-in/email", {
      returned: new Error("Invalid credentials"),
    });

    await (afterHook!.handler as Function)(arg);

    expect(storage.entries).toHaveLength(1);
    expect(storage.entries[0]?.status).toBe("failed");
    expect(storage.entries[0]?.metadata).toHaveProperty("error");
  });

  test("after hook records success for a redirect to the app (not a failure)", async () => {
    const plugin = auditLog({ storage });
    const [afterHook] = plugin.hooks.after;

    // better-auth throws a 302 to complete a flow; that's a success, not a failure.
    const redirect = new APIError("FOUND", undefined, new Headers({ location: "/dashboard/error-corp" }));
    const arg = makeHandlerArg("/callback/oauth2", { returned: redirect });

    await (afterHook!.handler as Function)(arg);

    expect(storage.entries).toHaveLength(1);
    expect(storage.entries[0]?.status).toBe("success");
    expect(storage.entries[0]?.metadata).not.toHaveProperty("error");
  });

  test("after hook records failed with the error code for a redirect to the error page", async () => {
    const plugin = auditLog({ storage });
    const [afterHook] = plugin.hooks.after;

    // A redirect carrying ?error=<code> is a failure; the code/description are pulled from the URL.
    const redirect = new APIError(
      "FOUND",
      undefined,
      new Headers({ location: "/error?error=access_denied&error_description=request+denied" }),
    );
    const arg = makeHandlerArg("/callback/oauth2", { returned: redirect });

    await (afterHook!.handler as Function)(arg);

    expect(storage.entries).toHaveLength(1);
    expect(storage.entries[0]?.status).toBe("failed");
    expect(storage.entries[0]?.metadata).toMatchObject({
      error: { code: "access_denied", message: "request denied" },
    });
  });

  test("after hook omits the message for an error redirect that carries only a code", async () => {
    const plugin = auditLog({ storage });
    const [afterHook] = plugin.hooks.after;

    // Many OAuth error redirects are just ?error=<code> with no error_description.
    const redirect = new APIError(
      "FOUND",
      undefined,
      new Headers({ location: "/error?error=access_denied" }),
    );
    const arg = makeHandlerArg("/callback/oauth2", { returned: redirect });

    await (afterHook!.handler as Function)(arg);

    expect(storage.entries).toHaveLength(1);
    expect(storage.entries[0]?.status).toBe("failed");
    expect(storage.entries[0]?.metadata).toMatchObject({ error: { code: "access_denied" } });
    // No empty-string message is stored.
    expect(storage.entries[0]?.metadata).not.toHaveProperty("error.message");
  });

  test("after hook captures the error code from body.code (better-call APIError shape)", async () => {
    const plugin = auditLog({ storage });
    const [afterHook] = plugin.hooks.after;

    // better-call APIErrors expose the code on `body.code`, not a top-level `code`.
    const apiError = new APIError("BAD_REQUEST", { code: "INVALID_INPUT", message: "Invalid input" });
    const arg = makeHandlerArg("/sign-up/email", { returned: apiError });

    await (afterHook!.handler as Function)(arg);

    expect(storage.entries).toHaveLength(1);
    expect(storage.entries[0]?.status).toBe("failed");
    expect(storage.entries[0]?.metadata).toMatchObject({
      error: { status: "BAD_REQUEST", code: "INVALID_INPUT" },
    });
  });

  test("before hook records a sign-out with status 'requested'", async () => {
    const plugin = auditLog({ storage });
    const [beforeHook] = plugin.hooks.before;

    const arg = makeHandlerArg("/sign-out");
    expect(beforeHook!.matcher(arg as unknown as HookEndpointContext)).toBe(true);

    await (beforeHook!.handler as Function)(arg);

    expect(storage.entries).toHaveLength(1);
    expect(storage.entries[0]?.action).toBe("sign-out");
    // The write happens before the action runs, so the outcome isn't observed.
    expect(storage.entries[0]?.status).toBe("requested");
  });

  test("after hook with null userId for unauthenticated context", async () => {
    const plugin = auditLog({ storage });
    const [afterHook] = plugin.hooks.after;

    const arg = makeHandlerArg("/sign-in/email", {
      session: undefined,
      newSession: undefined,
    });

    await (afterHook!.handler as Function)(arg);

    expect(storage.entries).toHaveLength(1);
    expect(storage.entries[0]?.userId).toBeNull();
  });

  test("background hook does not crash when storage write fails", async () => {
    const failStorage = {
      write: async () => { throw new Error("DB down"); },
    };

    const plugin = auditLog({ storage: failStorage, writeMode: "background" });
    const [afterHook] = plugin.hooks.after;

    const arg = makeHandlerArg("/sign-in/email");
    await (afterHook!.handler as Function)(arg);
  });

  test("after hook captures request body when configured", async () => {
    const plugin = auditLog({ storage, capture: { requestBody: true } });
    const [afterHook] = plugin.hooks.after;

    const arg = makeHandlerArg("/sign-in/email");
    arg.body = { email: "test@example.com" } as any;

    await (afterHook!.handler as Function)(arg);

    expect(storage.entries).toHaveLength(1);
    const meta = storage.entries[0]?.metadata as Record<string, unknown>;
    expect(meta.requestBody).toBeDefined();
  });

  test("after hook rethrows in sync-strict mode when storage write fails", async () => {
    const failStorage = {
      write: async () => { throw new Error("DB down"); },
    };

    const plugin = auditLog({ storage: failStorage, writeMode: "sync-strict" });
    const [afterHook] = plugin.hooks.after;

    const arg = makeHandlerArg("/sign-in/email");

    await expect(
      (afterHook!.handler as Function)(arg),
    ).rejects.toThrow("DB down");
  });

  test("before hook rethrows in sync-strict mode when storage write fails", async () => {
    const failStorage = {
      write: async () => { throw new Error("DB down"); },
    };

    const plugin = auditLog({ storage: failStorage, writeMode: "sync-strict" });
    const [beforeHook] = plugin.hooks.before;

    const arg = makeHandlerArg("/sign-out");

    await expect(
      (beforeHook!.handler as Function)(arg),
    ).rejects.toThrow("DB down");
  });

  test("after hook does not rethrow by default (writeMode defaults to sync-best-effort)", async () => {
    const failStorage = {
      write: async () => { throw new Error("DB down"); },
    };

    // No writeMode passed — the resolved default is sync-best-effort, so a write failure is
    // swallowed and the auth request still succeeds. Locks in the default the hooks depend on.
    const plugin = auditLog({ storage: failStorage });
    const [afterHook] = plugin.hooks.after;

    const arg = makeHandlerArg("/sign-in/email");
    await (afterHook!.handler as Function)(arg); // resolves, does not throw
  });

  test("after hook in sync-best-effort awaits the write but swallows failures", async () => {
    let attempted = false;
    const failStorage = {
      write: async () => {
        attempted = true;
        throw new Error("DB down");
      },
    };
    const onWriteError = mock(() => {});

    const plugin = auditLog({
      storage: failStorage,
      writeMode: "sync-best-effort",
      onWriteError,
    });
    const [afterHook] = plugin.hooks.after;

    const arg = makeHandlerArg("/sign-in/email");
    // Does not throw, but the write was attempted inline (not backgrounded) and reported.
    await (afterHook!.handler as Function)(arg);

    expect(attempted).toBe(true);
    expect(onWriteError).toHaveBeenCalledTimes(1);
    expect(arg._backgroundTasks).toHaveLength(0);
  });

  test("after hook rethrows the original error instance unchanged", async () => {
    const storageError = new Error("boom");
    const failStorage = {
      write: async () => { throw storageError; },
    };

    const plugin = auditLog({ storage: failStorage, writeMode: "sync-strict" });
    const [afterHook] = plugin.hooks.after;

    const arg = makeHandlerArg("/sign-in/email");

    // The exact error propagates so better-auth surfaces the real cause, not a wrapper.
    await expect((afterHook!.handler as Function)(arg)).rejects.toBe(storageError);
  });

  test("after hook does not rethrow when a transient write failure recovers within retries", async () => {
    let attempts = 0;
    const flakyStorage = {
      write: async (entry: any) => {
        attempts++;
        if (attempts === 1) throw new Error("transient blip");
        storage.entries.push(entry);
      },
    };

    const plugin = auditLog({ storage: flakyStorage, writeMode: "sync-strict" });
    const [afterHook] = plugin.hooks.after;

    const arg = makeHandlerArg("/sign-in/email");
    // First attempt throws, the retry succeeds — the handler resolves and the entry lands.
    // The hook only rethrows once retries are exhausted, so this must not throw.
    await (afterHook!.handler as Function)(arg);

    expect(attempts).toBe(2);
    expect(storage.entries).toHaveLength(1);
  });

  test("after hook rethrows when a beforeLog callback throws (non-storage path)", async () => {
    // beforeLog runs before the write and outside writeEntry's retry/onWriteError guard,
    // so this is a different failure route than a storage throw — it must still bubble up.
    const plugin = auditLog({
      storage,
      writeMode: "sync-strict",
      beforeLog: async () => { throw new Error("beforeLog blew up"); },
    });
    const [afterHook] = plugin.hooks.after;

    const arg = makeHandlerArg("/sign-in/email");

    await expect(
      (afterHook!.handler as Function)(arg),
    ).rejects.toThrow("beforeLog blew up");
  });

  test("after hook rethrows when an afterLog callback throws, even though the entry was written", async () => {
    const plugin = auditLog({
      storage,
      writeMode: "sync-strict",
      afterLog: async () => { throw new Error("afterLog blew up"); },
    });
    const [afterHook] = plugin.hooks.after;

    const arg = makeHandlerArg("/sign-in/email");

    // afterLog runs *after* the write, so the entry is persisted but the hook still throws —
    // the rethrow isn't tied to the write failing.
    await expect(
      (afterHook!.handler as Function)(arg),
    ).rejects.toThrow("afterLog blew up");
    expect(storage.entries).toHaveLength(1);
  });

  test("background hooks run via runInBackground", async () => {
    const backgroundTasks: Promise<unknown>[] = [];
    const delayedStorage = {
      write: async (entry: any) => {
        await new Promise((r) => setTimeout(r, 50));
        storage.entries.push(entry);
      },
    };

    const plugin = auditLog({ storage: delayedStorage, writeMode: "background" });
    const [afterHook] = plugin.hooks.after;

    const arg = makeHandlerArg("/sign-in/email", {
      runInBackground: (p: Promise<unknown>) => backgroundTasks.push(p),
    });

    await (afterHook!.handler as Function)(arg);

    // Entry not written yet — delayed write is in the background
    expect(storage.entries).toHaveLength(0);

    await Promise.all(backgroundTasks);
    expect(storage.entries).toHaveLength(1);
  });
});
