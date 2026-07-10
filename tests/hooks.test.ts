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

  test("after hook records failed status when returned is an Error", async () => {
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

  test("before hook does not crash for sign-out", async () => {
    const plugin = auditLog({ storage });
    const [beforeHook] = plugin.hooks.before;

    const arg = makeHandlerArg("/sign-out");
    expect(beforeHook!.matcher(arg as unknown as HookEndpointContext)).toBe(true);

    await (beforeHook!.handler as Function)(arg);
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

  test("hook does not crash when storage write fails", async () => {
    const failStorage = {
      write: async () => { throw new Error("DB down"); },
    };

    const plugin = auditLog({ storage: failStorage });
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

  test("nonBlocking hooks run via runInBackground", async () => {
    const backgroundTasks: Promise<unknown>[] = [];
    const delayedStorage = {
      write: async (entry: any) => {
        await new Promise((r) => setTimeout(r, 50));
        storage.entries.push(entry);
      },
    };

    const plugin = auditLog({ storage: delayedStorage, nonBlocking: true });
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
