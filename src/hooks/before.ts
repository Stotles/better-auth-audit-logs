import { createAuthMiddleware, getSessionFromCtx } from "better-auth/api";
import type { HookEndpointContext } from "@better-auth/core";
import type { AuditLogEntry, ResolvedOptions } from "../types";
import { buildLogEntry, writeEntry } from "../internal";

export function createBeforeHooks(opts: ResolvedOptions, modelName: string) {
  return [
    {
      matcher: (context: HookEndpointContext) =>
        !!context.path &&
        opts.runBeforeHook(context.path) &&
        opts.shouldCapture(context.path),

      handler: createAuthMiddleware(async (ctx) => {
        // Build the entry under a guard for the setup phase (session resolution, entry build).
        // writeEntry owns its own logging / onWriteError / sync-strict rethrow, so it stays
        // outside this catch to avoid double-logging the same failure.
        let entry: Omit<AuditLogEntry, "id"> | undefined;
        try {
          const session = await getSessionFromCtx(ctx);
          const path = ctx.path!;
          const pathConfig = opts.getPathConfig(path);

          // before-hook entries record that the action was *requested*; the outcome is not
          // observed here since the write happens before the handler runs (and is never updated).
          entry = await buildLogEntry(path, "requested", {
            userId: session?.user?.id ?? null,
            request: ctx.request,
            headers: ctx.headers,
            pathConfig,
            options: opts,
            authOptions: ctx.context.options,
            logger: ctx.context.logger,
          });
        } catch (err) {
          ctx.context.logger?.error("[audit-log] before hook failed to build entry", err);
          if (opts.writeMode === "sync-strict") throw err;
          return;
        }

        await writeEntry(ctx, entry, opts, modelName);
      }),
    },
  ];
}
