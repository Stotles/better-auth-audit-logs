import { createAuthMiddleware, isAPIError, type APIError } from "better-auth/api";
import type { HookEndpointContext } from "@better-auth/core";
import type { AuditLogEntry, AuditLogStatus, ResolvedOptions } from "../types";
import { buildLogEntry, writeEntry } from "../internal";

type RedirectClassification =
  | { failed: false }
  // `message` is omitted when the error redirect has no `error_description` (many OAuth errors are
  // just `?error=<code>`), rather than storing an empty string.
  | { failed: true; error: { code: string; message?: string } };

/**
 * better-auth performs redirects by *throwing* an APIError with a 3xx statusCode (302 "FOUND") whose
 * destination is in a `location` header. A redirect is not itself a failure: flows such as the OAuth
 * callback succeed by redirecting to the app, and fail by redirecting to an error page carrying
 * `?error=<code>&error_description=<msg>` (the better-auth convention).
 * This function classifies if a thrown redirect is a failure or not and if it is, what the error code/message are.
 */
function classifyRedirect(err: APIError): RedirectClassification | null {
  const isRedirect = err.statusCode >= 300 && err.statusCode < 400;
  if (!isRedirect) return null;

  const location = new Headers(err.headers).get("location");
  if (!location) return { failed: false };

  // Try to extract the information from the URL
  try {
    const params = new URL(location, "http://localhost").searchParams;
    const code = params.get("error");
    if (!code) {
      return { failed: false };
    }

    const description = params.get("error_description");
    return { failed: true, error: { code, ...(description ? { message: description } : {}) } };
  } catch {
    return { failed: false };
  }
}

export function createAfterHooks(opts: ResolvedOptions, modelName: string) {
  return [
    {
      matcher: (context: HookEndpointContext) =>
        !!context.path &&
        !opts.runBeforeHook(context.path) &&
        opts.shouldCapture(context.path),

      handler: createAuthMiddleware(async (ctx) => {
        // Build the entry under a guard for the setup phase (reading ctx, inferring status).
        // writeEntry owns its own logging / onWriteError / sync-strict rethrow, so it stays
        // outside this catch to avoid double-logging the same failure.
        let entry: Omit<AuditLogEntry, "id"> | undefined;
        try {
          const path = ctx.path!;
          const returned = ctx.context.returned;

          const user =
            ctx.context.newSession?.user ?? ctx.context.session?.user;

          const pathConfig = opts.getPathConfig(path);

          const metadata: Record<string, unknown> = {};

          if (opts.capture.requestBody && ctx.body) {
            metadata.requestBody = ctx.body as Record<string, unknown>;
          }

          let status: AuditLogStatus = "success";

          if (isAPIError(returned)) {
            const redirect = classifyRedirect(returned);
            if (redirect) {
              // A thrown redirect is only a failure when it targets an error page; a plain redirect
              // (e.g. an OAuth callback landing on the app) is a success with no error recorded.
              if (redirect.failed) {
                status = "failed";
                metadata.error = redirect.error;
              }
            } else {
              // API error which isn't a redirct - we can enhance the log with some extra info from the APIError.
              // Truthy checks so each field is omitted when absent or an empty ""
              status = "failed";
              metadata.error = {
                ...(returned.message && { message: returned.message }),
                ...(returned.status && { status: returned.status }),
                ...(returned.body?.code && { code: returned.body.code }),
              };
            }
          } else if (returned instanceof Error) {
            // Defensive: today's better-auth re-throws a non-APIError out of the handler *before*
            // the after-hook stage runs (see dispatchAuthEndpoint), so `returned` is never a plain
            // Error in practice — an unhandled throw isn't logged at all (see README limitation).
            // We keep this branch as a safety net: if a future version ever surfaces such an error
            // as `returned` rather than re-throwing, we still record the failure instead of silently
            // logging it as a success.
            status = "failed";
            if (returned.message) {
              metadata.error = { message: returned.message };
            }
          }

          entry = await buildLogEntry(path, status, {
            userId: user?.id ?? null,
            request: ctx.request,
            headers: ctx.headers,
            metadata,
            pathConfig,
            options: opts,
            authOptions: ctx.context.options,
            logger: ctx.context.logger,
          });
        } catch (err) {
          ctx.context.logger?.error("[audit-log] after hook failed to build entry", err);
          if (opts.writeMode === "sync-strict") throw err;
          return;
        }

        await writeEntry(ctx, entry, opts, modelName);
      }),
    },
  ];
}
