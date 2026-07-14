import type { GenericEndpointContext } from "@better-auth/core";
import type {
  AuditLogEntry,
  AuditLogStatus,
  PathConfig,
  ResolvedOptions,
} from "./types";
import {
  normalizePath,
  inferSeverity,
  extractRequestMeta,
  redactPII,
  validateEntry,
  withRetry,
} from "./utils";

interface BuildParams {
  userId: string | null;
  request: Request | undefined;
  headers: Headers | undefined;
  metadata?: Record<string, unknown>;
  pathConfig?: PathConfig;
  options: ResolvedOptions;
  authOptions: GenericEndpointContext["context"]["options"];
  logger?: GenericEndpointContext["context"]["logger"];
}

export async function buildLogEntry(
  path: string,
  status: AuditLogStatus,
  params: BuildParams,
): Promise<Omit<AuditLogEntry, "id">> {
  const action = normalizePath(path);
  const severity =
    params.pathConfig?.severity ?? inferSeverity(action, status);

  const captureOpts = {
    ...params.options.capture,
    ...params.pathConfig?.capture,
  };

  const { ipAddress, userAgent } = extractRequestMeta(
    captureOpts.ipAddress !== false ? params.request : undefined,
    captureOpts.userAgent !== false ? params.headers : undefined,
    params.authOptions,
    params.logger,
  );

  let metadata = params.metadata ?? {};
  if (params.options.piiRedaction.enabled) {
    metadata = await redactPII(metadata, params.options.piiRedaction);
  }

  return {
    userId: params.userId,
    action,
    status,
    severity,
    ipAddress,
    userAgent,
    metadata,
    createdAt: new Date(),
  };
}

export async function buildLogEntryFromAction(
  action: string,
  status: AuditLogStatus,
  params: Omit<BuildParams, "pathConfig">,
): Promise<Omit<AuditLogEntry, "id">> {
  const severity = inferSeverity(action, status);

  const { ipAddress, userAgent } = extractRequestMeta(
    params.options.capture.ipAddress !== false ? params.request : undefined,
    params.options.capture.userAgent !== false ? params.headers : undefined,
    params.authOptions,
    params.logger,
  );

  let metadata = params.metadata ?? {};
  if (params.options.piiRedaction.enabled) {
    metadata = await redactPII(metadata, params.options.piiRedaction);
  }

  return {
    userId: params.userId,
    action,
    status,
    severity,
    ipAddress,
    userAgent,
    metadata,
    createdAt: new Date(),
  };
}

export async function writeEntry(
  ctx: GenericEndpointContext,
  entry: Omit<AuditLogEntry, "id">,
  opts: ResolvedOptions,
  modelName: string,
): Promise<void> {
  // The entry actually attempted, after any beforeLog transform. Reported to onWriteError so
  // callers see what failed to persist, not the pre-transform input.
  let attemptedEntry = entry;

  const doFullWrite = async () => {
    if (opts.beforeLog) {
      const modified = await opts.beforeLog(attemptedEntry, ctx);
      if (modified === null) return;

      const validated = validateEntry(modified, ctx.context.logger);
      if (validated === null) return;
      attemptedEntry = validated;
    }

    const written = await withRetry(async () => {
      if (opts.storage) {
        const result: AuditLogEntry = { id: crypto.randomUUID(), ...attemptedEntry };
        await opts.storage!.write(result);
        return result;
      }

      const record = await ctx.context.adapter.create<
        Record<string, unknown>
      >({
        model: modelName,
        data: {
          ...attemptedEntry,
          metadata: JSON.stringify(attemptedEntry.metadata),
        },
      });
      return {
        ...(record as Omit<AuditLogEntry, "metadata">),
        metadata: attemptedEntry.metadata,
      } as AuditLogEntry;
    }, { maxRetries: 2, baseDelayMs: 100 });

    if (opts.afterLog) await opts.afterLog(written);
  };

  // "background": fire-and-forget. The write never affects the response; failures are
  // isolated to the logger/onWriteError. Requires the runtime to keep the task alive.
  if (opts.writeMode === "background") {
    ctx.context.runInBackground(
      doFullWrite().catch((err) => {
        ctx.context.logger?.error("[audit-log] background write failed", err);
        opts.onWriteError?.(err, attemptedEntry);
      }),
    );
    return;
  }

  // Both sync modes await the write. On failure they report once via the logger/onWriteError;
  // only "sync-strict" rethrows to fail the auth request, "sync-best-effort" swallows.
  try {
    await doFullWrite();
  } catch (err) {
    ctx.context.logger?.error("[audit-log] audit write failed", err);
    opts.onWriteError?.(err, attemptedEntry);
    if (opts.writeMode === "sync-strict") throw err;
  }
}
