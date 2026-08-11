import type { BetterAuthPlugin } from "better-auth";
import { buildSchema, getModelName, validateSchema } from "./schema";
import { createBeforeHooks, createAfterHooks } from "./hooks";
import {
  createListLogsEndpoint,
  createGetLogEndpoint,
  createInsertLogEndpoint,
} from "./endpoints";
import type {
  AuditLogOptions,
  PathConfig,
  ResolvedOptions,
} from "./types";
import { DEFAULT_METADATA_LIMITS } from "./utils/validate-metadata";

const DEFAULT_BEFORE_PATHS = [
  "/sign-out",
  "/delete-user",
  "/revoke-session",
  "/revoke-sessions",
  "/revoke-other-sessions",
] as const;

function validateStorageAdapter(storage: AuditLogOptions["storage"]): void {
  if (!storage) return;

  if (typeof storage.write !== "function") {
    throw new Error(
      "[audit-log] Custom storage adapter must implement write(entry): Promise<void>",
    );
  }

  if (storage.read !== undefined && typeof storage.read !== "function") {
    throw new Error(
      "[audit-log] storage.read must be a function if provided",
    );
  }

  if (storage.readById !== undefined && typeof storage.readById !== "function") {
    throw new Error(
      "[audit-log] storage.readById must be a function if provided",
    );
  }

  if (storage.deleteOlderThan !== undefined && typeof storage.deleteOlderThan !== "function") {
    throw new Error(
      "[audit-log] storage.deleteOlderThan must be a function if provided",
    );
  }
}

/**
 * Combines the config attached to a `paths` entry with the matching `pathConfig` entry, the latter
 * winning field by field. Returns the source object untouched when only one side is present so the
 * common case allocates nothing.
 */
function mergePathConfig(
  fromPaths: PathConfig | undefined,
  fromPathConfig: PathConfig | undefined,
): PathConfig | undefined {
  if (!fromPaths) return fromPathConfig;
  if (!fromPathConfig) return fromPaths;

  return {
    severity: fromPathConfig.severity ?? fromPaths.severity,
    capture: { ...fromPaths.capture, ...fromPathConfig.capture },
  };
}

function resolveOptions(options?: AuditLogOptions): ResolvedOptions {
  const pathsMap = new Map<string, PathConfig | undefined>();
  const hasPaths = (options?.paths?.length ?? 0) > 0;

  const { beforePaths, afterPaths } = options ?? {};
  if (beforePaths !== undefined && afterPaths !== undefined) {
    throw new Error(
      "[audit-log] Provide either `beforePaths` or `afterPaths`, not both. " +
        "`beforePaths` lists the paths logged in the before hook (all others after); " +
        "`afterPaths` inverts this — all paths log in the before hook except those listed.",
    );
  }

  // `afterPaths` inverts the default timing: every path is logged in the before hook except the
  // listed ones. Otherwise the before hook captures only `beforePaths` (defaulting to the
  // session-destroying paths) and everything else is logged after.
  const beforePathList = beforePaths ?? DEFAULT_BEFORE_PATHS;
  const runBeforeHook =
    afterPaths !== undefined
      ? (path: string) => !afterPaths.some((p) => path.startsWith(p))
      : (path: string) => beforePathList.some((p) => path.startsWith(p));

  for (const p of options?.paths ?? []) {
    if (typeof p === "string") {
      pathsMap.set(p, undefined);
    } else {
      pathsMap.set(p.path, p.config);
    }
  }

  // Config only — kept out of `pathsMap` so configuring a path never narrows what is captured.
  const pathConfigMap = new Map<string, PathConfig>(
    Object.entries(options?.pathConfig ?? {}),
  );

  // Resolve metadata limits: false = disabled, undefined = defaults, object = merge with defaults
  const metadataLimits =
    options?.metadataLimits === false
      ? false
      : {
          maxBytes: options?.metadataLimits?.maxBytes ?? DEFAULT_METADATA_LIMITS.maxBytes,
          maxDepth: options?.metadataLimits?.maxDepth ?? DEFAULT_METADATA_LIMITS.maxDepth,
        };

  return {
    enabled: options?.enabled ?? true,
    writeMode: options?.writeMode ?? "sync-best-effort",
    storage: options?.storage,
    capture: {
      ipAddress: options?.capture?.ipAddress ?? true,
      userAgent: options?.capture?.userAgent ?? true,
      requestBody: options?.capture?.requestBody ?? false,
    },
    piiRedaction: {
      enabled: options?.piiRedaction?.enabled ?? false,
      fields: options?.piiRedaction?.fields,
      strategy: options?.piiRedaction?.strategy ?? "mask",
    },
    metadataLimits,
    runBeforeHook,
    beforeLog: options?.beforeLog,
    afterLog: options?.afterLog,
    onWriteError: options?.onWriteError,
    shouldCapture: (path: string) => !hasPaths || pathsMap.has(path),
    getPathConfig: (path: string) =>
      mergePathConfig(pathsMap.get(path), pathConfigMap.get(path)),
  };
}

export function auditLog(options?: AuditLogOptions) {
  validateStorageAdapter(options?.storage);

  const schema = buildSchema(options);
  validateSchema(schema);

  const modelName = getModelName(options);
  const resolved = resolveOptions(options);

  const beforeHooks = resolved.enabled ? createBeforeHooks(resolved, modelName) : [];
  const afterHooks = resolved.enabled ? createAfterHooks(resolved, modelName) : [];

  return {
    id: "audit-log",
    schema,
    hooks: {
      before: beforeHooks,
      after: afterHooks,
    },
    endpoints: {
      listAuditLogs: createListLogsEndpoint(resolved, modelName),
      getAuditLog: createGetLogEndpoint(resolved, modelName),
      insertAuditLog: createInsertLogEndpoint(resolved, modelName),
    },
    rateLimit: [
      {
        pathMatcher: (path: string) => path.startsWith("/audit-log/"),
        window: 60,
        max: 60,
      },
    ],
  } satisfies BetterAuthPlugin;
}
