import type { GenericEndpointContext } from "@better-auth/core";

/**
 * - `success` - the action was requested and completed successfully
 * - `failed` - the action was requested but failed (e.g. invalid credentials)
 * - `requested` - the action was requested but its outcome is not observed.
 *    Used by the `before` hook since that entry is written before the handler runs
 *    and is never updated afterwards so the outcome is unknown.
 */
export type AuditLogStatus = "success" | "failed" | "requested";
export type AuditLogSeverity = "low" | "medium" | "high" | "critical";
export type PIIStrategy = "mask" | "hash" | "remove";
export type AuditLogWriteMode = "sync-strict" | "sync-best-effort" | "background";

export interface AuditLogEntry {
  id: string;
  userId: string | null;
  action: string;
  status: AuditLogStatus;
  severity: AuditLogSeverity;
  ipAddress: string | null;
  userAgent: string | null;
  metadata: Record<string, unknown>;
  createdAt: Date;
}

export interface StorageReadOptions {
  userId?: string;
  action?: string;
  status?: AuditLogStatus;
  from?: Date;
  to?: Date;
  limit: number;
  offset: number;
}

export interface StorageReadResult {
  entries: AuditLogEntry[];
  total: number;
}

export interface AuditLogStorage {
  write(entry: AuditLogEntry): Promise<void>;
  read?(options: StorageReadOptions): Promise<StorageReadResult>;
  readById?(id: string): Promise<AuditLogEntry | null>;
  deleteOlderThan?(date: Date): Promise<number>;
}

export interface PIIRedactionOptions {
  /**
   * Whether PII redaction should run on the metadata before writing to the audit log.
   *
   * This is the last step before writing to the audit log
   */
  enabled: boolean;
  /**
   * An array of field names to redact from the metadata.
   *
   * This currently only supports top-level fields, fields in nested objects **will not be redacted**.
   *
   * If requestBody capture is enabled by default this **will not redact fields** since that is captured
   * at metadata.requestBody so all the properties are nested objects.
   *
   * If you want more advance redaction you can implement your own redaction with the `beforeLog` hook
   *
   * @default DEFAULT_PII_FIELDS
   */
  fields?: string[];
  /**
   * The strategy to use for redacting PII fields.
   *
   * - `"mask"` - replaces the value with `[REDACTED]`.
   * - `"hash"` - replaces the value with a SHA-256 hash of the original value.
   * - `"remove"` - removes the field from the metadata entirely.
   *
   * @default "mask"
   */
  strategy?: PIIStrategy;
}

export interface CaptureOptions {
  /**
   * Whether to capture the IP address of the request or not.
   *
   * @default true
   */
  ipAddress?: boolean;
  /**
   * Whether to capture the user agent of the request or not.
   *
   * @default true
   */
  userAgent?: boolean;
  /**
   * Whether to capture the request body of the request or not.
   * This can contain sensitive information such as passwords so it is disabled by default.
   *
   * @default false
   */
  requestBody?: boolean;
}

export interface PathConfig {
  severity?: AuditLogSeverity;
  capture?: CaptureOptions;
}

export interface MetadataLimitsConfig {
  maxBytes?: number;
  maxDepth?: number;
}

export interface AuditLogOptions {
  /**
   * Whether the audit log is enabled
   *
   * @default true
   */
  enabled?: boolean;
  /**
   * Controls how the audit-log write relates to the auth request lifecycle:
   *
   * - `"sync-best-effort"` — await the write, but on failure log it (and call `onWriteError`)
   *   without rethrowing, so auth always succeeds. Because the write is awaited before responding,
   *   it isn't dropped on runtimes without a reliable background mechanism (e.g. serverless/edge).
   * - `"sync-strict"` — await the write, and if it ultimately fails (after retries) rethrow so
   *   the underlying auth request fails. This attempts to fail-closed but there are **many** scenarios
   *   where this doesn't happen, see the [README](../README.md) for details
   * - `"background"` — fire-and-forget via `runInBackground`; failures are logged and passed to
   *   `onWriteError` but never affect the response. Lowest latency, but requires the runtime to
   *   keep the task alive after responding (e.g. `waitUntil`) or writes may be lost.
   *
   * @default "sync-best-effort"
   */
  writeMode?: AuditLogWriteMode;
  /**
   * Storage adapter used for audit logs. If not provided, will use the Better-Auth adapter
   * and the database associated with it.
   */
  storage?: AuditLogStorage;
  /**
   * An array of paths where the audit log will be written after the request is processed.
   *
   * If not provided or it's an empty array, the audit log will be written for all paths.
   *
   * This is a capture **allowlist**: as soon as it is non-empty, every path not listed here stops
   * being audited. To configure a path without narrowing what is captured, use {@link pathConfig}.
   */
  paths?: (string | { path: string; config?: PathConfig })[];
  /**
   * Per-path overrides (severity, capture) that do **not** affect which paths are captured.
   *
   * Applies to every captured path it matches, whether {@link paths} is set or not. Use this to
   * override the inferred severity of an endpoint without turning `paths` into an allowlist.
   *
   * Keys are raw request paths matched exactly, the same format as {@link paths}
   * (e.g. `"/oauth2/authorize"`, not the normalised action `"oauth2:authorize"`).
   *
   * Where a path is configured in both, the entry here wins field by field.
   *
   * @example
   * ```ts
   * auditLog({ pathConfig: { "/oauth2/authorize": { severity: "medium" } } })
   * ```
   */
  pathConfig?: Record<string, PathConfig>;
  /**
   * An array of paths where the audit log will be written before the request is processed.
   * This is needed on paths which remove the user from the request context (e.g. logout)
   * so the userId can be captured.
   *
   * Cannot be combined with {@link afterPaths} is set by the user — the two describe the same before/after
   * partition from opposite sides, so providing both throws a configuration error. When
   * `afterPaths` is set this option is unused and no default is applied.
   *
   * @default DEFAULT_BEFORE_PATHS
   */
  beforePaths?: string[];
  /**
   * Inverts the default hook timing: when provided, the audit log is written *before* the
   * request is processed for **all** paths, except those listed here which are written after.
   *
   * Use this when most of your captured paths need before-hook logging and only a few can be
   * logged afterwards.
   * Cannot be combined with {@link beforePaths} is set by the user — the two describe the same
   * before/after partition from opposite sides, so providing both throws a configuration error.
   *
   * Session-destroying paths (e.g. `/sign-out`, `/delete-user`) will not have the userId available
   * so are recommended not to be listed here unless you want to accept that the userId will be
   * always `null` for those paths.
   */
  afterPaths?: string[];
  piiRedaction?: PIIRedactionOptions;
  capture?: CaptureOptions;
  metadataLimits?: MetadataLimitsConfig | false;
  schema?: {
    auditLog?: {
      modelName?: string;
      fields?: Record<string, string>;
    };
  };
  /**
   * A function to be called before logging an audit entry
   */
  beforeLog?: (
    entry: Omit<AuditLogEntry, "id">,
    ctx: GenericEndpointContext,
  ) => Promise<Omit<AuditLogEntry, "id"> | null>;
  /**
   * A function to be called after logging an audit entry
   */
  afterLog?: (entry: AuditLogEntry) => Promise<void>;
  /**
   * A function to be called when writing to the audit log fails after all retries
   */
  onWriteError?: (error: unknown, entry: Omit<AuditLogEntry, "id">) => void;
}

export interface ResolvedMetadataLimits {
  maxBytes: number;
  maxDepth: number;
}

export interface ResolvedOptions {
  enabled: boolean;
  writeMode: AuditLogWriteMode;
  storage: AuditLogStorage | undefined;
  capture: Required<CaptureOptions>;
  piiRedaction: { enabled: boolean; fields?: string[]; strategy: PIIStrategy };
  metadataLimits: ResolvedMetadataLimits | false;
  /**
   * Predicate deciding whether a path is logged in the before hook (`true`) or the after hook
   * (`false`). Resolved from `beforePaths`/`afterPaths` so the hooks stay exact complements.
   */
  runBeforeHook: (path: string) => boolean;
  beforeLog: AuditLogOptions["beforeLog"];
  afterLog: AuditLogOptions["afterLog"];
  onWriteError: AuditLogOptions["onWriteError"];
  /** Whether the path is audited at all. Reads `paths` only, never `pathConfig`. */
  shouldCapture: (path: string) => boolean;
  /** Per-path overrides, merged from the `paths` entry and `pathConfig` (the latter wins). */
  getPathConfig: (path: string) => PathConfig | undefined;
}
