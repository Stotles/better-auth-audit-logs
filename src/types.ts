import type { GenericEndpointContext } from "@better-auth/core";

export type AuditLogStatus = "success" | "failed";
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
   */
  paths?: (string | { path: string; config?: PathConfig })[];
  /**
   * An array of paths where the audit log will be written before the request is processed.
   * This is needed on paths which remove the user from the request context (e.g. logout)
   * so the userId can be captured.
   *
   * @default DEFAULT_BEFORE_PATHS
   */
  beforePaths?: string[];
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
  beforePaths: readonly string[];
  beforeLog: AuditLogOptions["beforeLog"];
  afterLog: AuditLogOptions["afterLog"];
  onWriteError: AuditLogOptions["onWriteError"];
  shouldCapture: (path: string) => boolean;
  getPathConfig: (path: string) => PathConfig | undefined;
}
