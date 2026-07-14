# @stotles/better-auth-audit-logs

[![npm version](https://img.shields.io/npm/v/@stotles/better-auth-audit-logs)](https://www.npmjs.com/package/@stotles/better-auth-audit-logs)
[![npm downloads](https://img.shields.io/npm/dm/@stotles/better-auth-audit-logs)](https://www.npmjs.com/package/@stotles/better-auth-audit-logs)
[![license](https://img.shields.io/npm/l/@stotles/better-auth-audit-logs)](https://github.com/Stotles/better-auth-audit-logs/blob/main/LICENSE)

Audit log plugin for [Better Auth](https://better-auth.com). Automatically captures auth events with IP, user agent, and severity — zero config required.

**Requires** `better-auth >= 1.5.0` and `typescript >= 5`.

## Quick start

```bash
npm install @stotles/better-auth-audit-logs
```

```ts
import { betterAuth } from "better-auth";
import { auditLog } from "@stotles/better-auth-audit-logs";

export const auth = betterAuth({
  plugins: [auditLog()],
});
```

Then generate and run the migration:

```bash
npx @better-auth/cli generate
```

That's it. All auth events are now logged automatically.

## Schema

The plugin adds an `auditLog` table. If you prefer to manage your schema manually, copy the relevant definition:

<details>
<summary>Prisma</summary>

```prisma
model AuditLog {
  id        String   @id @default(cuid())
  userId    String?
  action    String
  status    String
  severity  String
  ipAddress String?
  userAgent String?
  metadata  String?
  createdAt DateTime @default(now())

  user User? @relation(fields: [userId], references: [id], onDelete: SetNull)

  @@index([userId])
  @@index([action])
  @@index([createdAt])
  @@map("auditLog")
}
```

</details>

<details>
<summary>Drizzle</summary>

```ts
import { sqliteTable, text, integer } from "drizzle-orm/sqlite-core";
import { user } from "./auth-schema"; // your existing user table

export const auditLog = sqliteTable("auditLog", {
  id: text("id").primaryKey(),
  userId: text("userId").references(() => user.id, { onDelete: "set null" }),
  action: text("action").notNull(),
  status: text("status").notNull(),
  severity: text("severity").notNull(),
  ipAddress: text("ipAddress"),
  userAgent: text("userAgent"),
  metadata: text("metadata"),
  createdAt: integer("createdAt", { mode: "timestamp" }).notNull(),
});
```

</details>

<details>
<summary>MongoDB</summary>

```ts
// Collection: auditLog
{
  _id: ObjectId,
  userId: String | null,       // references user collection
  action: String,              // e.g. "sign-in:email"
  status: String,              // "success" | "failed" | "requested"
  severity: String,            // "low" | "medium" | "high" | "critical"
  ipAddress: String | null,
  userAgent: String | null,
  metadata: String | null,     // JSON string
  createdAt: Date
}

// Recommended indexes
db.auditLog.createIndex({ userId: 1 })
db.auditLog.createIndex({ action: 1 })
db.auditLog.createIndex({ createdAt: 1 })
```

</details>

## Client plugin

```ts
import { createAuthClient } from "better-auth/client";
import { auditLogClient } from "@stotles/better-auth-audit-logs/client";

export const authClient = createAuthClient({
  plugins: [auditLogClient()],
});
```

```ts
// List recent failed sign-ins
const { data } = await authClient.auditLog.listAuditLogs({
  query: { status: "failed", limit: 20 },
});

// Single entry by ID
const { data: entry } = await authClient.auditLog.getAuditLog({
  params: { id: "log-entry-id" },
});

// Manually log custom events (admin actions, data exports, etc.)
await authClient.auditLog.insertAuditLog({
  action: "admin:user-export",
  status: "success",
  severity: "high",
  metadata: { exportedCount: 500 },
});
```

## What gets logged

All auth `POST` endpoints are captured by default:

| Event | Path | Hook |
|---|---|---|
| Sign in | `/sign-in/email`, `/sign-in/social` | after |
| Sign up | `/sign-up/email` | after |
| Change/reset password | `/change-password`, `/reset-password` | after |
| Change email | `/change-email` | after |
| Two-factor | `/two-factor/*` | after |
| OAuth callback | `/oauth/callback` | after |
| Sign out | `/sign-out` | **before** |
| Delete account | `/delete-user` | **before** |
| Revoke session | `/revoke-session`, `/revoke-sessions`, `/revoke-other-sessions` | **before** |

"Before" hooks fire for destructive events where the session would be lost after execution. Because the write happens *before* the action runs, these entries are recorded with `status: "requested"` — the request was captured, but its outcome is not (the entry is never updated). `after`-hook events, by contrast, record the observed `"success"` or `"failed"`.

> **before-hook events produce exactly one `"requested"` entry, even if the action then fails.** The before and after hooks are mutually exclusive, so a failed `delete-user`/`sign-out`/`revoke-session` is *not* separately logged as `"failed"` — only the `"requested"` record exists. (This is the trade-off for capturing the userId before the session is torn down.) Regular `after`-hook paths do record failures: a thrown `APIError` is captured as `"failed"`. A handler that throws a non-`APIError` bypasses the after hook entirely and isn't logged at all (see the limitation below).
>
> **This applies to *every* path routed through the before hook — including when you invert the timing with [`afterPaths`](#configuration).** In that mode most paths log before the handler runs, so most of your entries will be `"requested"` with no observed outcome, and only the paths listed in `afterPaths` will record `"success"`/`"failed"`. Reach for `afterPaths` only when capturing the *request* (not its outcome) is what you want for the bulk of your paths.

Severity is inferred automatically (`critical` for ban/impersonate, `high` for delete/revoke/failed sign-in, `medium` for sign-in/out, `low` for everything else) and can be overridden per-path.

### Limitation: unexpected (non-`APIError`) failures aren't logged

The after hook only sees failures that better-auth surfaces as an `APIError` (invalid credentials, rate limits, validation, etc.). If a handler throws something else — a raw database driver error, a `TypeError`, any unhandled bug — the current better-auth re-throws it *before* the after-hook stage runs, so **no audit entry is written** for it. There is no plugin-level error hook that can catch this, so the plugin cannot close the gap on its own. (The after hook does keep a defensive guard that records a `"failed"` entry should a future version ever surface such an error as the endpoint result instead of re-throwing — but you can't rely on that today.)

These are unexpected `500`s rather than auth outcomes, so they usually belong in your error monitoring (Sentry, structured logs). If you *do* want them in the audit trail, wire better-auth's global `onAPIError.onError` — it fires for any escaped error and write the non-`APIError` case yourself via your storage backend:

```ts
import { betterAuth } from "better-auth";
import { APIError } from "better-auth/api";

export const auth = betterAuth({
  plugins: [auditLog({ storage })],
  onAPIError: {
    onError: async (error, ctx) => {
      if (error instanceof APIError) return; // already captured by the after hook
      await storage.write({
        id: crypto.randomUUID(),
        userId: null,
        action: "unexpected-error",
        status: "failed",
        severity: "high",
        ipAddress: null,
        userAgent: null,
        metadata: { error: error instanceof Error ? error.message : String(error) },
        createdAt: new Date(),
      });
    },
  },
});
```

Note the callback only receives better-auth's shared `AuthContext`, **not** the per-request context: better-auth doesn't forward the `Request` to `onAPIError.onError`, and the request-scoped context is already torn down by the time an unhandled throw reaches it. So there's no reliable `path`/IP/headers here — the entry is necessarily coarse.

## Configuration

All options are optional:

```ts
auditLog({
  enabled: true,                 // disable without removing the plugin
  writeMode: "sync-best-effort", // how the write relates to the auth request (see Design decisions)

  // restrict to specific paths (empty = capture all)
  paths: [
    "/sign-in/email",
    { path: "/delete-user", config: { severity: "high", capture: { requestBody: true } } },
  ],

  // paths logged *before* the handler runs (needed where the session is torn down mid-request,
  // so the userId can still be captured). Defaults to the session-destroying paths.
  // This can be combined with `paths`
  beforePaths: ["/sign-out", "/delete-user", "/revoke-session"],

  // OR invert it: log *all* paths before the handler, except these which log after.
  // Mutually exclusive with beforePaths. Don't list session-destroying paths here.
  // This can be combined with `paths`
  // afterPaths: ["/callback"],

  capture: {
    ipAddress: true,         // capture client IP
    userAgent: true,         // capture User-Agent header
    requestBody: false,      // include request body in metadata
  },

  piiRedaction: {
    enabled: false,          // redact sensitive fields when requestBody is captured
    strategy: "mask",        // "mask" (***) | "hash" (SHA-256) | "remove" (delete key)
    fields: ["password"],    // defaults: password, token, secret, apiKey, otp, etc.
  },

  // intercept before write — return null to suppress. Receives the endpoint
  // ctx as a second argument, so you can resolve the session or read the request.
  beforeLog: async (entry, ctx) => {
    if (entry.userId === "service-account") return null;
    return entry;
  },

  // called after each successful write
  afterLog: async (entry) => {
    await analytics.track("auth.event", entry);
  },

  storage: undefined,        // custom storage backend (see below)
})
```

To override the DB model name, pass `schema: { auditLog: { modelName: "your_table_name" } }`.

## Adding additional metadata to log entries

`beforeLog` is the injection point for extra per-entry data. Because it receives the
endpoint `ctx`, you can resolve the session and stash a value such as the active
organization into `metadata` — which is stored as JSON and returned intact:

```ts
import { getSessionFromCtx } from "better-auth/api";

auditLog({
  beforeLog: async (entry, ctx) => {
    const session = await getSessionFromCtx(ctx);
    return {
      ...entry,
      metadata: {
        ...entry.metadata,
        activeOrganizationId: session?.session?.activeOrganizationId ?? null,
      },
    };
  },
});
```

## Custom storage

Route writes to any external backend instead of Better Auth's database:

```ts
import { auditLog, type AuditLogStorage } from "@stotles/better-auth-audit-logs";

const clickhouse: AuditLogStorage = {
  async write(entry) {
    await fetch("https://ch.example.com/insert", {
      method: "POST",
      body: JSON.stringify(entry),
    });
  },
  // Optional — enables the query endpoints to work with your backend
  async read(options) { /* ... */ },
  async readById(id) { /* ... */ },
};

auditLog({ storage: clickhouse })
```

A `MemoryStorage` adapter is included for testing:

```ts
import { auditLog, MemoryStorage } from "@stotles/better-auth-audit-logs";

const storage = new MemoryStorage();
const auth = betterAuth({ plugins: [auditLog({ storage })] });

// assert in tests
expect(storage.entries).toHaveLength(1);
expect(storage.entries[0].action).toBe("sign-in:email");
```

## API endpoints

Three endpoints are registered under `/audit-log/`, all requiring an active session. Rate limited to 60 req/min.

| Endpoint | Method | Description |
|---|---|---|
| `/audit-log/list` | `GET` | Paginated entries |
| `/audit-log/:id` | `GET` | Single entry by ID |
| `/audit-log/insert` | `POST` | Manually insert a custom event |

**Query parameters** for `GET /audit-log/list`:

| Parameter | Type | Default |
|---|---|---|
| `userId` | `string` | session user |
| `action` | `string` | — |
| `status` | `"success" \| "failed" \| "requested"` | — |
| `from` | ISO date string | — |
| `to` | ISO date string | — |
| `limit` | `number` | `50` (max 500) |
| `offset` | `number` | `0` |

## Design decisions

- **Entries survive user deletion** — `userId` uses `ON DELETE SET NULL`. Deleting a user does not erase their audit trail.
- **`userAgent` is not returned in API responses** — stored for forensics but excluded from client queries by default.
- **Failed sign-ins have `userId: null`** — the user isn't authenticated yet, so there's no session to pull from.
- **`writeMode` trades audit integrity against auth availability** — the write can relate to the auth request in three ways:
  - `"sync-best-effort"` **(default)** — the write is awaited before responding (so it isn't dropped on runtimes without a reliable background mechanism), but a failure after retries is logged and passed to `onWriteError` **without** failing the auth request. Auth always succeeds.
  - `"sync-strict"` — same, but a failure (storage after retries, or a throw from `beforeLog`/`afterLog`) is **rethrown**, turning the audit failure into the auth response. This does **not** roll the action back: `after` hooks run once the auth action has already executed and committed (better-auth does not wrap the request and its hooks in a shared transaction), so strict mode surfaces an error *after the fact*. To actually gate an action on a durable audit record, log its path in the *before* hook so the write runs before the action — a failed write then blocks it. The robust way to do this broadly is `afterPaths`, which inverts the default so **every** path logs before except the ones you list. Prefer it over `beforePaths` here: you only have to enumerate the non-mutating paths (which don't need gating), rather than remembering to add every mutating path. However, this means you lose the observed outcome of those paths (they all log as `"requested"`).
  - `"background"` — fire-and-forget via `runInBackground`; lowest latency, failures never touch the response. Requires the runtime to keep the task alive after responding (e.g. `waitUntil`), or writes may be lost.

## Recommended production config

```ts
auditLog({
  writeMode: "sync-best-effort", // the default: never fails auth, and the write isn't dropped post-response.
                                 // See above for trade-offs between modes as all are reasonable.
  piiRedaction: { enabled: true, strategy: "hash" },
  afterLog: async (entry) => {
    if (entry.severity === "critical" || entry.severity === "high") {
      await alerting.emit(entry);
    }
  },
})
```

## Acknowledgments

This plugin was inspired by the audit log design shared by [@Re4GD](https://github.com/Re4GD) in [better-auth/better-auth#1184](https://github.com/better-auth/better-auth/issues/1184). Additional inspiration from [@issamwahbi](https://github.com/issamwahbi) ([#3592](https://github.com/better-auth/better-auth/discussions/3592)) and [@ItsProless](https://github.com/ItsProless) ([#7952](https://github.com/better-auth/better-auth/discussions/7952)).

This plugin was originally maintained by [@ejirocodes](https://github.com/ejirocodes/better-auth-audit-logs).

This fork is maintained by [@Stotles](https://github.com/Stotles).

## License

[MIT](./LICENSE)
