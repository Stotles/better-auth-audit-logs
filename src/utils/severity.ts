import type { AuditLogSeverity, AuditLogStatus } from "../types";

// Matched with `action.includes(pattern)` in insertion order, first hit wins. So a pattern that is
// a substring of another action must come *after* the more specific one (e.g. `revoke-sessions`
// before `revoke-session`, otherwise a session revoke-all would resolve to medium).
const SEVERITY_MAP = new Map<string, AuditLogSeverity>([
  ["ban-user", "critical"],
  ["impersonate-user", "critical"],
  ["delete-user", "high"],
  ["delete-account", "high"],
  ["revoke-sessions", "high"],
  ["revoke-other-sessions", "high"],
  // Minting or changing an OAuth client's credentials.
  ["oauth2:create-client", "high"],
  ["oauth2:update-client", "high"],
  // A read of an existing token: high volume, no state change. Listed explicitly so it is not
  // picked up by a broader pattern later.
  ["oauth2:introspect", "low"],
  ["sign-in", "medium"],
  ["sign-out", "medium"],
  ["revoke-session", "medium"],
  ["two-factor", "medium"],
  ["change-password", "medium"],
  ["reset-password", "medium"],
  // OIDC provider flows. Each is a credential being issued, exchanged or destroyed, so they
  // promote to high on failure like the other medium entries.
  ["oauth2:authorize", "medium"],
  ["oauth2:token", "medium"],
  ["oauth2:revoke", "medium"],
  ["oauth2:end-session", "medium"],
  ["oauth2:consent", "medium"],
]);

export function inferSeverity(
  action: string,
  status: AuditLogStatus,
): AuditLogSeverity {
  for (const [pattern, severity] of SEVERITY_MAP) {
    if (action.includes(pattern)) {
      if (severity === "medium" && status === "failed") return "high";
      return severity;
    }
  }
  return "low";
}
