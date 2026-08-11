import { describe, test, expect } from "bun:test";
import { inferSeverity } from "../../src/utils/severity";

describe("inferSeverity", () => {
  test("critical for ban-user", () => {
    expect(inferSeverity("ban-user", "success")).toBe("critical");
  });

  test("critical for impersonate-user", () => {
    expect(inferSeverity("impersonate-user", "success")).toBe("critical");
  });

  test("high for delete-user", () => {
    expect(inferSeverity("delete-user", "success")).toBe("high");
  });

  test("high for revoke-sessions", () => {
    expect(inferSeverity("revoke-sessions", "success")).toBe("high");
  });

  test("medium for sign-in success", () => {
    expect(inferSeverity("sign-in:email", "success")).toBe("medium");
  });

  test("high for sign-in failure (escalation)", () => {
    expect(inferSeverity("sign-in:email", "failed")).toBe("high");
  });

  test("medium for change-password success", () => {
    expect(inferSeverity("change-password", "success")).toBe("medium");
  });

  test("low for unknown actions", () => {
    expect(inferSeverity("custom:action", "success")).toBe("low");
  });

  test("low for unknown failed actions", () => {
    expect(inferSeverity("custom:action", "failed")).toBe("low");
  });

  test("matches partial action names", () => {
    expect(inferSeverity("two-factor:totp:verify", "success")).toBe("medium");
  });

  describe("OIDC provider actions", () => {
    const MEDIUM_ACTIONS = [
      "oauth2:authorize",
      "oauth2:token",
      "oauth2:revoke",
      "oauth2:end-session",
      "oauth2:consent",
    ];

    for (const action of MEDIUM_ACTIONS) {
      test(`medium for ${action} success`, () => {
        expect(inferSeverity(action, "success")).toBe("medium");
      });

      test(`high for ${action} failure (escalation)`, () => {
        expect(inferSeverity(action, "failed")).toBe("high");
      });
    }

    test("low for oauth2:introspect — a read, and not escalated on failure", () => {
      expect(inferSeverity("oauth2:introspect", "success")).toBe("low");
      expect(inferSeverity("oauth2:introspect", "failed")).toBe("low");
    });

    test("high for client credential changes", () => {
      expect(inferSeverity("oauth2:create-client", "success")).toBe("high");
      expect(inferSeverity("oauth2:update-client", "success")).toBe("high");
    });

    test("oauth2:revoke is not matched by the revoke-session patterns", () => {
      // `revoke-session`/`revoke-sessions` are session endpoints; an OAuth token revoke is its own
      // action and must not inherit their high/medium mapping by substring.
      expect(inferSeverity("oauth2:revoke", "success")).toBe("medium");
      expect(inferSeverity("oauth2:end-session", "success")).toBe("medium");
    });

    test("unmapped oauth2 actions still fall through to low", () => {
      expect(inferSeverity("oauth2:userinfo", "success")).toBe("low");
    });
  });
});
