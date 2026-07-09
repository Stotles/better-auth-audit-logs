import { describe, test, expect } from "bun:test";
import * as betterAuthApi from "better-auth/api";
import { extractRequestMeta } from "../../src/utils/request-meta";

const options = {} as never;

describe("extractRequestMeta", () => {
  // Guard against a future better-auth bump renaming/removing the IP helper.
  // getIpWrapper prefers getIP (>= 1.7) and falls back to getIp (1.5–1.7);
  // if a dep bump drops both, IP capture silently returns null — this fails
  // loudly in CI at that point instead.
  test("better-auth/api still exports a getIP/getIp function", () => {
    const fn =
      ("getIP" in betterAuthApi && betterAuthApi.getIP) ||
      ("getIp" in betterAuthApi &&
        (betterAuthApi as { getIp?: unknown }).getIp);
    expect(typeof fn).toBe("function");
  });

  test("captures user-agent from headers", () => {
    const headers = new Headers({ "user-agent": "test-agent" });
    const result = extractRequestMeta(undefined, headers, options);
    expect(result.userAgent).toBe("test-agent");
  });

  test("ipAddress is null when no request is provided", () => {
    const headers = new Headers({ "user-agent": "test-agent" });
    const result = extractRequestMeta(undefined, headers, options);
    expect(result.ipAddress).toBeNull();
  });

  test("userAgent is null when headers are absent", () => {
    const result = extractRequestMeta(undefined, undefined, options);
    expect(result.userAgent).toBeNull();
  });
});
