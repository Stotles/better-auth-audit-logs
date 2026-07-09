import * as betterAuthApi from "better-auth/api";
import type { BetterAuthOptions } from "better-auth";

type Logger = { error: (message: string, ...args: unknown[]) => void };

// The api's export is fixed for the lifetime of the process, so warn at most
// once instead of on every audited request.
let hasWarnedMissingGetIp = false;

function getIpWrapper(
  req: Request | Headers,
  options: BetterAuthOptions,
  logger?: Logger,
): string | null {
  // getIp was added in 1.5 but it was renamed to getIP in 1.7
  if ("getIP" in betterAuthApi) {
    return betterAuthApi.getIP(req, options);
  }
  if ("getIp" in betterAuthApi) {
    // @ts-expect-error: getIp only exists between 1.5 and 1.7, which is why we are checking for it existing first
    return betterAuthApi.getIp(req, options);
  }
  if (!hasWarnedMissingGetIp) {
    hasWarnedMissingGetIp = true;
    logger?.error(
      "[audit-log] better-auth/api exposes neither getIP nor getIp; " +
        "IP addresses will not be captured. This likely means an incompatible better-auth version.",
    );
  }
  return null;
}

export function extractRequestMeta(
  request: Request | undefined,
  headers: Headers | undefined,
  options: BetterAuthOptions,
  logger?: Logger,
): { ipAddress: string | null; userAgent: string | null } {
  return {
    ipAddress: request ? (getIpWrapper(request, options, logger) ?? null) : null,
    userAgent: headers?.get("user-agent") ?? null,
  };
}
