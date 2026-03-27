import { lookup } from "dns/promises";

const PRIVATE_RANGES = [
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^169\.254\./,
  /^::1$/,
  /^fc[0-9a-f]{2}:/i,
  /^fe80:/i,
];

const BLOCKED_HOSTS = [
  "metadata.google.internal",
  "169.254.169.254",
  "metadata.aws.internal",
];

export class SsrfBlockedError extends Error {
  constructor(
    public readonly url: string,
    reason: string
  ) {
    super(`SSRF blocked: ${url} — ${reason}`);
  }
}

export interface SsrfPolicy {
  allowPrivate?: boolean;
  allowedSuffixes?: string[];
}

function isPrivateIp(ip: string): boolean {
  return PRIVATE_RANGES.some((r) => r.test(ip));
}

function stripSensitiveHeaders(headers: Headers): Headers {
  const stripped = new Headers(headers);
  stripped.delete("authorization");
  stripped.delete("x-api-key");
  stripped.delete("cookie");
  return stripped;
}

export async function safeFetch(
  url: string | URL,
  init?: RequestInit,
  policy?: SsrfPolicy
): Promise<Response> {
  const parsed = typeof url === "string" ? new URL(url) : url;

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new SsrfBlockedError(
      parsed.toString(),
      `disallowed scheme: ${parsed.protocol}`
    );
  }

  const hostname = parsed.hostname;

  if (BLOCKED_HOSTS.includes(hostname)) {
    throw new SsrfBlockedError(parsed.toString(), `blocked host: ${hostname}`);
  }

  if (policy?.allowedSuffixes && policy.allowedSuffixes.length > 0) {
    const allowed = policy.allowedSuffixes.some((suffix) =>
      hostname.endsWith(suffix)
    );
    if (!allowed) {
      throw new SsrfBlockedError(
        parsed.toString(),
        `hostname not in allowedSuffixes`
      );
    }
  }

  if (!policy?.allowPrivate) {
    const { address } = await lookup(hostname);
    if (isPrivateIp(address)) {
      throw new SsrfBlockedError(
        parsed.toString(),
        `resolved to private IP: ${address}`
      );
    }
  }

  const requestInit: RequestInit = {
    ...init,
    redirect: "manual",
  };

  let currentUrl = parsed.toString();
  let currentOrigin = parsed.origin;
  let currentHeaders = new Headers(
    (init?.headers as HeadersInit | undefined) ?? {}
  );

  for (let redirects = 0; redirects < 10; redirects++) {
    const response = await fetch(currentUrl, {
      ...requestInit,
      headers: currentHeaders,
    });

    if (
      response.status === 301 ||
      response.status === 302 ||
      response.status === 303 ||
      response.status === 307 ||
      response.status === 308
    ) {
      const location = response.headers.get("location");
      if (!location) return response;

      const nextUrl = new URL(location, currentUrl);
      const nextOrigin = nextUrl.origin;

      if (nextUrl.protocol !== "http:" && nextUrl.protocol !== "https:") {
        throw new SsrfBlockedError(
          nextUrl.toString(),
          `redirect to disallowed scheme: ${nextUrl.protocol}`
        );
      }

      if (BLOCKED_HOSTS.includes(nextUrl.hostname)) {
        throw new SsrfBlockedError(
          nextUrl.toString(),
          `redirect to blocked host: ${nextUrl.hostname}`
        );
      }

      if (!policy?.allowPrivate) {
        const { address } = await lookup(nextUrl.hostname);
        if (isPrivateIp(address)) {
          throw new SsrfBlockedError(
            nextUrl.toString(),
            `redirect resolved to private IP: ${address}`
          );
        }
      }

      if (nextOrigin !== currentOrigin) {
        currentHeaders = stripSensitiveHeaders(currentHeaders);
      }

      currentUrl = nextUrl.toString();
      currentOrigin = nextOrigin;

      if (response.status === 303) {
        requestInit.method = "GET";
        requestInit.body = undefined;
      }
      continue;
    }

    return response;
  }

  throw new SsrfBlockedError(currentUrl, "too many redirects");
}
