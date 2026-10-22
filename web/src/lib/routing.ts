import type { RoutingHost } from "@/types";

const isDevMock = process.env.NEXT_PUBLIC_DEV_MOCK === "true";

/**
 * Resolve which host the user is authenticating for, from `?redirect=`.
 *
 * Guard's frontend is always reached with a redirect target: the reverse proxy
 * bounces an unauthenticated request to /guard/frontend/login?redirect=<url>
 * (see `authentication_misc.rs`), and that target decides which hostname's
 * metadata, authentication methods and policies apply.
 */
export function getRoutingHost(): RoutingHost {
  if (isDevMock) {
    const mockRedirect = new URL("http://localhost:8484/");
    return {
      host: "localhost:8484",
      href: mockRedirect.href,
      redirect_url: mockRedirect,
      webpage_url: new URL(window.location.href),
    };
  }

  const webpageUrl = new URL(window.location.href);
  const redirect = webpageUrl.searchParams.get("redirect");
  if (!redirect) {
    throw new Error("Missing params.redirect.");
  }

  const redirectUrl = new URL(redirect);
  return {
    host: redirectUrl.host,
    href: redirectUrl.href,
    redirect_url: redirectUrl,
    webpage_url: webpageUrl,
  };
}

/**
 * Whether a device-authentication callback is a loopback address.
 *
 * The callback is where the one-time setup token is handed back to the desktop
 * app, so it MUST be loopback and nothing else — a non-loopback callback (say
 * `?callback=https://evil.example` in a phishing link) would exfiltrate the
 * setup token to an attacker, who could then enrol their own device as the
 * victim. Only 127.0.0.0/8, localhost and ::1 over http are trusted; the
 * desktop app always uses http://127.0.0.1:<port>.
 */
export function isLoopbackCallback(callback: string | null | undefined): boolean {
  if (!callback) {
    return false;
  }

  let url: URL;
  try {
    url = new URL(callback);
  } catch {
    return false;
  }

  // Loopback is never served over TLS; the desktop's local server is plain http.
  if (url.protocol !== "http:") {
    return false;
  }

  const host = url.hostname.toLowerCase();
  if (host === "localhost" || host === "::1" || host === "[::1]") {
    return true;
  }

  // The whole 127.0.0.0/8 range, not just 127.0.0.1.
  return /^127(?:\.\d{1,3}){3}$/.test(host);
}
