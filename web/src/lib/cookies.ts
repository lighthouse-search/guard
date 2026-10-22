import { Cookies } from "react-cookie";
import type { AuthenticationMetadata } from "@/types";

const cookies = new Cookies();

/** Ten years — these cookies are revoked server-side, not by expiry. */
function farFutureExpiry(): Date {
  const expires = new Date();
  expires.setFullYear(expires.getFullYear() + 10);
  return expires;
}

/**
 * The domain to scope cookies to, so one Guard instance can authenticate every
 * subdomain of a site: `auth.example.com` writes cookies for `.example.com`.
 *
 * Note this uses `hostname`, not `host`: a cookie domain may not contain a port,
 * and loopback gets no domain at all (there is no registrable parent).
 */
export function cookieRootDomain(): string {
  const hostname = window.location.hostname;
  if (hostname === "127.0.0.1" || hostname === "localhost") {
    return hostname;
  }

  const labels = hostname.split(".");
  if (labels.length < 2) {
    return hostname;
  }

  return `.${labels[labels.length - 2]}.${labels[labels.length - 1]}`;
}

/**
 * Cookies are namespaced by the Guard instance's hostname so two instances
 * sharing a root domain cannot overwrite each other's credentials. The Rust
 * side derives the same name (see `prepend_hostname_to_cookie` in
 * server/src/device.rs).
 */
export function prependHostnameToCookie(name: string): string {
  return `${window.location.hostname}_${name}`;
}

/**
 * Write one of Guard's long-lived credential cookies.
 *
 * `secure` is deliberately false: Guard is reachable over plain http on
 * loopback during development, and a secure cookie would simply never be set
 * there. In production the cookie is only ever transmitted over the TLS
 * connection the instance is served on.
 */
export function setCredentialCookie(name: string, value: string): void {
  cookies.set(prependHostnameToCookie(name), value, {
    domain: cookieRootDomain(),
    path: "/",
    secure: false,
    expires: farFutureExpiry(),
    sameSite: "strict",
  });
}

export function getCredentialCookie(name: string): unknown {
  return cookies.get(prependHostnameToCookie(name));
}

/** Which authentication method the user logged in with, or null if unknown. */
export function getAuthenticationMetadata(): AuthenticationMetadata | null {
  return (getCredentialCookie("guard_authentication_metadata") as AuthenticationMetadata | undefined) ?? null;
}

export function setAuthenticationMetadata(metadata: AuthenticationMetadata): void {
  setCredentialCookie("guard_authentication_metadata", JSON.stringify(metadata));
}

/**
 * Remove every cookie this origin can see.
 *
 * Each name is removed twice: once unscoped and once with the domain and path
 * the credential cookies were written with. universal-cookie matches on those
 * attributes, so an unscoped remove silently fails to clear a `.example.com`
 * cookie.
 */
export function removeAllCookies(): void {
  for (const name of Object.keys(cookies.getAll() ?? {})) {
    cookies.remove(name);
    cookies.remove(name, { domain: cookieRootDomain(), path: "/" });
  }
}
