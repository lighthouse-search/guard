import { getCredentials } from "./credentials.js";

/**
 * Base URL for the Guard API, in precedence order:
 *   1. `custom_guard_api_endpoint` in localStorage — set by the desktop app when
 *      the auth page is served from a different origin than the API (dev).
 *   2. The current origin's `/guard/api` — the normal in-browser case.
 *   3. `additional_data.endpoint` from the credentials — non-browser consumers.
 */
export function getGuardApiURL(): string {
  if (typeof localStorage !== "undefined") {
    const custom = localStorage.getItem("custom_guard_api_endpoint");
    if (custom) {
      return removeTrailingSlash(new URL(custom).href);
    }
  }

  if (typeof window !== "undefined") {
    return removeTrailingSlash(new URL(`${window.location.protocol}//${window.location.host}/guard/api`).href);
  }

  const endpoint = getCredentials()?.additional_data?.endpoint;
  if (endpoint) {
    return removeTrailingSlash(endpoint);
  }

  throw new Error("Could not determine the Guard API URL: no custom endpoint, no window, and no credentials.additional_data.endpoint.");
}

function removeTrailingSlash(href: string): string {
  return href.endsWith("/") ? href.slice(0, -1) : href;
}
