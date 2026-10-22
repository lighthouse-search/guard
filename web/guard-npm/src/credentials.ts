import type { Credentials } from "./types.js";

// Credentials live in module scope: `Guard(creds)` sets them once and every
// subsequent call reuses them. Callers that only need unauthenticated endpoints
// (the whole pre-login flow — metadata, magiclink request, oauth exchange) just
// call `Guard()` and nothing is signed.
let credentials: Credentials | null = null;

export function setCredentials(next: Credentials | null): void {
  credentials = next;
}

/** The credentials in effect, or null when unauthenticated. */
export function getCredentials(): Credentials | null {
  return credentials;
}

/**
 * Async accessor kept for backwards compatibility with consumers that call
 * `await getCreds()`. Prefer `getCredentials()` inside this package — it is
 * synchronous, so it cannot be accidentally used un-awaited.
 */
export async function getCreds(): Promise<Credentials | null> {
  return credentials;
}
