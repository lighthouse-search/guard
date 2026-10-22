import { signStaticCredential } from "@oracularhades/guard";
import {
  getCredentialCookie,
  removeAllCookies,
  setAuthenticationMetadata,
  setCredentialCookie,
} from "@/lib/cookies";
import type { AuthenticationMetadata, DeviceCredentials, StoredAuth } from "@/types";

const AUTH_STORAGE_KEY = "auth";

/** Persist new credentials and record which method produced them. */
export function storeAuth(auth: StoredAuth, metadata: AuthenticationMetadata): void {
  if (!auth) {
    throw new Error("No auth data given.");
  }

  localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(auth));
  setAuthenticationMetadata(metadata);
}

/**
 * Store an RFC 9421 static device credential (a signature over an empty
 * covered-components list) in a cookie, so plain browser navigations through
 * Guard's reverse proxy can prove device identity without setting Signature
 * headers.
 *
 * The credential JSON is base64url-encoded so it contains only URL-unreserved
 * characters and round-trips cleanly through the cookie encoders on both ends
 * (the Rust side decodes it in `parse_static_auth_cookie`).
 */
export async function storeStaticAuth(auth: StoredAuth): Promise<void> {
  if (!auth.device_id) {
    throw new Error("device_id not provided.");
  }
  if (!auth.private_key) {
    throw new Error("private_key not provided.");
  }

  const credential = await signStaticCredential({
    deviceId: auth.device_id,
    privateKeyPkcs8Base64: auth.private_key,
  });

  const encoded = btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(credential))))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  setCredentialCookie("guard_static_auth", encoded);
}

/** Store an OAuth access token, which Guard validates live on each request. */
export function storeOauthAccessToken(accessToken: string): void {
  setCredentialCookie("guard_oauth_access_token", accessToken);
}

function readStoredAuth(): StoredAuth | null {
  const raw = localStorage.getItem(AUTH_STORAGE_KEY);
  if (!raw) {
    return null;
  }

  try {
    return JSON.parse(raw) as StoredAuth;
  } catch {
    return null;
  }
}

/** Credentials in the shape `Guard()` expects, or null if not enrolled. */
export function readCredentials(): DeviceCredentials | null {
  const auth = readStoredAuth();
  if (!auth?.device_id || !auth.private_key) {
    return null;
  }

  return { deviceid: auth.device_id, privatekey: auth.private_key };
}

export function isAuthenticated(): boolean {
  return localStorage.getItem(AUTH_STORAGE_KEY) !== null
    || getCredentialCookie("guard_authentication_metadata") !== undefined;
}

/**
 * Clear local credentials and return to the login page.
 *
 * TODO: this should also tell the server the credential is no longer valid and
 * wait for confirmation that it was removed — right now it is local-only.
 */
export function logout(redirect?: string): void {
  removeAllCookies();
  localStorage.removeItem(AUTH_STORAGE_KEY);
  // Older builds could write credentials under `auth_local`; clear it so a
  // logout does not leave stale credentials behind for anyone upgrading.
  localStorage.removeItem("auth_local");

  const params = new URLSearchParams();
  if (redirect) {
    params.set("redirect", redirect);
  }

  const query = params.toString();
  window.location.href = query ? `/guard/frontend/login?${query}` : "/guard/frontend/login";
}
