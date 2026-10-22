import type { Metadata } from "@oracularhades/guard";

export type { AuthenticationMethod, Metadata, RequestData } from "@oracularhades/guard";

/**
 * Login-page metadata. Extends the server's `Metadata` with fields the frontend
 * renders when present but which `GET /metadata` does not serve yet (see
 * server/src/endpoints/metadata.rs) — hence optional, and absent in practice.
 */
export interface LoginMetadata extends Metadata {
  login_header?: string | null;
  form?: {
    bottom_text?: string | null;
    bottom_text_fontsize?: string | number | null;
  } | null;
}

/**
 * Where the login flow should send the user afterwards, resolved from
 * `?redirect=`.
 */
export interface RoutingHost {
  /** Host of the redirect target, i.e. the host being authenticated for. */
  host: string;
  href: string;
  redirect_url: URL;
  /** URL of this page, for reading our own query parameters. */
  webpage_url: URL;
}

/**
 * Context the Guard desktop app hands to the browser when it opens
 * /device-authentication. Its presence switches the login form into device mode.
 */
export interface DeviceContext {
  /** Opaque value the desktop app matches when we hand the token back. */
  deeplink_state: string | null;
  /** Loopback URL to deliver the setup token to. Validated before every use. */
  callback: string | null;
}

/**
 * One in-flight authentication attempt, persisted to localStorage so the
 * magiclink/OAuth round-trip can be matched back to the request that began it.
 *
 * Stored as an array: a user who requests two links (e.g. types their email
 * twice) must be able to complete either, so a second attempt cannot overwrite
 * the first.
 */
export interface ConfirmMetadataItem {
  authentication_method: string;
  state: string;
  redirect_url: string;
  /** Set for the desktop device-authentication flow. */
  device_authentication?: boolean;
  deeplink_state?: string | null;
  callback?: string | null;
}

/** Credentials as persisted in localStorage under `auth`. */
export interface StoredAuth {
  device_id?: string;
  /** ed25519 private key, base64-encoded PKCS#8 DER. */
  private_key?: string;
  /** Set instead of a device key when the credential is an OAuth access token. */
  access_token?: string;
}

/** Which authentication method the user logged in with, kept in a cookie. */
export interface AuthenticationMetadata {
  authentication_method: string | null;
}

/** Credentials in the shape `Guard()` expects. */
export interface DeviceCredentials {
  deviceid: string;
  privatekey: string;
}
