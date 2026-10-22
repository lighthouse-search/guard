// Shapes returned by the Guard server. These mirror the Rust types in
// server/src/structs.rs and the handlers in server/src/endpoints/, so if you
// change a response there, change it here too.

/** Credentials for a Guard-enrolled device. */
export interface Credentials {
  /** Guard `device_id`; travels as the RFC 9421 `keyid` signature parameter. */
  deviceid: string;
  /** ed25519 private key as base64-encoded PKCS#8 DER (WebCrypto `exportKey("pkcs8", ...)`). */
  privatekey: string;
  /** Extra query parameters appended to every request (e.g. `{ endpoint }`). */
  additional_data?: Record<string, string> | null;
  type?: string | null;
}

/** Every endpoint wraps its payload as `{ ok, data }`. */
export interface ApiResponse<T> {
  ok: boolean;
  data: T;
}

/** An error response. `fetch_wrapper` throws these rather than returning them. */
export interface ApiError {
  error: true;
  code?: number;
  message?: string;
}

/** `GET /metadata` — branding for a login page. */
export interface Metadata {
  alias: string | null;
  public_description: string | null;
  logo: string | null;
  image: string | null;
  motd_banner: string | null;
  domain_placeholder: string | null;
  username_placeholder: string | null;
  background_colour: string | null;
  style: string;
}

/** `GET /metadata/get-authentication-methods` — one configured method. */
export interface AuthenticationMethod {
  active: boolean;
  id: string | null;
  alias: string | null;
  icon: string | null;
  method_type: string;
  login_page: string | null;
}

/** The public view of a guarded hostname, returned alongside a new device. */
export interface PublicHostname {
  host: string;
}

/** `POST /auth/request` and `/auth/device/request`. */
export interface AuthRequestResponse {
  ok: boolean;
}

/** `POST /auth/authenticate` — a browser device enrolment. */
export interface AuthenticateResponse {
  ok: boolean;
  device_id: string;
  hostname: PublicHostname;
}

/**
 * `POST /auth/device/authenticate` and `GET /auth/device/oauth/exchange-code`.
 * A one-time token the desktop app exchanges for its own enrolment; the browser
 * never sees the device key.
 */
export interface SetupTokenResponse {
  ok: boolean;
  setup_token: string;
}

/** `GET /oauth/exchange-code` — browser login; the provider token is the credential. */
export interface OauthExchangeResponse {
  ok: boolean;
  access_token: string;
  hostname: PublicHostname;
}

/** Arbitrary data an authentication method needs (e.g. `{ email }`, `{ code }`). */
export type RequestData = Record<string, unknown>;
