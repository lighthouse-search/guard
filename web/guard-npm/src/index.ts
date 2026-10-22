import auth from "./api/auth.js";
import metadata from "./api/metadata.js";
import oauth from "./api/oauth.js";
import { getCreds, setCredentials } from "./credentials.js";
import { fetch_wrapper } from "./request.js";
import type { Credentials } from "./types.js";

/** The Guard API surface returned by `Guard()`. */
export interface GuardClient {
  metadata: typeof metadata;
  auth: typeof auth;
  oauth: typeof oauth;
  /** Raw signed `fetch`, for endpoints this package does not wrap. */
  fetch_wrapper: typeof fetch_wrapper;
}

/**
 * Entry point for the Guard API.
 *
 * Pass credentials to enrol them for this and every later call — requests are
 * then signed with an RFC 9421 HTTP Message Signature:
 *
 *     Guard({ deviceid, privatekey }).auth.authenticate(...)
 *
 * Call it with no arguments for the unauthenticated endpoints (the whole
 * pre-login flow: metadata, magiclink request, oauth code exchange). Doing so
 * leaves any previously enrolled credentials in place.
 */
export function Guard(credentials?: Credentials | null): GuardClient {
  if (credentials) {
    setCredentials(credentials);
  }

  return { metadata, auth, oauth, fetch_wrapper };
}

export { getCreds };
export { signDataToken, signStaticCredential, signRequestHeaders } from "./http-signature.js";
export type { SignRequestOptions, StaticCredential, StaticCredentialOptions } from "./http-signature.js";
export type {
  ApiError,
  ApiResponse,
  AuthRequestResponse,
  AuthenticateResponse,
  AuthenticationMethod,
  Credentials,
  Metadata,
  OauthExchangeResponse,
  PublicHostname,
  RequestData,
  SetupTokenResponse,
} from "./types.js";
export type { AuthenticationMethodsOptions } from "./api/metadata.js";
