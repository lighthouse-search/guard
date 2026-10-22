import { getGuardApiURL } from "../api-url.js";
import { objectToParams } from "../params.js";
import { getRequest, requestJson } from "../request.js";
import type { ApiResponse, AuthenticationMethod, Metadata } from "../types.js";

export interface AuthenticationMethodsOptions {
  /**
   * Resolve the general `[device_authentication]` methods instead of a
   * hostname's. One endpoint serves both so auth-method exposure logic cannot
   * diverge between the two flows.
   */
  device_authentication?: boolean;
}

/** Branding for a hostname's login page. */
async function get(hostname: string): Promise<ApiResponse<Metadata>> {
  const query = objectToParams({ hostname });
  return requestJson<ApiResponse<Metadata>>(`${getGuardApiURL()}/metadata?${query}`, getRequest());
}

/**
 * The authentication methods a hostname accepts, or — with
 * `{ device_authentication: true }` — the general device-authentication methods
 * configured under `[device_authentication]` (which take no hostname).
 */
async function get_authentication_methods(hostname: string | null, options?: AuthenticationMethodsOptions): Promise<ApiResponse<AuthenticationMethod[]>> {
  const query = options?.device_authentication
    ? objectToParams({ device_authentication: true })
    : objectToParams({ hostname });

  return requestJson<ApiResponse<AuthenticationMethod[]>>(`${getGuardApiURL()}/metadata/get-authentication-methods?${query}`, getRequest());
}

const metadata = { get, get_authentication_methods };
export default metadata;
