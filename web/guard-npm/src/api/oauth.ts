import { getGuardApiURL } from "../api-url.js";
import { objectToParams } from "../params.js";
import { getRequest, requestJson } from "../request.js";
import type { OauthExchangeResponse, SetupTokenResponse } from "../types.js";

/** Browser login: exchange the provider's `code` for an access token. */
async function exchange_code(host: string, authentication_method: string, code: string): Promise<OauthExchangeResponse> {
  const query = objectToParams({ host, authentication_method, code });
  return requestJson<OauthExchangeResponse>(`${getGuardApiURL()}/oauth/exchange-code?${query}`, getRequest());
}

/**
 * Device authentication ("login with X", opened by the desktop app and completed
 * in the browser). No `host` — the server resolves the
 * `[device_authentication]` context and returns a one-time setup token instead
 * of an access token, which the browser hands to the desktop over its loopback
 * callback.
 */
async function device_exchange_code(authentication_method: string, code: string): Promise<SetupTokenResponse> {
  const query = objectToParams({ authentication_method, code });
  return requestJson<SetupTokenResponse>(`${getGuardApiURL()}/auth/device/oauth/exchange-code?${query}`, getRequest());
}

const oauth = { exchange_code, device_exchange_code };
export default oauth;
