import { getGuardApiURL } from "../api-url.js";
import { objectToParams } from "../params.js";
import { postRequest, requestJson } from "../request.js";
import type { AuthRequestResponse, AuthenticateResponse, RequestData, SetupTokenResponse } from "../types.js";

/** Begin authentication for a host (e.g. send a magiclink email). */
async function request(host: string, authentication_method: string, request_data: RequestData): Promise<AuthRequestResponse> {
  const query = objectToParams({ host });
  return requestJson<AuthRequestResponse>(
    `${getGuardApiURL()}/auth/request?${query}`,
    postRequest({ authentication_method, request_data })
  );
}

/** Complete authentication for a host, enrolling the browser's device key. */
async function authenticate(host: string, authentication_method: string, request_data: RequestData): Promise<AuthenticateResponse> {
  const query = objectToParams({ host });
  return requestJson<AuthenticateResponse>(
    `${getGuardApiURL()}/auth/authenticate?${query}`,
    postRequest({ authentication_method, request_data })
  );
}

// Device authentication is general rather than per-host, so these carry no
// `host` — the server resolves the context from [device_authentication].

/** Begin device authentication for the desktop app. */
async function device_request(authentication_method: string, request_data: RequestData): Promise<AuthRequestResponse> {
  return requestJson<AuthRequestResponse>(
    `${getGuardApiURL()}/auth/device/request`,
    postRequest({ authentication_method, request_data })
  );
}

/**
 * Complete device authentication. Returns a one-time setup token the desktop app
 * exchanges for its own enrolment — the browser never handles the device key.
 */
async function device_authenticate(authentication_method: string, request_data: RequestData): Promise<SetupTokenResponse> {
  return requestJson<SetupTokenResponse>(
    `${getGuardApiURL()}/auth/device/authenticate`,
    postRequest({ authentication_method, request_data })
  );
}

const auth = { request, authenticate, device_request, device_authenticate };
export default auth;
