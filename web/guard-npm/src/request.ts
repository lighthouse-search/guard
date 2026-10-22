import { getCredentials } from "./credentials.js";
import { signRequestHeaders, type SignableBody } from "./http-signature.js";
import type { ApiError } from "./types.js";

/** `fetch` options, narrowed to the body types we can sign a digest over. */
export type GuardRequestInit = Omit<RequestInit, "body"> & { body?: SignableBody };

/** Options shared by every Guard endpoint. Kept in one place so they cannot drift. */
const JSON_REQUEST: GuardRequestInit = {
  mode: "cors",
  cache: "default",
  credentials: "same-origin",
  redirect: "error",
  referrerPolicy: "no-referrer",
  headers: { "Content-Type": "application/json" },
};

export function getRequest(): GuardRequestInit {
  return { ...JSON_REQUEST, method: "GET" };
}

export function postRequest(body: unknown): GuardRequestInit {
  return { ...JSON_REQUEST, method: "POST", body: JSON.stringify(body) };
}

function isApiError(value: unknown): value is ApiError {
  return typeof value === "object" && value !== null && (value as { error?: unknown }).error === true;
}

/**
 * Perform the request, signing it when credentials are present, and return both
 * the response and its parsed JSON body (null when the body is not JSON).
 * Throws the server's error object when the body is an API error.
 */
async function send(url: string, properties?: GuardRequestInit): Promise<{ response: Response; json: unknown }> {
  const credentials = getCredentials();

  // Credentials can carry extra query parameters every request must include.
  if (credentials?.additional_data) {
    const target = new URL(url);
    for (const [key, value] of Object.entries(credentials.additional_data)) {
      target.searchParams.set(key, value);
    }
    url = target.href;
  }

  let response: Response;
  if (credentials?.deviceid && credentials.privatekey) {
    // Sign with an RFC 9421 HTTP Message Signature. The device is identified by
    // the `keyid` signature parameter (the device_id).
    const signatureHeaders = await signRequestHeaders({
      method: properties?.method ?? "GET",
      url,
      body: properties?.body,
      deviceId: credentials.deviceid,
      privateKeyPkcs8Base64: credentials.privatekey,
    });

    response = await fetch(url, {
      ...properties,
      headers: { ...properties?.headers, ...signatureHeaders },
    } as RequestInit);
  } else {
    response = await fetch(url, properties as RequestInit);
  }

  let json: unknown = null;
  try {
    json = await response.clone().json();
  } catch {
    // Not JSON — could legitimately be an image or an empty body. Nothing to do.
  }

  if (isApiError(json)) {
    throw json;
  }

  return { response, json };
}

/**
 * Low-level escape hatch: the raw `Response`, with signing and error handling
 * applied. Prefer `requestJson` — it cannot be used un-awaited by mistake.
 */
export async function fetch_wrapper(url: string, properties?: GuardRequestInit): Promise<Response> {
  return (await send(url, properties)).response;
}

/** Perform the request and return its parsed JSON body. */
export async function requestJson<T>(url: string, properties?: GuardRequestInit): Promise<T> {
  const { json } = await send(url, properties);
  if (json === null) {
    throw new Error(`Guard API did not return JSON for ${url}`);
  }
  return json as T;
}
