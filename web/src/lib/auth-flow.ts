import { getRoutingHost } from "@/lib/routing";
import { generateState } from "@/lib/random";
import type { ConfirmMetadataItem, DeviceContext } from "@/types";

const CONFIRM_METADATA_KEY = "confirm_metadata";

/**
 * The in-flight authentication attempts.
 *
 * An array rather than a single value: a user who requests two magiclinks must
 * be able to complete either one, so a second attempt must not overwrite the
 * state of the first.
 */
export function readConfirmMetadata(): ConfirmMetadataItem[] {
  const raw = localStorage.getItem(CONFIRM_METADATA_KEY);
  if (!raw) {
    return [];
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }

  // Tolerate a bare object from an older build that stored a single attempt.
  return Array.isArray(parsed) ? (parsed as ConfirmMetadataItem[]) : [parsed as ConfirmMetadataItem];
}

function writeConfirmMetadata(items: ConfirmMetadataItem[]): void {
  localStorage.setItem(CONFIRM_METADATA_KEY, JSON.stringify(items));
}

/** Find the attempt a returning magiclink/OAuth `state` belongs to. */
export function findConfirmMetadata(state: string | null): ConfirmMetadataItem | null {
  if (!state) {
    return null;
  }

  return readConfirmMetadata().find((item) => item.state === state) ?? null;
}

/**
 * Drop a completed attempt, so its link cannot be replayed and the list does
 * not grow without bound.
 */
export function consumeConfirmMetadata(item: ConfirmMetadataItem): void {
  writeConfirmMetadata(readConfirmMetadata().filter((candidate) => candidate.state !== item.state));
}

function beginAttempt(item: ConfirmMetadataItem): ConfirmMetadataItem {
  writeConfirmMetadata([...readConfirmMetadata(), item]);
  return item;
}

/**
 * Begin a browser login: mint a `state` and record what it belongs to, so the
 * magiclink completion can match it back.
 */
export function startAuth(authentication_method: string): ConfirmMetadataItem {
  return beginAttempt({
    authentication_method,
    state: generateState(),
    redirect_url: getRoutingHost().href,
  });
}

/**
 * Begin the desktop device-authentication flow.
 *
 * Like `startAuth`, but it also carries the desktop's deeplink `state` and
 * loopback callback through the round-trip, so the magiclink completion can
 * deep-link a one-time setup token back to the app. The device key is never
 * handled here — the desktop enrols its own key with that token.
 *
 * Device auth targets the Guard instance itself, so there is no `?redirect=`.
 */
export function startDeviceAuth(authentication_method: string, device_context: DeviceContext): ConfirmMetadataItem {
  return beginAttempt({
    authentication_method,
    state: generateState(),
    redirect_url: `https://${window.location.host}`,
    device_authentication: true,
    deeplink_state: device_context.deeplink_state,
    callback: device_context.callback,
  });
}
