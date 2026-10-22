/**
 * An unguessable value for the `state` parameter that ties a magiclink or OAuth
 * round-trip back to the request that started it.
 *
 * This must not be predictable — `state` is what stops an attacker-supplied
 * link from completing against a session they did not initiate — so it comes
 * from the CSPRNG, not Math.random(). The trailing timestamp keeps entries
 * recognisable when inspecting localStorage.
 */
export function generateState(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  const random = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${random}${Date.now()}`;
}
