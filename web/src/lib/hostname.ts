import { useEffect, useState } from "react";

/**
 * The hostname the user is on, or `null` until the client has mounted.
 *
 * Reading `window.location` during render would make the prerendered HTML
 * disagree with the first client render and fail hydration, so this waits for
 * an effect. Callers should render nothing (or a placeholder) for `null`.
 */
export function useHostname(): string | null {
  const [hostname, setHostname] = useState<string | null>(null);

  useEffect(() => {
    setHostname(window.location.hostname);
  }, []);

  return hostname;
}
