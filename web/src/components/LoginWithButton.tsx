import { startAuth, startDeviceAuth } from "@/lib/auth-flow";
import type { AuthenticationMethod, DeviceContext } from "@/types";

interface LoginWithButtonProps {
  authentication_method: AuthenticationMethod;
  /** When set, this begins device authentication for the desktop app instead. */
  device_context?: DeviceContext | null;
}

/** "Login with <provider>" — sends the user to the provider's login page. */
export default function LoginWithButton({ authentication_method, device_context }: LoginWithButtonProps) {
  const service = authentication_method.alias ?? authentication_method.id ?? "provider";

  function handleClick() {
    const methodId = authentication_method.id;
    if (!methodId || !authentication_method.login_page) {
      return;
    }

    // In device mode, carry the deeplink state and loopback callback through the
    // OAuth round-trip so the magiclink completion can hand the setup token back
    // to the desktop app; otherwise this is a normal browser login.
    const attempt = device_context
      ? startDeviceAuth(methodId, device_context)
      : startAuth(methodId);

    const loginPage = new URL(authentication_method.login_page);
    loginPage.searchParams.set("state", attempt.state);

    window.location.href = loginPage.href;
  }

  return (
    <button className="login_with" onClick={handleClick}>
      {authentication_method.icon && <img src={authentication_method.icon} alt="" />}
      <p>Login with {service}</p>
    </button>
  );
}
