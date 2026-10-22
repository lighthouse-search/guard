import Base from "@/components/Base";
import DeviceAuthScreen from "@/screens/DeviceAuthScreen";

/**
 * Opened by the Guard desktop app to authorise itself. The app generates its own
 * keypair and keeps the private key in secure storage; this page only
 * authenticates the user, then hands back a one-time setup token the app uses to
 * enrol its public key.
 */
export default function DeviceAuthentication() {
  return (
    <Base>
      <DeviceAuthScreen />
    </Base>
  );
}
