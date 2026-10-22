import Base from "@/components/Base";
import MagiclinkScreen from "@/screens/MagiclinkScreen";

/**
 * Where an authentication round-trip lands: the magiclink in the user's email,
 * and the OAuth providers' configured redirect_uri, both point here carrying
 * the `state` that identifies the attempt.
 */
export default function Magiclink() {
  return (
    <Base>
      <MagiclinkScreen />
    </Base>
  );
}
