import Base from "@/components/Base";

/**
 * Guard's frontend root. There is nothing to show here: users arrive at
 * /login, /magiclink or /device-authentication, which the Rust server links to
 * directly.
 */
export default function Index() {
  return <Base />;
}
