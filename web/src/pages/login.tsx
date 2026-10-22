import { useEffect, useRef, useState } from "react";
import Base from "@/components/Base";
import Form from "@/components/Form";
import LoadingScreen from "@/components/LoadingScreen";
import MetadataPanelFrame from "@/components/MetadataPanelFrame";
import { errorMessage } from "@/lib/errors";
import { getMetadata } from "@/lib/metadata";
import LoginScreen from "@/screens/LoginScreen";
import LoginSplitScreen from "@/screens/LoginSplitScreen";
import type { LoginMetadata } from "@/types";

/**
 * The login page. Guard's reverse proxy sends unauthenticated users here with
 * `?redirect=<url>`; the instance's configured `style` picks the layout.
 */
export default function Login() {
  const shouldRun = useRef(true);
  const [metadata, setMetadata] = useState<LoginMetadata | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!shouldRun.current) {
      return;
    }
    shouldRun.current = false;

    getMetadata()
      .then((loaded) => {
        if (loaded.alias) {
          window.document.title = `Login to ${loaded.alias}`;
        }
        setMetadata(loaded);
      })
      // Surface the real reason (e.g. "Missing params.redirect.") rather than
      // sitting on the loading spinner forever.
      .catch((cause: unknown) => setError(errorMessage(cause)));
  }, []);

  if (error) {
    return (
      <Base>
        <MetadataPanelFrame>
          <Form className="magiclink_form" style={{ rowGap: 5 }}>
            <h2 className="magiclink_checkyouremail">Error</h2>
            <p className="magiclink_wesentalink greyText">{error}</p>
          </Form>
        </MetadataPanelFrame>
      </Base>
    );
  }

  if (!metadata) {
    return <LoadingScreen />;
  }

  return (
    <Base metadata={metadata} className={metadata.style === "login_2" ? "login2" : undefined}>
      {metadata.style === "login_2"
        ? <LoginSplitScreen metadata={metadata} />
        : <LoginScreen metadata={metadata} />}
    </Base>
  );
}
