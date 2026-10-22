"use client";
import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/router";
import { Guard } from "@oracularhades/guard";
import Form from "@/components/Form";
import MetadataPanelFrame from "@/components/MetadataPanelFrame";
import { consumeConfirmMetadata, findConfirmMetadata } from "@/lib/auth-flow";
import { errorMessage } from "@/lib/errors";
import { generateDeviceKeyPair } from "@/lib/keys";
import { isLoopbackCallback } from "@/lib/routing";
import { storeAuth, storeOauthAccessToken, storeStaticAuth } from "@/lib/session";
import type { ConfirmMetadataItem } from "@/types";

/**
 * Completes an authentication round-trip: the user has come back from their
 * email (`?magiclink_code=`) or from an OAuth provider (`?code=`), carrying the
 * `state` that identifies which attempt this is.
 */
export default function MagiclinkScreen() {
  const router = useRouter();
  const shouldRun = useRef(true);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  useEffect(() => {
    if (!shouldRun.current) {
      return;
    }
    shouldRun.current = false;

    // complete() awaits outside its inner try/catch blocks; without this catch a
    // throw would reject silently and leave the UI on the loading view forever.
    complete(new URLSearchParams(window.location.search)).catch((cause: unknown) => {
      console.log(cause);
      setError(errorMessage(cause));
    });
  });

  /**
   * Hand a one-time setup token to the desktop app.
   *
   * Both device-auth methods (email magiclink and "login with X") end here: the
   * server issued a setup token, and the desktop enrols its own ed25519 key with
   * it — the browser never sees the device key.
   */
  function deliverSetupToken(attempt: ConfirmMetadataItem, setupToken: string) {
    // Consume the state so the link cannot be replayed.
    consumeConfirmMetadata(attempt);

    // Re-check the callback is loopback here too: this is the moment the setup
    // token is exposed, so it is never handed to a non-loopback URL even if a
    // bad value somehow reached storage.
    if (attempt.callback && !isLoopbackCallback(attempt.callback)) {
      setError("Invalid callback — refusing to send the setup token off this machine.");
      return;
    }

    const params = new URLSearchParams({
      state: attempt.deeplink_state ?? "",
      setup_token: setupToken,
    });

    window.location.href = attempt.callback
      ? `${attempt.callback}?${params.toString()}`
      : `guard://auth-callback?${params.toString()}`;

    setDone("You're all set — return to the Guard app.");
  }

  async function complete(params: URLSearchParams) {
    const state = params.get("state");
    if (!state) {
      setError("Missing state param.");
      return;
    }

    // The attempt must have been started in this browser. An array is stored so
    // requesting a second link does not invalidate the first.
    const attempt = findConfirmMetadata(state);
    if (!attempt) {
      setError("Invalid state param. Try going to /login and starting again.");
      return;
    }

    const authenticationMethod = params.get("authentication_method") ?? attempt.authentication_method;
    const magiclinkCode = params.get("magiclink_code");
    const oauthCode = params.get("code");

    let redirectUrl: URL | null = null;
    try {
      redirectUrl = new URL(attempt.redirect_url);
    } catch (cause: unknown) {
      console.log(cause);
    }

    let authenticatedHost: string | null = null;

    if (magiclinkCode) {
      // Device authentication: we neither generate nor handle the device key.
      // The server issues a one-time setup token which we deep-link to the
      // desktop app, and the app enrols its own public key with it.
      if (attempt.device_authentication) {
        const response = await Guard().auth.device_authenticate(authenticationMethod, { code: magiclinkCode });
        deliverSetupToken(attempt, response.setup_token);
        return;
      }

      if (!redirectUrl) {
        setError("This link has no valid redirect target.");
        return;
      }

      const keys = await generateDeviceKeyPair();
      const response = await Guard().auth.authenticate(redirectUrl.host, authenticationMethod, {
        public_key: keys.publicKeyBase64,
        code: magiclinkCode,
      });
      authenticatedHost = response.hostname.host;

      const auth = { device_id: response.device_id, private_key: keys.privateKeyPkcs8Base64 };
      storeAuth(auth, { authentication_method: authenticationMethod });
      await storeStaticAuth(auth);
    } else if (oauthCode) {
      // Device-authentication OAuth ("login with X", opened by the desktop app).
      // The server resolves the external user and issues a one-time setup token
      // rather than an access token; we hand it to the desktop.
      if (attempt.device_authentication) {
        const response = await Guard().oauth.device_exchange_code(authenticationMethod, oauthCode);
        deliverSetupToken(attempt, response.setup_token);
        return;
      }

      if (!redirectUrl) {
        setError("This link has no valid redirect target.");
        return;
      }

      const response = await Guard().oauth.exchange_code(redirectUrl.host, authenticationMethod, oauthCode);
      authenticatedHost = response.hostname.host;

      storeAuth({ access_token: response.access_token }, { authentication_method: authenticationMethod });
      storeOauthAccessToken(response.access_token);
    } else {
      setError("This link is missing its authentication code.");
      return;
    }

    // Credentials are stored; the state is now just bloat.
    consumeConfirmMetadata(attempt);

    // Only redirect when the server confirms it authenticated the very host the
    // `redirect` parameter names, so a tampered `redirect` cannot send a freshly
    // authenticated user to an unrelated origin. The same-host test is kept from
    // the original: a redirect back to the Guard frontend's own host is refused
    // rather than followed.
    const redirectable = redirectUrl !== null
      && authenticatedHost !== null
      && redirectUrl.host !== new URL(window.location.href).host
      && new URL(`https://${authenticatedHost}`).host === redirectUrl.host;

    if (!redirectable) {
      setError("Sorry, we couldn't redirect you. Just manually go to the page you want.");
      return;
    }

    window.location.href = (redirectUrl as URL).href;
  }

  if (error) {
    return (
      <MetadataPanelFrame>
        <Form className="magiclink_form" style={{ rowGap: 5 }}>
          <h2 className="magiclink_checkyouremail">Error</h2>
          <p className="magiclink_wesentalink greyText">{error}</p>
          <button onClick={() => void router.push("/login")}>Try again</button>
        </Form>
      </MetadataPanelFrame>
    );
  }

  if (done) {
    return (
      <MetadataPanelFrame>
        <Form className="magiclink_form" style={{ rowGap: 5 }}>
          <h2 className="magiclink_checkyouremail">Device authorized</h2>
          <p className="magiclink_wesentalink greyText">{done}</p>
        </Form>
      </MetadataPanelFrame>
    );
  }

  return (
    <MetadataPanelFrame>
      <Form className="magiclink_form" style={{ rowGap: 5 }}>
        <img className="magiclink_img" src="/guard/frontend/assets/crystalball.png" alt="" />
        <h2 className="magiclink_checkyouremail">Opening the portal...</h2>
        <p className="magiclink_wesentalink">Logging you in, just a moment.</p>
      </Form>
    </MetadataPanelFrame>
  );
}
