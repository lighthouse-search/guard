"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import DeviceCodePrompt from "@/components/DeviceCodePrompt";
import Form from "@/components/Form";
import LoadingSpinner from "@/components/LoadingSpinner";
import LoginForm from "@/components/LoginForm";
import MetadataPanelFrame from "@/components/MetadataPanelFrame";
import { errorMessage } from "@/lib/errors";
import { getMetadata } from "@/lib/metadata";
import { isLoopbackCallback } from "@/lib/routing";
import type { DeviceContext, LoginMetadata } from "@/types";

type Phase = "loading" | "confirm" | "form" | "fatal";

/** The message shown for every rejected entry condition, so it reveals nothing. */
const NOT_FROM_APP = "This page must be opened from the Guard desktop app.";

/**
 * Authorises the Guard desktop app, which opens this page as:
 *
 *   /guard/frontend/device-authentication?state=<deeplink_state>&code=<display_code>&callback=<loopback>
 *
 * It reuses the standard login form in device mode, so every configured method
 * (email, "login with X", ...) works with identical logic. The form hands a
 * one-time setup token back to the app over its loopback callback, and the app
 * enrols its own ed25519 key with it — no key is ever presented in the URL.
 */
export default function DeviceAuthScreen() {
  const shouldRun = useRef(true);
  const [phase, setPhase] = useState<Phase>("loading");
  const [metadata, setMetadata] = useState<LoginMetadata | null>(null);
  const [fatal, setFatal] = useState<string | null>(null);
  const [context, setContext] = useState<DeviceContext & { code: string | null }>({
    deeplink_state: null,
    code: null,
    callback: null,
  });

  // Stable identity, so passing it down does not retrigger the form's effect.
  const deviceContext = useMemo<DeviceContext>(
    () => ({ deeplink_state: context.deeplink_state, callback: context.callback }),
    [context.deeplink_state, context.callback],
  );

  useEffect(() => {
    if (!shouldRun.current) {
      return;
    }
    shouldRun.current = false;

    async function run() {
      const params = new URLSearchParams(window.location.search);
      const state = params.get("state");
      // If the app displayed a confirmation code, the user types it before we
      // show the form — it proves intent to authorise (anti-phishing).
      const code = params.get("code");
      // Where to hand the setup token back: a loopback URL the desktop is
      // listening on, else we fall back to the guard:// deep link.
      const callback = params.get("callback");

      // In dev the auth page can be served from a different origin than the API
      // (e.g. the Next dev server), so the desktop passes the API base
      // explicitly. Persisting it makes this origin's calls route correctly.
      const api = params.get("api");
      if (api) {
        localStorage.setItem("custom_guard_api_endpoint", api);
      }

      if (!state) {
        setFatal(NOT_FROM_APP);
        setPhase("fatal");
        return;
      }

      // The callback receives the one-time setup token. Reject anything that is
      // not loopback up front: a non-loopback callback can only be an attempt to
      // redirect the token off this machine.
      if (callback && !isLoopbackCallback(callback)) {
        setFatal(NOT_FROM_APP);
        setPhase("fatal");
        return;
      }

      setContext({ deeplink_state: state, code, callback });

      // Device authentication targets the Guard instance itself, so metadata
      // comes from this host rather than a `?redirect=` target.
      try {
        setMetadata(await getMetadata(window.location.host));
      } catch (cause: unknown) {
        setFatal(errorMessage(cause, "Failed to load instance metadata."));
        setPhase("fatal");
        return;
      }

      setPhase(code ? "confirm" : "form");
    }

    void run();
  }, []);

  if (phase === "fatal") {
    return (
      <MetadataPanelFrame metadata={metadata}>
        <Form className="magiclink_form" style={{ rowGap: 5 }}>
          <h2 className="text-[20px] my-0 font-bold">Error</h2>
          <p className="text-[15px] my-0 text-center w-full muted_text">{fatal}</p>
        </Form>
      </MetadataPanelFrame>
    );
  }

  if (phase === "loading") {
    return (
      <MetadataPanelFrame metadata={metadata}>
        <LoadingSpinner speed="600ms" size={15} style={{ alignSelf: "center" }} />
      </MetadataPanelFrame>
    );
  }

  if (phase === "confirm") {
    return (
      <MetadataPanelFrame metadata={metadata}>
        <DeviceCodePrompt code={context.code} onSuccess={() => setPhase("form")} />
      </MetadataPanelFrame>
    );
  }

  return (
    <MetadataPanelFrame metadata={metadata}>
      <LoginForm
        header="Authorize this device"
        description="Sign in to link the Guard desktop app to your account."
        metadata={metadata}
        device_context={deviceContext}
      />
    </MetadataPanelFrame>
  );
}
