"use client"
import { useEffect, useRef, useState } from 'react';
import { Guard } from '@oracularhades/guard';
import Frame_AestheticMetadataPanel from '@/components/miscellaneous/frame_aesthetic_metadata_panel';
import FormStyle_1 from '../forms/form_style1';
import FormStyle_special_1 from '../forms/form_style_special1';
import LoadingSpinner from '@/components/miscellaneous/loadingspinner';
import Authenticating_desktop_application from '../forms/special_styles/authenticating_desktop_application';
import { is_loopback_callback } from '@/global';
import './css/magiclink1.css';
import './../../global.css';

// Opened by the Guard desktop app. This page no longer builds its own login
// form — it reuses the standard login form (FormStyle_special_1) in "device
// mode", so every configured method (email, "login with X", ...) is supported
// with identical logic. The form hands a one-time setup token back to the
// desktop over the loopback callback; the desktop enrolls its own ed25519 key.
//
// phase: loading | confirm | form | fatal
export default function Device_authentication1() {
  const should_run = useRef(true);
  const [phase, set_phase] = useState('loading');
  const [metadata, set_metadata] = useState(null);
  const [fatal, set_fatal] = useState(null);

  // Context handed to us by the desktop app via the URL.
  const ctx = useRef({ deeplink_state: null, code: null, callback: null });

  async function run() {
    const params = new URLSearchParams(document.location.search);
    const state = params.get("state");
    // If the app displayed a confirmation code, we ask the user to enter it
    // before showing the form (anti-phishing — proves intent to authorize).
    const code = params.get("code");
    // Where to hand the setup token back: a loopback URL the desktop is
    // listening on (preferred), else we fall back to the guard:// deep link.
    const callback = params.get("callback");

    // In dev the auth page can be served from a different host than the API
    // (e.g. a Next dev server), so the desktop passes the API base explicitly.
    // Persisting it makes getGuardApiURL() route this origin's calls correctly.
    const api = params.get("api");
    if (api) {
      localStorage.setItem("custom_guard_api_endpoint", api);
    }

    // No public_key here by design — the desktop never presets its key in the
    // URL. On success the form deep-links a one-time setup token back, and the
    // desktop enrolls its own key with it.
    if (!state) {
      set_fatal("This page must be opened from the Guard desktop app.");
      set_phase('fatal');
      return;
    }

    // The callback (if provided) receives the one-time setup token. Reject
    // anything that isn't a loopback address up front — a non-loopback callback
    // can only be an attempt to redirect the token off this machine (phishing).
    if (callback && is_loopback_callback(callback) == false) {
      set_fatal("This page must be opened from the Guard desktop app.");
      set_phase('fatal');
      return;
    }
    ctx.current = { deeplink_state: state, code, callback };

    // Device authentication targets the Guard instance itself.
    try {
      const metadata_v = await Guard().metadata.get(window.location.host);
      set_metadata(metadata_v.data);
    } catch (error) {
      set_fatal(error.message || "Failed to load instance metadata.");
      set_phase('fatal');
      return;
    }

    set_phase(code ? 'confirm' : 'form');
  }

  useEffect(() => {
    if (should_run.current != true) { return; }
    should_run.current = false;
    run();
  });

  if (phase == 'fatal') {
    return (
      <Frame_AestheticMetadataPanel metadata={metadata}>
        <FormStyle_1 header={false} className="magiclink_form" style={{ rowGap: 5 }}>
          <h2 className='text-[20px] my-0 font-bold'>Error</h2>
          <p className='text-[15px] my-0 text-center w-full text-[#5a5a5a]'>{fatal}</p>
        </FormStyle_1>
      </Frame_AestheticMetadataPanel>
    );
  }

  if (phase == 'loading') {
    return (
      <Frame_AestheticMetadataPanel metadata={metadata}>
        <LoadingSpinner speed="600ms" style={{ width: 15, height: 15, alignSelf: "center" }}/>
      </Frame_AestheticMetadataPanel>
    );
  }

  if (phase == 'confirm') {
    return (
      <Frame_AestheticMetadataPanel metadata={metadata}>
        <Authenticating_desktop_application
          code={ctx.current.code}
          on_success={() => { set_phase('form'); }}
        />
      </Frame_AestheticMetadataPanel>
    );
  }

  // phase == 'form' — the standard login form, in device mode.
  return (
    <Frame_AestheticMetadataPanel metadata={metadata}>
      <FormStyle_special_1
        header="Authorize this device"
        description="Sign in to link the Guard desktop app to your account."
        metadata={metadata}
        device_context={{ deeplink_state: ctx.current.deeplink_state, callback: ctx.current.callback }}
      />
    </Frame_AestheticMetadataPanel>
  );
}
