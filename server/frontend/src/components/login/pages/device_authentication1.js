"use client"
import { useEffect, useRef, useState } from 'react';
import { Guard } from '@oracularhades/guard';
import Frame_AestheticMetadataPanel from '@/components/miscellaneous/frame_aesthetic_metadata_panel';
import FormStyle_1 from '../forms/form_style1';
import Input_with_header from '@/components/input/input_with_header';
import LoadingSpinner from '@/components/miscellaneous/loadingspinner';
import Authenticating_desktop_application from '../forms/special_styles/authenticating_desktop_application';
import Check_your_email from '../forms/special_styles/check_your_email';
import { device_auth_init_params, is_loopback_callback } from '@/global';
import './css/magiclink1.css';
import './../../global.css';

// phase: loading | confirm | email | check_email | fatal
export default function Device_authentication1() {
  const should_run = useRef(true);
  const [phase, set_phase] = useState('loading');
  const [metadata, set_metadata] = useState(null);
  const [email_method, set_email_method] = useState(null);
  const [email, set_email] = useState("");
  const [error, set_error] = useState(null);
  const [fatal, set_fatal] = useState(null);
  const [loading, set_loading] = useState(false);

  // Context handed to us by the desktop app via the URL.
  const ctx = useRef({ deeplink_state: null, public_key: null, code: null });

  async function run() {
    const params = new URLSearchParams(document.location.search);
    const state = params.get("state");
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
    // URL. On success we deep-link a one-time setup token back, and the desktop
    // enrolls its own key with it.
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
    const host = window.location.host;
    try {
      const metadata_v = await Guard().metadata.get(host);
      set_metadata(metadata_v.data);

      // Devices authenticate generally, so methods come from the
      // hostname-independent [device_authentication] config.
      const methods_v = await Guard().metadata.get_device_authentication_methods();
      const email_m = (methods_v.data || []).find((m) => m.method_type == "email");
      set_email_method(email_m || null);
    } catch (error) {
      set_fatal(error.message || "Failed to load instance metadata.");
      set_phase('fatal');
      return;
    }

    // If the app displayed a confirmation code, ask the user to enter it first
    // (anti-phishing — proves they intend to authorize this desktop app).
    set_phase(code ? 'confirm' : 'email');
  }

  useEffect(() => {
    if (should_run.current != true) { return; }
    should_run.current = false;
    run();
  });

  async function start_email_authentication() {
    if (!email_method) {
      set_error("Email authentication is not enabled on this instance.");
      return;
    }
    set_loading(true);
    set_error(null);

    try {
      // Stash the deeplink state so the magiclink completion (magiclink1) can
      // deep-link the setup token back to the right desktop request.
      const init = await device_auth_init_params(email_method.id, {
        deeplink_state: ctx.current.deeplink_state,
        callback: ctx.current.callback
      });

      const response = await Guard().auth.device_request(email_method.id, { email, state: init.state });
      if (response.ok == true) {
        set_phase('check_email');
        return;
      }
      // Resolved but not ok — surface an error instead of silently dropping
      // back to the form with no feedback.
      set_error("Something went wrong. Please try again.");
    } catch (error) {
      set_error(error.message || "Something went wrong.");
    }

    set_loading(false);
  }

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
          on_success={() => { set_phase('email'); }}
        />
      </Frame_AestheticMetadataPanel>
    );
  }

  if (phase == 'check_email') {
    return (
      <Frame_AestheticMetadataPanel metadata={metadata}>
        <Check_your_email/>
      </Frame_AestheticMetadataPanel>
    );
  }

  // phase == 'email'
  let email_placeholder = null;
  if (metadata) {
    email_placeholder = `${metadata.username_placeholder}@${metadata.domain_placeholder}`;
  }

  return (
    <Frame_AestheticMetadataPanel metadata={metadata}>
      <FormStyle_1 header={false} className="magiclink_form" style={{ rowGap: 8 }}>
        <div className='flex flex-col gap-y-[2px]'>
          <h2 className='text-[20px] my-0 font-bold'>Authorize this device</h2>
          <p className='text-[15px] my-0 text-center w-full text-[#5a5a5a]'>Sign in to link the Guard desktop app to your account.</p>
        </div>

        {loading == false && <div className='FormStyle_1_div'>
          {error != null && <p className='FormStyle_1_div_error font-bold'>Error: {error}</p>}
          {email_method && <div className='FormStyle_1_div_email'>
            <Input_with_header header="Email" placeholder={email_placeholder} value={email} onChange={(e) => { set_email(e.target.value); }} onKeyDown={(e) => { if (e.key == "Enter") { start_email_authentication(); } }} autoCapitalize="off"/>
            <button className='FormStyle_1_div_login_button' onClick={() => { start_email_authentication(); }}>Continue</button>
          </div>}
          {!email_method && <p className='FormStyle_1_div_error'>Email authentication is not enabled on this instance.</p>}
        </div>}
        {loading == true && <LoadingSpinner speed="600ms" style={{ width: 15, height: 15, alignSelf: "center" }}/>}
      </FormStyle_1>
    </Frame_AestheticMetadataPanel>
  );
}
