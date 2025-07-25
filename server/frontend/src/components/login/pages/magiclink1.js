"use client"
import { useEffect, useRef, useState } from 'react';
import { Guard } from '@oracularhades/guard';
import Frame_AestheticMetadataPanel from '@/components/miscellaneous/frame_aesthetic_metadata_panel';
import './css/magiclink1.css';
import './../../global.css';
import FormStyle_1 from '../forms/form_style1';
import { generatePublicPrivateKey, handle_new, handle_new_oauth_access_token, handle_new_static_auth } from '@/global';
import { useRouter } from 'next/router';

export default function Magiclink1() {
  const router = useRouter();
  const [error, set_error] = useState(null);

  const shouldSend = useRef(true);

  async function send_magiclink(params) {
    if (!params.get("state")) {
      set_error("Missing state param.");
      return;
    }

    // Check confirm_state localstorage.
    const confirm_metadata_localstorage = await localStorage.getItem("confirm_metadata");
    if (!confirm_metadata_localstorage) {
      set_error("missing confirm_metadata. Try going to /login and starting again.");
      return;
    }
    // Parse confirm_metadata array. Confirm_metadata is an array so if the user creates multiple links (e.g enters their email twice) it won't overwrite the state. If the state is overwritten and the user clicks an older link, it will fail.
    const confirm_metadata = JSON.parse(confirm_metadata_localstorage);

    // Within the array of states, we need to iterate and check if this state is valid.
    const relevant_state = confirm_metadata.find(d => d.state === params.get("state"));
    if (!relevant_state || params.get("state") != relevant_state.state) {
      set_error("Invalid state param.");
      return;
    }

    let authentication_method_id = params.get("authentication_method");
    let auth_metadata = { authentication_method: authentication_method_id };

    let redirect_url = null;
    let host = null;
    try {
      redirect_url = new URL(relevant_state.redirect_url);
      host = redirect_url.host;
    } catch (error) {
      console.log(error);
    }

    let hostname = null;
    if (params.get("magiclink_code")) {
      const keys = await generatePublicPrivateKey();

      let authentication_data = {
        public_key: keys.publicKeyNaked,
        code: params.get("magiclink_code")
      }

      let response = null;
      try {
        response = await Guard().auth.authenticate(host, authentication_method_id, authentication_data);
        hostname = response.hostname;
      } catch (error) {
        console.log(error);
        set_error(error.message);
        return;
      }

      let private_key = keys.privateKeyNaked;
      let auth_data = { device_id: response.device_id, private_key: private_key };
      await handle_new(auth_data, auth_metadata, private_key);
      await handle_new_static_auth(auth_data, private_key);
    } else if (params.get("code")) {
      let response = null;
      try {
        response = await Guard().oauth.exchange_code(host, authentication_method_id, params.get("code"));
        hostname = response.hostname;
      } catch (error) {
        console.log(error);
        set_error(error.message);
        return;
      }

      let auth_data = { access_token: response.access_token };
      await handle_new(auth_data, auth_metadata, null);
      await handle_new_oauth_access_token(response.access_token);
    }


    // We've handled credentials and are about to redirect, remove state from array as it's now bloat.
    let new_confirm_metadata = confirm_metadata;
    new_confirm_metadata.splice(new_confirm_metadata.indexOf(relevant_state), 1);
    await localStorage.setItem("confirm_metadata", JSON.stringify(new_confirm_metadata));

    // If a hostname was returned, it means the host param we provided as valid. Provided redirect_uri is still in good shape up until this part of the function, we're good to redirect.
    if (hostname && redirect_url.host != new URL(window.location.href).host) {
      let hostname_url = new URL("https://"+hostname.host);
      if (hostname_url.host == redirect_url.host) {
        window.location.href = redirect_url.href;
      }
    } else {
      alert("Sorry, we couldn't redirect you. Just manually go to the page you want.")
    }
  }

  useEffect(() => {
    if (shouldSend.current != true && typeof window !== "undefined") { return; }
    shouldSend.current = false;

    const params = new URLSearchParams(document.location.search);

    send_magiclink(params);
  });

  return (
    <Frame_AestheticMetadataPanel>
      {error == null && <FormStyle_1 header={false} className="magiclink_form" style={{ rowGap: 5 }}>
        <img className='magiclink_img' src="/guard/frontend/assets/crystalball.png"/>
        <h2 className='magiclink_checkyouremail'>Opening the portal...</h2>
        <p className='magiclink_wesentalink'>Logging you in, just a moment.</p>
      </FormStyle_1>}

      {error && <FormStyle_1 header={false} className="magiclink_form" style={{ rowGap: 5 }}>
        {/* <img className='magiclink_img' src="/guard/frontend/assets/warningsign.png"/> */}
        <h2 className='magiclink_checkyouremail'>Error</h2>
        <p className='magiclink_wesentalink greyText'>{error}</p>
        <button onClick={() => { router.push("/login"); }}>Try again</button>
      </FormStyle_1>}
    </Frame_AestheticMetadataPanel>
  );
}
