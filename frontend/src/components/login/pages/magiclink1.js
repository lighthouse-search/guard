"use client"
import { useEffect, useRef, useState } from 'react';
import { Guard } from '@oracularhades/guard';
import Frame_AestheticMetadataPanel from '@/components/miscellaneous/frame_aesthetic_metadata_panel';
import './css/magiclink1.css';
import './../../global.css';
import FormStyle_1 from '../forms/form_style1';
import { generatePublicPrivateKey, handle_new, handle_new_oauth_access_token, handle_new_static_auth } from '@/global';

export default function Magiclink1() {
  const [error, set_error] = useState(null);

  const shouldSend = useRef(true);

  async function send_magiclink(params) {
    const confirm_metadata = await localStorage.getItem("confirm_metadata");
    if (!confirm_metadata) {
      set_error("missing confirm_metadata. Try going to /login and starting again.");
      return;
    }
    await localStorage.removeItem("confirm_metadata");

    let auth_init_params = JSON.parse(confirm_metadata);
    if (!params.get("state") || params.get("state") != auth_init_params.state) {
      set_error("Invalid state param.");
      return;
    }

    let authentication_method_id = params.get("authentication_method");
    let auth_metadata = { authentication_method: authentication_method_id };

    let redirect_url = null;
    let host = null;
    try {
      redirect_url = new URL(auth_init_params.redirect_url);
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
      </FormStyle_1>}
    </Frame_AestheticMetadataPanel>
  );
}
