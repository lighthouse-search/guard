"use client"
import { useEffect, useRef, useState } from 'react';
import { Guard } from '@oracularhades/guard';
import Frame_AestheticMetadataPanel from '@/components/miscellaneous/frame_aesthetic_metadata_panel';
import './css/magiclink1.css';
import './../../global.css';
import FormStyle_1 from '../forms/form_style1';
import { generatePublicPrivateKey, get_routing_host, handle_new, handle_new_oauth_access_token, handle_new_static_auth } from '@/global';

export default function Magiclink1() {
  const [error, set_error] = useState(null);

  // TODO: ADD STATE PARAMS TO BLOCK CLICKJACKING!

  const shouldSend = useRef(true);

  async function send_magiclink(params) {
    // let host = get_routing_host(window);

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
    let auth_metadata = { authentication_method_id };

    let return_url = null;
    let host = null;
    try {
      return_url = new URL(auth_init_params.return_url);
      host = return_url.host;
    } catch (error) {
      console.log(error);
    }

    let hostname = null;
    if (params.get("magiclink_code")) {
      const keys = await generatePublicPrivateKey();

      let authentication_data = {
        public_key: keys.publicKeyNaked,
        code: params.get("code")
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

      let auth_data = { device_id: response.device_id, private_key: response.private_key };
      await handle_new(auth_data, keys.privateKeyNaked);
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

    // let return_url = auth_init_params.return_url;
    // if (!return_url || return_url.length == 0) {
    //   return_url = hostname.hostname;
    //   if (!return_url.startsWith("https://") && return_url.startsWith("http://")) {
    //     return_url = "https://"+return_url;
    //   }
    // }

    // CHECK URL AGAINST HOSTNAME.

    if (hostname) {
      let hostname_url = new URL(hostname);
      if (hostname_url.host == return_url.host) {
        window.location.href = return_url;
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
