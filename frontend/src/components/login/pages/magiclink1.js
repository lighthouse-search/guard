"use client"
import { useEffect, useRef, useState } from 'react';
import { Guard } from '@oracularhades/guard';
import Frame_AestheticMetadataPanel from '@/components/miscellaneous/frame_aesthetic_metadata_panel';
import './css/magiclink1.css';
import './../../global.css';
import FormStyle_1 from '../forms/form_style1';
import { generatePublicPrivateKey, get_auth_url, handle_new, is_motionfans_site } from '@/global';

export default function Magiclink1() {
  const [error, set_error] = useState(null);

  // TODO: ADD STATE PARAMS TO BLOCK CLICKJACKING!

  const shouldSend = useRef(true);

  async function send_magiclink(params) {
    const keys = await generatePublicPrivateKey();

    let response = null;
    try {
      response = await Guard().authenticate(params.get("authentication_method"), { code: params.get("code"), referer: "localhost", public_key: keys.publicKeyNaked });
    } catch (error) {
      console.log(error);
      set_error(error.message);
      return;
    }

    await handle_new(response.device_id, keys.privateKeyNaked);
    // if (response.authentication_method) {
    //   window.location.href = response.authentication_method.login_page;
    // }

    const return_url = await localStorage.getItem("return_url");
    if (return_url) {
      try {
        new URL(return_url);
      } catch (error) {
        alert("return_url is invalid");
        return;
      }

      if (is_motionfans_site(return_url) != true) {
        alert("return_url is not a valid motionfans site.");
        return;
      }

      window.location.href = return_url;
    }
  }

  useEffect(() => {
    if (shouldSend.current != true) { return; }
    shouldSend.current = false;

    const params = new URLSearchParams(document.location.search);

    send_magiclink(params);
  });

  return (
    <Frame_AestheticMetadataPanel>
      {error == null && <FormStyle_1 header={false} className="magiclink_form" style={{ rowGap: 5 }}>
        <img className='magiclink_img' src="/frontend/assets/crystalball.png"/>
        <h2 className='magiclink_checkyouremail'>Opening the portal...</h2>
        <p className='magiclink_wesentalink'>Logging you in, just a moment.</p>
      </FormStyle_1>}

      {error && <FormStyle_1 header={false} className="magiclink_form" style={{ rowGap: 5 }}>
        {/* <img className='magiclink_img' src="/frontend/assets/warningsign.png"/> */}
        <h2 className='magiclink_checkyouremail'>Error</h2>
        <p className='magiclink_wesentalink greyText'>{error}</p>
      </FormStyle_1>}
    </Frame_AestheticMetadataPanel>
  );
}
