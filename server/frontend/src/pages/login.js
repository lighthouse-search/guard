import React, { useEffect, useRef, useState } from 'react';
import Base from '@/components/base';
import { useRouter } from 'next/router';
import "../../styles/global.css";
import Login1_special from '@/components/login/pages/login1_special'
import Login2_special from '@/components/login/pages/login2_special';
import Loading from '@/components/navigating/in-progress/loading';
import Frame_AestheticMetadataPanel from '@/components/miscellaneous/frame_aesthetic_metadata_panel';
import FormStyle_1 from '@/components/login/forms/form_style1';
import '@/components/login/pages/css/magiclink1.css';
import { get_metadata } from '@/global';

export default function Login() {
  const router = useRouter();
  const shouldSend = useRef(true);
  const [metadata, set_metadata] = useState(null);
  const [error, set_error] = useState(null);

  async function check_logged_in() {
    const params = new URLSearchParams(document.location.search);

    // if (await is_authenticated() == true) {
    //   const auth = JSON.parse(await localStorage.getItem("auth"));
    //   await handle_new_static_auth(auth, auth.private_key);

    //   Here we'd check if the redirect in params.redirect are valid and redirect back, but there aren't standalone endpoints for that yet.
    //   return;
    // }
  }

  async function run() {
    try {
      const metadata_v = await get_metadata();
      if (metadata_v && metadata_v.alias) {
        window.document.title = `Login to ${metadata_v.alias}`;
      }
      set_metadata(metadata_v);
    } catch (error) {
      // Surface the real reason (e.g. "Missing params.redirect.") instead of
      // hanging on the loading spinner forever.
      set_error(typeof error === "string" ? error : (error?.message || "Something went wrong."));
    }
  }

  useEffect(() => {
    if (shouldSend.current != true) { return; }
    shouldSend.current = false;

    run();
    check_logged_in()
  });

  if (error) {
    return (
      <Frame_AestheticMetadataPanel metadata={metadata}>
        <FormStyle_1 header={false} className="magiclink_form" style={{ rowGap: 5 }}>
          <h2 className='magiclink_checkyouremail'>Error</h2>
          <p className='magiclink_wesentalink greyText'>{error}</p>
        </FormStyle_1>
      </Frame_AestheticMetadataPanel>
    );
  }

  const props = { "set_metadata": set_metadata, metadata: metadata };
  let Login_type = <Loading/>
  if (metadata) {
    if (metadata.style == "login_1") {
      Login_type = <Login1_special {...props}/>;
    }
    if (metadata.style == "login_2") {
      Login_type = <Login2_special {...props}/>;
    }
  }
  
  return (
    <Base metadata={metadata}>
      {React.cloneElement(Login_type, props)}
    </Base>
  )
}