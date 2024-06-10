"use client"
import { useEffect, useRef, useState } from 'react';
import Frame_AestheticMetadataPanel from '@/components/miscellaneous/frame_aesthetic_metadata_panel';
import { Guard } from '@oracularhades/guard';
import FormStyle_special_1 from '../forms/form_style_special1';
import './css/login1_special.css';
import './../../global.css';
import { get_routing_host } from '@/global';

export default function Login1_special(props) {
  const should_run = useRef(true);
  const [metadata, set_metadata] = useState(undefined);

  async function get_metadata() {
    let routing_host = get_routing_host(window);

    const metadata_v = await Guard().metadata.get(routing_host.host);
    if (metadata_v.ok == true) {
      set_metadata(metadata_v.data);
      if (props.set_metadata) {
        props.set_metadata(metadata_v.data);
      }
    }
  }
  useEffect(() => {
    if (should_run.current != true) { return; }
    should_run.current = false;

    get_metadata();
  });

  let header = null;
  if (metadata) {
    header = metadata.login_header;
  }

  return (
    <Frame_AestheticMetadataPanel metadata={metadata}>
      {metadata != undefined && <FormStyle_special_1 header={header} metadata={metadata}/>}
    </Frame_AestheticMetadataPanel>
  );
}
