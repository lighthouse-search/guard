"use client"
import { useEffect, useRef, useState } from 'react';
import Frame_AestheticMetadataPanel from '@/components/miscellaneous/frame_aesthetic_metadata_panel';
import { Guard } from '@oracularhades/guard';
import FormStyle_special_1 from '../forms/form_style_special1';
import './css/login2_special.css';
import './../../global.css';
import { get_metadata, get_routing_host } from '@/global';
import Base from '@/components/base';
import Image_background from '@/components/image/background/image_background';

export default function Login2_special(props) {
  const should_run = useRef(true);
  const [metadata, set_metadata] = useState(props.metadata);

  async function run() {
    const metadata_v = await get_metadata();
    set_metadata(metadata_v);
    if (props.set_metadata) {
      props.set_metadata(metadata_v);
    }
  }
  useEffect(() => {
    if (should_run.current != true || metadata) { return; }
    should_run.current = false;

    run();
  });

  return (
    <Base metadata={metadata} className="login2">
      {metadata && metadata.image && <Image_background src={metadata.image}/>}
      {metadata != undefined && <div className="column">
        <FormStyle_special_1 metadata={metadata} header={metadata.alias} description={metadata.public_description} logo={metadata.logo}/>
      </div>}
    </Base>
  );
}
