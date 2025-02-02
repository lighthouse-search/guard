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
  const [metadata, set_metadata] = useState(undefined);

  useEffect(() => {
    if (should_run.current != true) { return; }
    should_run.current = false;

    get_metadata((data) => {
      console.log(data);
      set_metadata(data);
      if (props.set_metadata) {
        props.set_metadata(data);
      }
    });
  });

  let header = null;
  if (metadata) {
    header = metadata.login_header;
  }

  return (
    <Base metadata={metadata} className="login">
      {metadata && metadata.image && <Image_background src={metadata.image}/>}
      {metadata != undefined && <FormStyle_special_1 header={header} metadata={metadata}/>}
    </Base>
  );
}
