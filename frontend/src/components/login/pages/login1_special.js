"use client"
import { useEffect, useRef, useState } from 'react';
import Frame_AestheticMetadataPanel from '@/components/miscellaneous/frame_aesthetic_metadata_panel';
import { Guard } from '@oracularhades/guard';
import FormStyle_special_1 from '../forms/form_style_special1';
import './css/login1_special.css';
import './../../global.css';
import { get_metadata } from '@/global';

export default function Login1_special(props) {
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
