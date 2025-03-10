"use client"
import Frame_AestheticMetadataPanel from '@/components/miscellaneous/frame_aesthetic_metadata_panel';
import './css/login1_special.css';
import './../../global.css';

export default function Login1(props) {
  return (
    <Frame_AestheticMetadataPanel>
      {props.children}
    </Frame_AestheticMetadataPanel>
  );
}
