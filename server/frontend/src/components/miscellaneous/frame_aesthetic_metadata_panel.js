import Base from '../base';
import AestheticMetadataPanel from './aesthetic_metadata_panel';
import './css/frame_aesthetic_metadata_panel.css';
import './css/aesthetic_metadata_panel.css';
import './../global.css';
import { useEffect, useState } from 'react';

export default function Frame_AestheticMetadataPanel(props) {
  const [isNarrow, setIsNarrow] = useState(false);

  const handleResize = () => {
    setIsNarrow(window.innerWidth < 808);
  };
  
  useEffect(() => {
    window.addEventListener('resize', handleResize);

    // Cleanup event listener on component unmount
    return () => {
      window.removeEventListener('resize', handleResize);
    };
  }, []);

  useEffect(() => {
    handleResize();
  })

  return (
    <Base className={`aesthetic_metadata_panel_frame`}>
      <AestheticMetadataPanel metadata={props.metadata}/>
      
      <div className='line'>.</div>

      {/* We're using new URL here to verify this is a real URL and not injection. */}
      <div className='aesthetic_metadata_panel_right' style={{ backgroundImage: isNarrow && props.metadata && props.metadata.image ? `URL(${new URL(props.metadata.image).href}` : null }}>
        {props.children}
      </div>
    </Base>
  );
}