import './css/aesthetic_metadata_panel.css';
import './../global.css';
import { useEffect, useRef, useState } from 'react';
import { Guard } from "@oracularhades/guard";

export default function AestheticMetadataPanel(props) {
    const should_run = useRef(true);
    const [metadata, set_metadata] = useState(null);

    async function get_metadata() {
        let url = new URL(window.location.href);
        let host = window.location.host;
        if (url && url.searchParams.get("host")) {
        host = url.searchParams.get("host")
        }

        const metadata_v = await Guard().metadata.get(host);
        if (metadata_v.ok == true) {
            set_metadata(metadata_v.data);
        }
    }
    useEffect(() => {
        if (props.metadata) {
            set_metadata(props.metadata);
        }
        if (should_run.current != true || props.metadata) { return; }
        should_run.current = false;

        get_metadata();
    });

    // We're going right into CSS here. Just some safety from bad inputs, we need to verify this is a real link.
    let link = null;
    try {
        link = new URL(metadata.image).href;
    } catch (error) {
        // Invalid link, ignore.
    }

    let background_colour = null;
    if (!link) {
        background_colour = "#000000";
    }
    
    return (
        <div style={{ backgroundImage: `url(${link})`, backgroundColor: background_colour }} className='aesthetic_metadata_panel_left'>
            {metadata && <div className='aesthetic_metadata_panel_left_div'>
                {metadata.logo && <img className='aesthetic_metadata_panel_left_logo' src={metadata.logo}/>}
                {metadata.alias && <h2 className='aesthetic_metadata_panel_left_header'>{metadata.alias}</h2>}
                <p>{metadata.public_description}</p>
            </div>}
        </div>
    )
}