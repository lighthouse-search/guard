import { useState } from 'react';
import FormStyle_1 from '../form_style1';
import './css/authenticating_desktop_application.css';

export default function Authenticating_desktop_application(props) {
    const [error, set_error] = useState(null);
    const [code, set_code] = useState(null);

    function verify_code() {
        set_error(null);
        if (props.code == code) {
            if (props.on_success) {
                props.on_success();
            }
        } else {
            set_error("Incorrect code");
            if (props.on_failure) {
                props.on_failure();
            }
        }
    }

    return (
        <FormStyle_1 header={false} className="desktop_application_form row_gap_6">
            {/* <img className='magiclink_img' src="/assets/crystalball.png"/> */}
            {error && <p className="FormStyle_1_div_error">{error}</p>}
            <div className="column row_gap_2">
                <h2 className='desktop_application_header'>Authenticating Desktop Application</h2>
                <p className='desktop_application_subtext'>You're authenticating a Guard Desktop Application. Please enter the displayed code. If you don't intend to do this, you can safely close this page.</p>
            </div>
            <input placeholder="Code" value={code} onChange={(e) => { set_code(e.target.value); }}/>
            <button onClick={() => { verify_code(); }}>Authenticate</button>
        </FormStyle_1>
    )
};