import './css/form_style1.css';
import './../../global.css';
import Input_with_header from '@/components/input/input_with_header';
import Login_With from '@/components/login/forms/login_with';
import Magiclink from '@/pages/magiclink';
import { useEffect, useRef, useState } from 'react';
import { Guard } from '@oracularhades/guard';
import Or_Bar from './or_bar';
import FormStyle_1 from './form_style1';
import LoadingSpinner from '@/components/miscellaneous/loadingspinner';
import { get_routing_host, auth_init_params, device_auth_init_params } from '@/global';
import HCaptcha from '@hcaptcha/react-hcaptcha';
import Check_your_email from './special_styles/check_your_email';
import Authenticating_desktop_application from './special_styles/authenticating_desktop_application';

export default function FormStyle_special_1(props) {
    const should_run = useRef(true);
    const metadata = props.metadata;
    // When set (opened by the Guard desktop app), this same form drives the
    // device-authentication flow: methods come from [device_authentication], and
    // each method hands a one-time setup token back to the desktop instead of
    // logging the browser in. Shape: { deeplink_state, callback }.
    const device_context = props.device_context;
    const [magiclink, set_magiclink] = useState(false);
    const [email, set_email] = useState(null);
    const [authentication_methods, set_authentication_methods] = useState([]);
    const [state, set_state] = useState(null);
    const [error, set_error] = useState(null);
    const [fatal_error, set_fatal_error] = useState(null);
    const [loading, set_loading] = useState(false);
    const passed_code_verification = useRef(false);

    async function get_authentication_methods() {
        try {
            // Device auth has no client-supplied host (methods come from
            // [device_authentication]); normal login resolves the host from
            // ?redirect=.
            const authentication_methods_v = device_context
                ? await Guard().metadata.get_authentication_methods(null, { device_authentication: true })
                : await Guard().metadata.get_authentication_methods(get_routing_host(window).host);
            set_authentication_methods(authentication_methods_v.data);
        } catch (error) {
            set_error(error.message);
            return;
        }
    }

    useEffect(() => {
        if (should_run.current != true) { return; }
        should_run.current = false;

        get_authentication_methods();
    })

    if (magiclink == true) {
        return (
            <Magiclink email={email}/>
        );
    }

    let email_placeholder = null;
    if (metadata) {
        email_placeholder = `${metadata.username_placeholder}@${metadata.domain_placeholder}`;
    }

    async function start_email_authentication(authentication_method, request_data) {
        set_loading(true);
        set_error(null);

        // Both flows carry `state` through confirm_metadata so the magiclink
        // completion can match it; device auth additionally stashes the deeplink
        // state + loopback callback so it can hand the setup token to the desktop.
        const init = device_context
            ? await device_auth_init_params(authentication_method, { deeplink_state: device_context.deeplink_state, callback: device_context.callback })
            : await auth_init_params(authentication_method, window);
        request_data.state = init.state;

        try {
            const response = device_context
                ? await Guard().auth.device_request(authentication_method, request_data)
                : await Guard().auth.request(get_routing_host(window).host, authentication_method, request_data);
            if (response.ok == true) {
                set_state("check_your_email");
                return;
            }
        } catch (error) {
            set_error(error.message);
        }

        set_loading(false);
    }

    let email_method = null;

    const methods_ul = authentication_methods.map((data) => {
        if (!email_method && data.method_type == "email") {
            email_method = data;
            return;
        }

        return (
            <Login_With authentication_method={data} device_context={device_context}/>
        )
    });

    if (fatal_error) {
        return (
            <div className={`FormStyle_1 ${props.className}`} style={props.style}>
                {(props.header || props.description || props.logo) && <div className='column row_gap_4'>
                    {props.logo && <img className='FormStyle_1_logo' src={props.logo}/>}
                    {props.header && <h1 className='FormStyle_1_header'>{props.header}</h1>}
                    {props.description && <p className='FormStyle_1_description'>{props.description}</p>}
                </div>}

                {loading == false && <div className='FormStyle_1_div'>
                    {error != null && <p className='FormStyle_1_div_error'>Error: {error}</p>}
                </div>}
            </div>
        )
    }

    if (state == "check_your_email") {
        return <Check_your_email/>
    } else if (state == "desktop_application") {
        let routing_host = get_routing_host(window);
        let decoded_base64 = null;
        try {
            decoded_base64 = atob(routing_host.webpage_url.searchParams.get("code"));
        } catch (error) {
            alert("ERR");
            // todo: need to check if this actually shows.
            set_fatal_error("Failed to decode base64 in params.code (is it valid base64?)");
        }
        return <Authenticating_desktop_application code={decoded_base64} on_success={() => { should_run.current = true; passed_code_verification.current = true; set_state(null); }}/>
    } else if (state == "show_captcha") {
        return (
            <div className={`FormStyle_1 ${props.className}`} style={props.style}>
                <div className='FormStyle_1_div'>
                    <HCaptcha
                        sitekey="9a1a8707-24b1-48f8-aa43-5f47f2a9e8cf"
                        size="normal"
                        onVerify={(token,ekey) => {  }}
                    />
                </div>
            </div>
        );
    } else {
        return (
            <div className={`FormStyle_1 ${props.className}`} style={props.style}>
                {(props.header || props.description || props.logo) && <div className='column row_gap_4'>
                    {props.logo && <img className='FormStyle_1_logo' src={props.logo}/>}
                    {props.header && <h1 className='FormStyle_1_header'>{props.header}</h1>}
                    {props.description && <p className='FormStyle_1_description'>{props.description}</p>}
                </div>}

                {loading == false && <div className='FormStyle_1_div'>
                    {error != null && <p className='FormStyle_1_div_error'>Error: {error}</p>}
                    {email_method && <div className='FormStyle_1_div_email'>
                        <Input_with_header header="Email" placeholder={email_placeholder} value={email} onChange={(e) => { set_email(e.target.value); }} onKeyDown={(e) => { if (e.key == "Enter") { start_email_authentication(email_method.id, { email: email }); } }} autoCapitalize="off"/>
                        <button className='FormStyle_1_div_login_button' onClick={() => { start_email_authentication(email_method.id, { email: email }); }}>Login</button>
                    </div>}
                    {methods_ul.length > 1 && <Or_Bar/>}
                    {methods_ul}
                    {/* {show_captcha == true && <HCaptcha
                        sitekey="9a1a8707-24b1-48f8-aa43-5f47f2a9e8cf"
                        size="normal"
                        onVerify={(token,ekey) => { request_magiclink(token); }}
                    />} */}
                </div>}
                {loading == true && <LoadingSpinner speed="600ms" style={{ width: 15, height: 15, alignSelf: "center" }}/>}

                {/* <Or_Bar/> */}

                {/* <div className='FormStyle_1_div'>
                <Login_With service="Microsoft" icon="https://www.microsoft.com/favicon.ico?v2" redirect={`https://login.microsoftonline.com/common/oauth2/v2.0/authorize?${microsoft_redirect.toString()}`}/>
                <Login_With service="Github" icon="https://github.com/favicon.ico" redirect={`https://github.com/login/oauth/authorize?${github_redirect.toString()}`}/>
                </div> */}

                {metadata && metadata.form && metadata.form.bottom_text && <p style={{ fontSize: metadata.form.bottom_text_fontsize }} className='you_agree_to'>{metadata.form.bottom_text}</p>}
            </div>
        )
    }
}