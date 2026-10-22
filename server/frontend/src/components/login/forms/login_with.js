import './css/login_with.css';
import './../../global.css';
import { auth_init_params, device_auth_init_params } from '@/global';

export default function Login_With(props) {
    const authentication_method = props.authentication_method;
    const device_context = props.device_context;

    async function handle_out() {
        // In device mode, carry the deeplink state + loopback callback through the
        // OAuth round-trip so the magiclink completion can hand the setup token
        // back to the desktop; otherwise it's a normal browser login.
        const init = device_context
            ? await device_auth_init_params(authentication_method.id, { deeplink_state: device_context.deeplink_state, callback: device_context.callback })
            : await auth_init_params(authentication_method.id, window);
        let login_page = new URL(authentication_method.login_page);
        login_page.searchParams.set("state", init.state);
        // login_page.searchParams.set("fallback_domain", init.redirect_url);

        window.location.href = login_page.href;
    }

    let service = authentication_method.id;
    if (authentication_method.alias) {
        service = authentication_method.alias;
    }

    return (
        <a onClick={() => { handle_out(); }} href={props.redirect} className='login_with'><button>
            <img src={authentication_method.icon}/>
            <p>Login with {service}</p>
        </button></a>
    )
}