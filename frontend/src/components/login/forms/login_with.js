import './css/login_with.css';
import './../../global.css';
import { auth_init_parmas } from '@/global';

export default function Login_With(props) {
    const authentication_method = props.authentication_method;

    async function handle_out() {
        const auth_init_parmas_v = await auth_init_parmas(authentication_method.id, document);
        let login_page = new URL(authentication_method.login_page);
        login_page.searchParams.set("state", auth_init_parmas_v.state);
        // login_page.searchParams.set("fallback_domain", auth_init_parmas_v.redirect_url);

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