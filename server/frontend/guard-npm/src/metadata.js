import { Guard, getCreds } from "./index.js";

import general from "./general.js";
import { getGuardApiURL } from "./routing.js";

async function get(hostname) {
    if (typeof process !== 'undefined' && process.env.NEXT_PUBLIC_DEV_MOCK === 'true') {
        return { ok: true, data: { alias: process.env.NEXT_PUBLIC_DEV_ALIAS ?? null, public_description: process.env.NEXT_PUBLIC_DEV_PUBLIC_DESCRIPTION ?? null, logo: process.env.NEXT_PUBLIC_DEV_LOGO || null, image: process.env.NEXT_PUBLIC_DEV_IMAGE || null, motd_banner: process.env.NEXT_PUBLIC_DEV_MOTD_BANNER || null, domain_placeholder: process.env.NEXT_PUBLIC_DEV_DOMAIN_PLACEHOLDER ?? null, username_placeholder: process.env.NEXT_PUBLIC_DEV_USERNAME_PLACEHOLDER ?? null, background_colour: process.env.NEXT_PUBLIC_DEV_BACKGROUND_COLOUR || null, style: process.env.NEXT_PUBLIC_DEV_STYLE ?? "login_1" } };
    }

    const response = await Guard(await getCreds()).fetch_wrapper(`${getGuardApiURL()}/metadata?${general().objectToParams({ hostname })}`, {
        method: 'GET', // *GET, POST, PUT, DELETE, etc.
        mode: 'cors', // no-cors, *cors, same-origin
        cache: 'default', // *default, no-cache, reload, force-cache, only-if-cached
        credentials: 'same-origin', // include, *same-origin, omit
        headers: {
            'Content-Type': 'application/json'
        },
        redirect: 'error', // manual, *follow, error
        referrerPolicy: 'no-referrer', // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
    })
    
    const data = response.json();
    
    return data;
}

// Authentication methods for a hostname, or — when device_authentication is true
// — the general device-authentication methods configured under
// [device_authentication] (no hostname). One endpoint so auth-method exposure
// logic can't diverge between the two flows.
async function get_authentication_methods(hostname, options) {
    const device_authentication = options && options.device_authentication ? true : false;

    if (typeof process !== 'undefined' && process.env.NEXT_PUBLIC_DEV_MOCK === 'true') {
        return { ok: true, data: [{ active: true, id: "email", alias: null, icon: null, method_type: "email", login_page: null }] };
    }

    const params = device_authentication ? { device_authentication: true } : { hostname };
    const response = await Guard(await getCreds()).fetch_wrapper(`${getGuardApiURL()}/metadata/get-authentication-methods?${general().objectToParams(params)}`, {
        method: 'GET', // *GET, POST, PUT, DELETE, etc.
        mode: 'cors', // no-cors, *cors, same-origin
        cache: 'default', // *default, no-cache, reload, force-cache, only-if-cached
        credentials: 'same-origin', // include, *same-origin, omit
        headers: {
            'Content-Type': 'application/json'
        },
        redirect: 'error', // manual, *follow, error
        referrerPolicy: 'no-referrer', // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
    })

    const data = response.json();

    return data;
}

const metadata = { get, get_authentication_methods };
export default metadata;