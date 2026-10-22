import general from "../general.js";
import { Guard, getCreds } from "../index.js";
import { getGuardApiURL } from "../routing.js";

async function exchange_code(host, authentication_method, code) {
    const response = await Guard(await getCreds()).fetch_wrapper(`${getGuardApiURL()}/oauth/exchange-code?${general().objectToParams({ host, authentication_method, code })}`, {
        method: 'GET',
        mode: 'cors',
        cache: 'default',
        credentials: 'same-origin',
        edirect: 'error',
        referrerPolicy: 'no-referrer'
    })
    
    const data = response.json();

    if (data.error == true) {
        throw data;
    }
    
    return data;
}

// Device authentication (opened by the desktop app): completed in the browser.
// No `host` — the server resolves the [device_authentication] context and, on
// success, returns a one-time setup_token (instead of an access token) which the
// browser hands to the desktop over its loopback callback.
async function device_exchange_code(authentication_method, code) {
    const response = await Guard(await getCreds()).fetch_wrapper(`${getGuardApiURL()}/auth/device/oauth/exchange-code?${general().objectToParams({ authentication_method, code })}`, {
        method: 'GET',
        mode: 'cors',
        cache: 'default',
        credentials: 'same-origin',
        edirect: 'error',
        referrerPolicy: 'no-referrer'
    })

    const data = response.json();

    if (data.error == true) {
        throw data;
    }

    return data;
}

const oauth = { exchange_code, device_exchange_code };
export default oauth;