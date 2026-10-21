import { Guard, getCreds } from "./index.js";

import general from "./general.js";
import { getGuardApiURL } from "./routing.js";

async function request(host, authentication_method, request_data) {
    const response = await Guard(await getCreds()).fetch_wrapper(`${getGuardApiURL()}/auth/request?${general().objectToParams({ host })}`, {
        method: 'POST', // *GET, POST, PUT, DELETE, etc.
        mode: 'cors', // no-cors, *cors, same-origin
        cache: 'default', // *default, no-cache, reload, force-cache, only-if-cached
        credentials: 'same-origin', // include, *same-origin, omit
        edirect: 'error', // manual, *follow, error
        referrerPolicy: 'no-referrer', // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            authentication_method,
            request_data
        })
    })
    
    const data = response.json();

    if (data.error == true) {
        throw data;
    }
    
    return data;
}

async function authenticate(host, authentication_method, request_data) {
    const response = await Guard(await getCreds()).fetch_wrapper(`${getGuardApiURL()}/auth/authenticate?${general().objectToParams({ host })}`, {
        method: 'POST', // *GET, POST, PUT, DELETE, etc.
        mode: 'cors', // no-cors, *cors, same-origin
        cache: 'default', // *default, no-cache, reload, force-cache, only-if-cached
        credentials: 'same-origin', // include, *same-origin, omit
        edirect: 'error', // manual, *follow, error
        referrerPolicy: 'no-referrer', // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            authentication_method,
            request_data
        })
    })
    
    const data = response.json();

    if (data.error == true) {
        throw data;
    }

    return data;
}

// Device authentication is general (not per host), so these carry no `host`.
// The server resolves the auth context from [device_authentication].
async function device_request(authentication_method, request_data) {
    const response = await Guard(await getCreds()).fetch_wrapper(`${getGuardApiURL()}/auth/device/request`, {
        method: 'POST',
        mode: 'cors',
        cache: 'default',
        credentials: 'same-origin',
        referrerPolicy: 'no-referrer',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            authentication_method,
            request_data
        })
    })

    const data = response.json();

    if (data.error == true) {
        throw data;
    }

    return data;
}

async function device_authenticate(authentication_method, request_data) {
    const response = await Guard(await getCreds()).fetch_wrapper(`${getGuardApiURL()}/auth/device/authenticate`, {
        method: 'POST',
        mode: 'cors',
        cache: 'default',
        credentials: 'same-origin',
        referrerPolicy: 'no-referrer',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            authentication_method,
            request_data
        })
    })

    const data = response.json();

    if (data.error == true) {
        throw data;
    }

    return data;
}

const auth = { request, authenticate, device_request, device_authenticate }
export default auth;