import { Guard, getCreds } from "./index.js";
import { getGuardApiURL } from "./routing.js";

async function request(authentication_method, request_data) {
    const response = await Guard(await getCreds()).fetch_wrapper(`${getGuardApiURL()}/request`, {
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

async function authenticate(authentication_method, request_data) {
    const response = await Guard(await getCreds()).fetch_wrapper(`${getGuardApiURL()}/authenticate`, {
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

export { request, authenticate }