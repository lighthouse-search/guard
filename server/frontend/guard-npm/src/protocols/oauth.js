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

const oauth = { exchange_code };
export default oauth;