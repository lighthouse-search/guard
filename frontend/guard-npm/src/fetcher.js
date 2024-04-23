import { getCreds } from "./index.js";
import { fetch_wrapper as fetch_wrapper_hades } from "hades-auth";

async function fetch_wrapper(url, properties) {
    const credsStatus = await getCreds();

    if (credsStatus && credsStatus.additional_data) {
        let new_url_obj = new URL(url);
        for (const key in credsStatus.additional_data) {
            new_url_obj.searchParams.set(key, credsStatus.additional_data[key]);   
        }

        url = new_url_obj.href;
    }

    let response = null;
    if (credsStatus && credsStatus.deviceid) {
        response = await fetch_wrapper_hades(url, properties, credsStatus.deviceid, credsStatus.privatekey);   
    } else {
        response = await fetch(url, properties);
    }

    let try_json = null;
    try {
        let response2 = response.clone();
        let try_json2 = await response2.json();
        try_json = try_json2;
    } catch (erorr) {
        // isn't parse-able with json, that's weird, nothing we can do about it. Might be an image.
    }

    if (try_json && try_json.error) {
        throw try_json;
    }

    return response;
}

export default fetch_wrapper;