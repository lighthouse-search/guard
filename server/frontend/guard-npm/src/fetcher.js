import { getCreds } from "./index.js";
import { signRequestHeaders } from "./http_signature.js";

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
    if (credsStatus && credsStatus.deviceid && credsStatus.privatekey) {
        // Sign the request with an RFC 9421 HTTP Message Signature. The device
        // is identified via the `keyid` signature parameter (the device_id).
        const method = (properties && properties.method) || "GET";
        const signatureHeaders = await signRequestHeaders({
            method,
            url,
            body: properties && properties.body,
            deviceId: credsStatus.deviceid,
            privateKeyPkcs8Base64: credsStatus.privatekey,
        });

        const signedProperties = {
            ...properties,
            headers: { ...(properties && properties.headers), ...signatureHeaders },
        };
        response = await fetch(url, signedProperties);
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
