import fetch_wrapper from "./fetcher.js";
import general from "./general.js";
import metadata from "./metadata.js";
import auth from './lib.js';
import oauth from "./protocols/oauth.js";
import { signStaticCredential, signDataToken } from "./http_signature.js";

let deviceIDG = null;
let privateKeyG = null;
let typeG = null;
let additional_data = null;

async function getCreds() {
    // privatekey is the device ed25519 private key as base64-encoded PKCS#8 DER
    // (WebCrypto exportKey("pkcs8", ...)); the RFC 9421 signer imports it directly.
    return {
        deviceid: deviceIDG,
        privatekey: privateKeyG,
        additional_data: additional_data,
        type: typeG
    };
}

function Guard(credsObject) {
    if (credsObject) {
        deviceIDG = credsObject.deviceid;
        privateKeyG = credsObject.privatekey;
        additional_data = credsObject.additional_data;
        typeG = credsObject.type;
    } else {
        console.warn("You need to specify a credentials object when initalizing Rover(). E.g Rover({ deviceID \"myawesomedeviceid\", \"privatekey\":\"awesomeprivatekey\"})");
    }

    return {
        metadata: metadata,
        auth: auth,
        oauth: oauth,
        fetch_wrapper: fetch_wrapper,
        general: general
    };
}

export { Guard, getCreds, signStaticCredential, signDataToken }