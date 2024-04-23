import fetch_wrapper from "./fetcher.js";
import general from "./general.js";
import metadata from "./metadata.js";
import { authenticate, request } from './lib.js';

let deviceIDG = null;
let privateKeyG = null;
let typeG = null;
let additional_data = null;

async function getCreds() {
    const pemHeader = "-----BEGIN PRIVATE KEY-----";
    const pemFooter = "-----END PRIVATE KEY-----";

    return {
        deviceid: deviceIDG,
        privatekey: pemHeader+privateKeyG+pemFooter,
        additional_data: additional_data,
        type: typeG
    };
}

async function OnlyGetAdditionalData() {
    // The getCreds function returns null for safety, however some parts of the codebase might still need something from the additional data object, such as a domain for local development.
    let additional_data_v = {};
    if (additional_data_v) {
        additional_data_v = additional_data_v;
    }
    return additional_data_v
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
        getCreds: getCreds,
        metadata: metadata,
        request: request,
        authenticate: authenticate,
        fetch_wrapper: fetch_wrapper,
        general: general
    };
}

export { Guard, getCreds, OnlyGetAdditionalData };