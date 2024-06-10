import { static_auth_sign } from "hades-auth";
import { Cookies } from 'react-cookie';

const cookies = new Cookies();

function get_auth_url() {
  return "https://auth.api.motionfans.com"
}

function get_api_url() {
  return "https://api.motionfans.com"
}

function ab2str(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}

async function generatePublicPrivateKey() {
  const keyPair = await crypto.subtle.generateKey(
  {
    name: "ECDSA",
    namedCurve: "P-521",
  },
    true,
    ["sign", "verify"]
  )
  const publicexported = await crypto.subtle.exportKey(
    "spki",
    keyPair.publicKey
  );
  const publicexportedAsString = ab2str(publicexported);
  const publicexportedAsBase64 = btoa(publicexportedAsString);

  const privateexported = await crypto.subtle.exportKey(
    "pkcs8",
    keyPair.privateKey
  );
  const privateexportedAsString = ab2str(privateexported);
  const privateexportedAsBase64 = btoa(privateexportedAsString);
  return { publicKeyNaked: publicexportedAsBase64, privateKeyNaked: privateexportedAsBase64 };
}

async function handle_new(auth_data, auth_metadata, private_key) {
  let localAppend = "";
  if (localStorage.getItem("use_prod_servers") == "false" && window.location.hostname.includes("127.0.0.1")) {
    localAppend = "_local";
  }
  
  if (!auth_data) {
    throw "No auth data given.";
  }

  await localStorage.setItem(`auth${localAppend}`, JSON.stringify(auth_data));
  await handle_new_authentication_metadata(auth_metadata);
}

async function handle_new_authentication_metadata(metadata) {
  let expirationDate = new Date();
  expirationDate.setFullYear(expirationDate.getFullYear() + 10);

  let root_domain = root_domain_logic();

  await cookies.set(`guard_authentication_metadata`, JSON.stringify(metadata), {
    domain: root_domain,
    path: "/",
    secure: false,
    expires: expirationDate,
    sameSite: "strict"
  });
}

async function handle_new_static_auth(auth_data, private_key) {
  let device_id = auth_data.device_id;
  if (!device_id) {
    throw "device_id not provided.";
  }

  let result = await static_auth_sign({ device_id: device_id }, private_key);

  let expirationDate = new Date();
  expirationDate.setFullYear(expirationDate.getFullYear() + 10);

  let root_domain = root_domain_logic();

  await cookies.set(`guard_static_auth`, result, {
    domain: root_domain,
    path: "/",
    secure: false,
    expires: expirationDate,
    sameSite: "strict"
  });
}

async function handle_new_oauth_access_token(access_token) {
  let expirationDate = new Date();
  expirationDate.setFullYear(expirationDate.getFullYear() + 10);

  let root_domain = root_domain_logic();

  await cookies.set(`guard_oauth_access_token`, access_token, {
    domain: root_domain,
    path: "/",
    secure: false,
    expires: expirationDate,
    sameSite: "strict"
  });
}

function root_domain_logic() {
  let root_domain = window.location.hostname;
  if (window.location.hostname != "127.0.0.1" && window.location.hostname != "localhost") {
    let root_domain_split = window.location.host.split(".");
    root_domain = "."+`${root_domain_split[root_domain_split.length-2]}.${root_domain_split[root_domain_split.length-1]}`;
  }

  return root_domain;
}

async function credentials_object() {
  let localAppend = "";
  if (localStorage.getItem("use_prod_servers") != "true" && window.location.origin.includes("127.0.0.1")) { //window.location.origin.includes("127.0.0.1") IS DANGEROUS IF YOU DON'T CHECK FOR A DOT. IF THERE IS A DOT IN THE HOSTNAME THEN IT'S A DOMAIN AND NOT THE REAL LOCALHOST. IT'S FINE IN THIS SPECIFIC CASE THOUGH.
    localAppend = "_local";
  }

  const authData = JSON.parse(await localStorage.getItem(`auth${localAppend}`));
  if (!authData) {
    console.log("No auth data found.");
    return null;
  }
  // if (authData.type != "elliptic") {
  //   await localStorage.removeItem(`auth${localAppend}`)
  //   return null;
  // }

  const deviceId = await authData.device_id;

  return { deviceid: deviceId, privatekey: authData.private_key };
}

async function logout() {
  // TODO: Should be signaling to the backend the credential is no longer valid and await verification it was removed.
  let localAppend = "";
  if (localStorage.getItem("use_prod_servers") != "true" && window.location.origin.includes("127.0.0.1")) { //window.location.origin.includes("127.0.0.1") IS DANGEROUS IF YOU DON'T CHECK FOR A DOT. IF THERE IS A DOT IN THE HOSTNAME THEN IT'S A DOMAIN AND NOT THE REAL LOCALHOST. IT'S FINE IN THIS SPECIFIC CASE THOUGH.
    localAppend = "_local";
  }

  await localStorage.removeItem(`auth${localAppend}`);
}

function get_routing_host(window) {
  let url = new URL(window.location.href);
  let host = window.location.host;
  if (url && url.searchParams.get("redirect")) {
    let redirect_url = new URL(url.searchParams.get("redirect"));
    host = redirect_url.host;
  }

  return host;
}

function generateRandomID() {
  var random_string = '';
  // const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ";
  for(var i, i = 0; i < characters.length; i++){
    random_string += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return random_string.slice(0, 20)+new Date().getTime();
}

async function auth_init_parmas(authentication_method, document) {
  const state = generateRandomID();
  
  const params = new URLSearchParams(document.location.search);
  const redirect_url = params.get("redirect");

  const confirm_metadata = {
    authentication_method,
    state,
    redirect_url
  }

  await localStorage.setItem("confirm_metadata", JSON.stringify(confirm_metadata));

  return confirm_metadata;
}

export { get_auth_url, get_api_url, generatePublicPrivateKey, handle_new, credentials_object, logout, get_routing_host, handle_new_oauth_access_token, handle_new_static_auth, auth_init_parmas };