import { Guard } from "@oracularhades/guard";
import { static_auth_sign } from "hades-auth";
import { Cookies } from 'react-cookie';

const cookies = new Cookies();

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

  await cookies.set(prepend_hostname_to_cookie("guard_authentication_metadata"), JSON.stringify(metadata), {
    domain: root_domain,
    path: "/",
    secure: false,
    expires: expirationDate,
    sameSite: "strict"
  });
}

async function guard_authentication_metadata() {
  let guard_authentication_metadata = await cookies.get(prepend_hostname_to_cookie("guard_authentication_metadata"));
  if (!guard_authentication_metadata) {
    return null;
  }

  return guard_authentication_metadata;
}

function prepend_hostname_to_cookie(cookie_name) {
  const guard_instance_hostname = window.location.hostname;
  return `${guard_instance_hostname}_${cookie_name}`;
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

  // guard_instance_hostname (should) match guard_config.frontend.metadata.instance_hostname, though there is no specific validation check and no endpoint to get the specific URL. This is fine, there really isn't any point to change this since there is no security downside (in this particular instance).
  await cookies.set(prepend_hostname_to_cookie("guard_static_auth"), result, {
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
  const authData = JSON.parse(await localStorage.getItem(`auth`));
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

async function logout(redirect) {
  // TODO: Should be signaling to the backend the credential is no longer valid and await verification it was removed.
  const all_cookies = await cookies.getAll();
  for (let key in Object.keys(all_cookies)) {
    await cookies.remove(key);
  }

  await localStorage.removeItem(`auth`);
  await localStorage.removeItem(`auth_local`);

  let url_params = new URLSearchParams({ redirect });
  window.location.href = `/guard/frontend/login?${url_params.toString()}`;
}

function get_routing_host(window) {
  let url = new URL(window.location.href);
  let host = window.location.host;
  let href = window.location.href;
  let redirect_url = null;
  if (url && url.searchParams.get("redirect")) {
    redirect_url = new URL(url.searchParams.get("redirect"));
    host = redirect_url.host;
    href = redirect_url.href;
  }

  return { host: host, href: href, redirect_url: redirect_url, webpage_url: url };
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

async function auth_init_params(authentication_method, window) {
  const state = generateRandomID();
  
  const redirect_url = get_routing_host(window).href;

  const confirm_metadata_item = {
    authentication_method,
    state,
    redirect_url
  }

  let confirm_metadata = await localStorage.getItem("confirm_metadata") ? JSON.parse(await localStorage.getItem("confirm_metadata")) : [];
  if (Array.isArray(confirm_metadata) == false) {
    confirm_metadata = [confirm_metadata];
  }
  confirm_metadata.push(confirm_metadata_item);

  await localStorage.setItem("confirm_metadata", JSON.stringify(confirm_metadata));

  return confirm_metadata_item;
}

async function is_authenticated() {
  if (await localStorage.getItem("auth") != null || await localStorage.getItem("auth_local") != null || cookies.get(prepend_hostname_to_cookie("guard_authentication_metadata"))) {
    return true;
  } else {
    return false;
  }
}

async function get_metadata() {
  let routing_host = get_routing_host(window);

  const metadata_v = await Guard().metadata.get(routing_host.host);
  return metadata_v.data;
}

export { generatePublicPrivateKey, handle_new, credentials_object, logout, get_routing_host, handle_new_oauth_access_token, handle_new_static_auth, auth_init_params, is_authenticated, get_metadata, guard_authentication_metadata };