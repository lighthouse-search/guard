import { Guard, signStaticCredential } from "@oracularhades/guard";
import { Cookies } from 'react-cookie';

const cookies = new Cookies();

function ab2str(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}

async function generatePublicPrivateKey() {
  // ed25519 keypair for RFC 9421 HTTP Message Signatures. The public key is
  // exported "raw" (32 bytes) to match what Guard stores/verifies; the private
  // key is exported as PKCS#8 for the signer to re-import.
  const keyPair = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"]
  )
  const publicexported = await crypto.subtle.exportKey(
    "raw",
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

  // Build an RFC 9421 static device credential (empty covered-components list)
  // and store it in the cookie, so browser navigations Guard reverse-proxies
  // can prove device identity without setting Signature headers. The credential
  // JSON is base64url-encoded so it only uses URL-unreserved characters and
  // round-trips cleanly through cookie encoders on both ends.
  const credential = await signStaticCredential({ deviceId: device_id, privateKeyPkcs8Base64: private_key });
  let result = btoa(unescape(encodeURIComponent(JSON.stringify(credential)))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

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

  await cookies.set(prepend_hostname_to_cookie(`guard_oauth_access_token`), access_token, {
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
  if (process.env.NEXT_PUBLIC_DEV_MOCK === 'true') {
    const mockRedirect = new URL('http://localhost:8484/');
    return { host: 'localhost:8484', href: 'http://localhost:8484/', redirect_url: mockRedirect, webpage_url: new URL(window.location.href) };
  }

  let url = new URL(window.location.href);
  let host = window.location.host;
  let href = window.location.href;
  let redirect_url = null;
  if (url && url.searchParams.get("redirect")) {
    redirect_url = new URL(url.searchParams.get("redirect"));
    host = redirect_url.host;
    href = redirect_url.href;
  } else {
    throw "Missing params.redirect.";
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

// Like auth_init_params, but for the desktop device-authentication flow. We
// carry the desktop's deeplink `state` through the email round-trip via
// confirm_metadata, so the magiclink completion can deep-link a one-time setup
// token back. The desktop then enrolls its own public key with that token — the
// key is never handled here. Device auth targets the Guard instance itself, so
// there is no `?redirect=`.
async function device_auth_init_params(authentication_method, device_context) {
  const state = generateRandomID();
  const redirect_url = `https://${window.location.host}`;

  const confirm_metadata_item = {
    authentication_method,
    state,
    redirect_url,
    device_authentication: true,
    deeplink_state: device_context.deeplink_state,
    callback: device_context.callback
  };

  let confirm_metadata = await localStorage.getItem("confirm_metadata") ? JSON.parse(await localStorage.getItem("confirm_metadata")) : [];
  if (Array.isArray(confirm_metadata) == false) {
    confirm_metadata = [confirm_metadata];
  }
  confirm_metadata.push(confirm_metadata_item);

  await localStorage.setItem("confirm_metadata", JSON.stringify(confirm_metadata));

  return confirm_metadata_item;
}

// The device-authentication callback is where the one-time setup token is handed
// back to the desktop app. It MUST be a loopback HTTP address and nothing else —
// a non-loopback callback (e.g. presetting `?callback=https://evil.com` in a
// phishing link) would exfiltrate the setup token to an attacker, who could then
// enroll their own device under the victim. Only 127.0.0.0/8, localhost and ::1
// over http are trusted; the desktop always uses http://127.0.0.1:<port>.
function is_loopback_callback(callback) {
  if (!callback) { return false; }

  let url = null;
  try {
    url = new URL(callback);
  } catch (error) {
    return false;
  }

  // Loopback is never served over TLS; the desktop's local server is plain http.
  if (url.protocol != "http:") { return false; }

  const host = url.hostname.toLowerCase();
  if (host == "localhost" || host == "::1" || host == "[::1]") { return true; }
  // 127.0.0.0/8 — the whole loopback range, not just 127.0.0.1.
  return /^127(?:\.\d{1,3}){3}$/.test(host);
}

async function is_authenticated() {
  if (await localStorage.getItem("auth") != null || await localStorage.getItem("auth_local") != null || cookies.get(prepend_hostname_to_cookie("guard_authentication_metadata"))) {
    return true;
  } else {
    return false;
  }
}

async function get_metadata() {
  if (process.env.NEXT_PUBLIC_DEV_MOCK === 'true') {
    return {
      alias: process.env.NEXT_PUBLIC_DEV_ALIAS ?? null,
      public_description: process.env.NEXT_PUBLIC_DEV_PUBLIC_DESCRIPTION ?? null,
      logo: process.env.NEXT_PUBLIC_DEV_LOGO || null,
      image: process.env.NEXT_PUBLIC_DEV_IMAGE || null,
      motd_banner: process.env.NEXT_PUBLIC_DEV_MOTD_BANNER || null,
      domain_placeholder: process.env.NEXT_PUBLIC_DEV_DOMAIN_PLACEHOLDER ?? null,
      username_placeholder: process.env.NEXT_PUBLIC_DEV_USERNAME_PLACEHOLDER ?? null,
      background_colour: process.env.NEXT_PUBLIC_DEV_BACKGROUND_COLOUR || null,
      style: process.env.NEXT_PUBLIC_DEV_STYLE ?? "login_1"
    };
  }

  let routing_host = get_routing_host(window);

  const metadata_v = await Guard().metadata.get(routing_host.host);
  return metadata_v.data;
}

export { generatePublicPrivateKey, handle_new, credentials_object, logout, get_routing_host, handle_new_oauth_access_token, handle_new_static_auth, auth_init_params, device_auth_init_params, is_authenticated, get_metadata, guard_authentication_metadata, is_loopback_callback };