// RFC 9421 HTTP Message Signatures (ed25519) + RFC 9530 Content-Digest.
//
// This replaces the previous "hades-auth" scheme. Devices sign with an ed25519
// key (WebCrypto); Guard verifies the signature server-side (see the Rust
// `http_signature`/`signed_token` modules). The device is identified by the
// `keyid` signature parameter, which carries the Guard device_id.
//
// Three producers, all sharing the same key material:
//   * signRequestHeaders  – per-request signature over the live request.
//   * signStaticCredential – empty-component signature carried in a cookie so a
//     browser navigation can prove device identity without Signature headers.
//   * signDataToken       – compact ed25519 signed token (the OAuth `code`).

const SUBTLE = () => globalThis.crypto.subtle;

function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function bytesToBase64(bytes) {
  let binary = "";
  const view = new Uint8Array(bytes);
  for (let i = 0; i < view.length; i++) {
    binary += String.fromCharCode(view[i]);
  }
  return btoa(binary);
}

function bytesToBase64Url(bytes) {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Import a device private key (base64-encoded PKCS#8 DER, as produced by
// WebCrypto exportKey("pkcs8", ...)) for ed25519 signing.
async function importPrivateKey(privateKeyPkcs8Base64) {
  return SUBTLE().importKey(
    "pkcs8",
    base64ToBytes(privateKeyPkcs8Base64),
    { name: "Ed25519" },
    false,
    ["sign"]
  );
}

async function ed25519Sign(privateKey, messageBytes) {
  const signature = await SUBTLE().sign({ name: "Ed25519" }, privateKey, messageBytes);
  return new Uint8Array(signature);
}

// RFC 9530 Content-Digest header value: sha-256=:<base64 of SHA-256(body)>:
async function contentDigest(bodyBytes) {
  const digest = await SUBTLE().digest("SHA-256", bodyBytes);
  return `sha-256=:${bytesToBase64(digest)}:`;
}

function toBytes(body) {
  if (body == null) return null;
  if (typeof body === "string") return new TextEncoder().encode(body);
  if (body instanceof Uint8Array) return body;
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  // Fall back to string coercion for other body types.
  return new TextEncoder().encode(String(body));
}

// Build the RFC 9421 §2.5 signature base. `components` are resolved by the
// caller into `{ name, value }` pairs (in order); `paramsRaw` is the exact
// signature-params value (also emitted verbatim in the Signature-Input header).
function buildSignatureBase(components, paramsRaw) {
  const lines = components.map(({ name, value }) => `"${name}": ${value}`);
  lines.push(`"@signature-params": ${paramsRaw}`);
  return lines.join("\n");
}

function signatureParams(componentNames, created, deviceId) {
  const inner = componentNames.map((name) => `"${name}"`).join(" ");
  return `(${inner});created=${created};keyid="${deviceId}";alg="ed25519"`;
}

// Produce the RFC 9421 headers to attach to a request. Returns an object of
// header name -> value (Content-Digest is included only when there is a body).
export async function signRequestHeaders({ method, url, body, deviceId, privateKeyPkcs8Base64 }) {
  const target = new URL(url);
  const created = Math.floor(Date.now() / 1000);
  const bodyBytes = toBytes(body);

  const componentValues = [
    { name: "@method", value: method.toUpperCase() },
    { name: "@authority", value: target.host.toLowerCase() },
    { name: "@path", value: target.pathname },
    { name: "@query", value: target.search ? target.search : "?" },
  ];

  const headers = {};
  if (bodyBytes) {
    const digest = await contentDigest(bodyBytes);
    headers["Content-Digest"] = digest;
    componentValues.push({ name: "content-digest", value: digest });
  }

  const componentNames = componentValues.map((component) => component.name);
  const paramsRaw = signatureParams(componentNames, created, deviceId);
  const base = buildSignatureBase(componentValues, paramsRaw);

  const privateKey = await importPrivateKey(privateKeyPkcs8Base64);
  const signature = await ed25519Sign(privateKey, new TextEncoder().encode(base));

  headers["Signature-Input"] = `sig1=${paramsRaw}`;
  headers["Signature"] = `sig1=:${bytesToBase64(signature)}:`;
  return headers;
}

// Produce a static device credential (empty covered-components list) for
// transport in a cookie. Returns { signature_input, signature }.
export async function signStaticCredential({ deviceId, privateKeyPkcs8Base64 }) {
  const created = Math.floor(Date.now() / 1000);
  const paramsRaw = signatureParams([], created, deviceId);
  const base = buildSignatureBase([], paramsRaw);

  const privateKey = await importPrivateKey(privateKeyPkcs8Base64);
  const signature = await ed25519Sign(privateKey, new TextEncoder().encode(base));

  return {
    signature_input: `sig1=${paramsRaw}`,
    signature: `sig1=:${bytesToBase64(signature)}:`,
  };
}

// Produce a compact ed25519 signed data token: base64url(payload).base64url(sig).
// `payload` must include `device_id` so the server can locate the key.
export async function signDataToken(payload, privateKeyPkcs8Base64) {
  const segment = bytesToBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
  const privateKey = await importPrivateKey(privateKeyPkcs8Base64);
  const signature = await ed25519Sign(privateKey, new TextEncoder().encode(segment));
  return `${segment}.${bytesToBase64Url(signature)}`;
}
