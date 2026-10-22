/** An ed25519 device keypair, encoded the way Guard stores and verifies it. */
export interface DeviceKeyPair {
  /** Public key, raw 32 bytes, base64. This is what Guard stores. */
  publicKeyBase64: string;
  /** Private key, PKCS#8 DER, base64. This is what the RFC 9421 signer imports. */
  privateKeyPkcs8Base64: string;
}

function toBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Generate the browser's device keypair for RFC 9421 HTTP Message Signatures.
 *
 * The public key is exported "raw" (32 bytes) to match what Guard stores and
 * verifies; the private key is exported as PKCS#8 so the signer can re-import
 * it. The private key never leaves this origin.
 */
export async function generateDeviceKeyPair(): Promise<DeviceKeyPair> {
  const keyPair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;

  return {
    publicKeyBase64: toBase64(await crypto.subtle.exportKey("raw", keyPair.publicKey)),
    privateKeyPkcs8Base64: toBase64(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey)),
  };
}
