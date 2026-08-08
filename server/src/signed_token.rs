//! Compact ed25519 signed tokens for signed *data* payloads (not HTTP
//! messages). Used for the OAuth authorization `code`, which carries a JSON
//! payload (`device_id`, `client_id`, `scope`, `redirect_uri`, `grant_type`,
//! `nonce`) signed by the device's ed25519 key. This replaces the previous
//! hades-auth `static_auth_sign`/`static_auth_verify` JWT for that use case.
//!
//! Format: `base64url(payload_json) . base64url(ed25519_signature)`, where the
//! signature is computed over the ASCII bytes of the first segment. The device
//! is identified by `payload.device_id`, so the caller parses the payload
//! (unverified) to look up the key, then verifies.

use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;

/// Decode the payload without verifying the signature. Use only to extract the
/// `device_id` needed to load the verifying key; never trust the result until
/// [`verify`] has succeeded.
pub fn parse_unverified(token: &str) -> Result<Value, String> {
    let segment = token
        .split('.')
        .next()
        .ok_or_else(|| "Signed token is empty.".to_string())?;
    let payload_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|error| format!("Signed token payload is not valid base64url: {}", error))?;
    serde_json::from_slice(&payload_bytes)
        .map_err(|error| format!("Signed token payload is not valid JSON: {}", error))
}

/// Verify the token against the device's ed25519 public key (raw 32-byte key,
/// base64 standard encoded) and return the payload.
pub fn verify(token: &str, public_key_base64: &str) -> Result<Value, String> {
    let mut parts = token.split('.');
    let segment = parts
        .next()
        .ok_or_else(|| "Signed token is missing its payload segment.".to_string())?;
    let signature_segment = parts
        .next()
        .ok_or_else(|| "Signed token is missing its signature segment.".to_string())?;
    if parts.next().is_some() {
        return Err("Signed token has too many segments.".to_string());
    }

    let key_bytes = general_purpose::STANDARD
        .decode(public_key_base64.trim())
        .map_err(|error| format!("Device public key is not valid base64: {}", error))?;
    let key_array: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "Device public key is not a 32-byte ed25519 key.".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(&key_array)
        .map_err(|error| format!("Invalid ed25519 public key: {}", error))?;

    let sig_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(signature_segment)
        .map_err(|error| format!("Signed token signature is not valid base64url: {}", error))?;
    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "Signed token signature is not 64 bytes.".to_string())?;
    let signature = Signature::from_bytes(&sig_array);

    verifying_key
        .verify_strict(segment.as_bytes(), &signature)
        .map_err(|_| "Signed token signature verification failed.".to_string())?;

    let payload_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|error| format!("Signed token payload is not valid base64url: {}", error))?;
    serde_json::from_slice(&payload_bytes)
        .map_err(|error| format!("Signed token payload is not valid JSON: {}", error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    fn make_token(signing_key: &SigningKey, payload: &Value) -> String {
        let segment = general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap());
        let signature = signing_key.sign(segment.as_bytes());
        let sig_segment = general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes());
        format!("{}.{}", segment, sig_segment)
    }

    #[test]
    fn verifies_and_returns_payload() {
        let signing_key = SigningKey::from_bytes(&[3u8; 32]);
        let public_b64 = general_purpose::STANDARD.encode(signing_key.verifying_key().to_bytes());
        let payload = json!({"device_id": "dev1", "client_id": "abc", "nonce": "n"});
        let token = make_token(&signing_key, &payload);

        assert_eq!(parse_unverified(&token).unwrap()["device_id"], "dev1");
        let verified = verify(&token, &public_b64).expect("verify");
        assert_eq!(verified["client_id"], "abc");
    }

    /// Golden token produced by the guard-npm JS signer
    /// (`http_signature.js::signDataToken`); locks in JS/Rust agreement on the
    /// base64url-encoded ed25519 signed token used for the OAuth code.
    #[test]
    fn verifies_js_generated_token() {
        let public_key = "Hsf20k+wDjudoE+wpyvaOy2th4r/w4iu2s6c9WuG3BI=";
        let token = "eyJkZXZpY2VfaWQiOiJkZXZYWVoiLCJjbGllbnRfaWQiOiJjIiwiY3JlYXRlZCI6MX0.CS1nazj6TWY2cNchUmVo5dCmegtoCyjUxOaV2Jx8g2JpKiAfkyIkFOry5yMAnL9Uba4I6lMghAEnd40VN_JoBQ";
        let payload = verify(token, public_key).expect("verify js token");
        assert_eq!(payload["device_id"], "devXYZ");
        assert_eq!(payload["client_id"], "c");
    }

    #[test]
    fn rejects_tampered_payload() {
        let signing_key = SigningKey::from_bytes(&[3u8; 32]);
        let public_b64 = general_purpose::STANDARD.encode(signing_key.verifying_key().to_bytes());
        let token = make_token(&signing_key, &json!({"device_id": "dev1", "scope": "read"}));

        // Swap the payload segment for a different one; signature no longer matches.
        let forged_payload = general_purpose::URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({"device_id": "dev1", "scope": "admin"})).unwrap(),
        );
        let sig_segment = token.split('.').nth(1).unwrap();
        let forged = format!("{}.{}", forged_payload, sig_segment);
        assert!(verify(&forged, &public_b64).is_err());
    }
}
