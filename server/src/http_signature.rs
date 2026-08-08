//! RFC 9421 HTTP Message Signatures verification (ed25519).
//!
//! Guard authenticates devices by verifying an RFC 9421 signature that the
//! client attaches to its request. This replaces the previous bespoke
//! "hades-auth" JWT-in-a-cookie scheme.
//!
//! Two shapes are verified with the same code path:
//!
//!   * **Per-request (programmatic clients):** the covered components are the
//!     live request derived components plus `content-digest`:
//!     `("@method" "@authority" "@path" "@query" "content-digest")`. The
//!     caller supplies a [`RequestContext`] reconstructed from the request
//!     (in the reverse-proxy flow, from the forwarded original method/URL).
//!
//!   * **Static credential (browser navigations):** the covered components
//!     list is empty — `()` — so the signature only proves possession of the
//!     device key at `created` time (matching the old static cookie token).
//!     No [`RequestContext`] is required.
//!
//! The device is identified by the `keyid` signature parameter, which carries
//! the Guard `device_id`. The caller parses first (to learn `keyid`), loads the
//! device's stored ed25519 public key, then verifies.

use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Live request components, resolved by the caller, used to build the
/// signature base for the covered derived components / `content-digest`.
///
/// In the reverse-proxy auth flow Guard does not receive the original request
/// body, so `body` is typically `None`; the `content_digest` header value is
/// still covered by (and therefore bound to) the signature, it just cannot be
/// independently recomputed. When `body` is present the digest is recomputed
/// and checked.
pub struct RequestContext<'a> {
    pub method: &'a str,
    pub authority: &'a str,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub content_digest: Option<&'a str>,
    pub body: Option<&'a [u8]>,
}

/// A parsed `Signature-Input` + `Signature` pair for a single signature label.
pub struct ParsedSignature {
    pub label: String,
    pub components: Vec<String>,
    /// The raw `Signature-Input` value for this label, e.g.
    /// `("@method" "@authority");created=123;keyid="abc";alg="ed25519"`.
    /// Used verbatim as the `@signature-params` line of the signature base.
    pub params_raw: String,
    pub keyid: String,
    pub alg: Option<String>,
    pub created: Option<i64>,
    pub signature: Vec<u8>,
}

/// Parse the `Signature-Input` and `Signature` header (or cookie) values.
///
/// Only a single signature is supported; the first dictionary member of each
/// is used and the labels must match.
pub fn parse(signature_input: &str, signature: &str) -> Result<ParsedSignature, String> {
    let (label, params_raw) = split_label(signature_input)?;
    let (sig_label, sig_value) = split_label(signature)?;
    if label != sig_label {
        return Err(format!(
            "Signature label '{}' does not match Signature-Input label '{}'",
            sig_label, label
        ));
    }

    // params_raw looks like: (comp1 comp2);created=..;keyid="..";alg=".."
    let inner_start = params_raw
        .find('(')
        .ok_or_else(|| "Signature-Input value is missing the component list '('".to_string())?;
    let inner_end = params_raw
        .find(')')
        .ok_or_else(|| "Signature-Input value is missing the component list ')'".to_string())?;
    if inner_end < inner_start {
        return Err("Malformed Signature-Input component list.".to_string());
    }

    let inner = &params_raw[inner_start + 1..inner_end];
    let mut components: Vec<String> = Vec::new();
    for token in inner.split_whitespace() {
        // Each component identifier is an sf-string ("name"); we don't support
        // component parameters, which our clients never emit.
        let name = token
            .strip_prefix('"')
            .and_then(|t| t.strip_suffix('"'))
            .ok_or_else(|| format!("Component identifier '{}' is not a quoted string.", token))?;
        components.push(name.to_ascii_lowercase());
    }

    let params_str = &params_raw[inner_end + 1..];
    let mut keyid: Option<String> = None;
    let mut alg: Option<String> = None;
    let mut created: Option<i64> = None;
    for param in params_str.split(';') {
        let param = param.trim();
        if param.is_empty() {
            continue;
        }
        let (key, value) = param
            .split_once('=')
            .ok_or_else(|| format!("Malformed signature parameter '{}'.", param))?;
        match key.trim() {
            "keyid" => keyid = Some(unquote(value.trim())?),
            "alg" => alg = Some(unquote(value.trim())?),
            "created" => {
                created = Some(
                    value
                        .trim()
                        .parse::<i64>()
                        .map_err(|_| "created parameter is not an integer.".to_string())?,
                )
            }
            _ => {} // ignore unknown params (e.g. expires, nonce)
        }
    }

    let keyid = keyid.ok_or_else(|| "Signature-Input is missing the 'keyid' parameter.".to_string())?;

    let signature = general_purpose::STANDARD
        .decode(strip_byte_sequence(&sig_value)?)
        .map_err(|error| format!("Signature is not valid base64: {}", error))?;

    Ok(ParsedSignature {
        label,
        components,
        params_raw,
        keyid,
        alg,
        created,
        signature,
    })
}

/// Verify a parsed signature against the device's ed25519 public key.
///
/// `public_key_base64` is the stored device key: the raw 32-byte ed25519
/// public key, base64 (standard) encoded. `max_age_secs`, when set, rejects
/// signatures whose `created` is older than the window or in the future.
pub fn verify_parsed(
    parsed: &ParsedSignature,
    public_key_base64: &str,
    ctx: Option<&RequestContext>,
    max_age_secs: Option<i64>,
) -> Result<(), String> {
    if let Some(alg) = &parsed.alg {
        if alg != "ed25519" {
            return Err(format!("Unsupported signature algorithm '{}'.", alg));
        }
    }

    if let Some(max_age) = max_age_secs {
        let created = parsed
            .created
            .ok_or_else(|| "Signature is missing 'created' but freshness is required.".to_string())?;
        let now = now_secs();
        if created > now + 5 {
            return Err("Signature 'created' is in the future.".to_string());
        }
        if now - created > max_age {
            return Err("Signature has expired.".to_string());
        }
    }

    let base = build_base(&parsed.components, &parsed.params_raw, ctx)?;

    let key_bytes = general_purpose::STANDARD
        .decode(public_key_base64.trim())
        .map_err(|error| format!("Device public key is not valid base64: {}", error))?;
    let key_array: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "Device public key is not a 32-byte ed25519 key.".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(&key_array)
        .map_err(|error| format!("Invalid ed25519 public key: {}", error))?;

    let sig_array: [u8; 64] = parsed
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| "Signature is not 64 bytes.".to_string())?;
    let signature = Signature::from_bytes(&sig_array);

    verifying_key
        .verify_strict(base.as_bytes(), &signature)
        .map_err(|_| "Signature verification failed.".to_string())
}

/// Build the RFC 9421 §2.5 signature base from the covered components.
fn build_base(
    components: &[String],
    params_raw: &str,
    ctx: Option<&RequestContext>,
) -> Result<String, String> {
    let mut lines: Vec<String> = Vec::new();

    for component in components {
        let value = match component.as_str() {
            "@method" => require_ctx(ctx)?.method.to_ascii_uppercase(),
            "@authority" => require_ctx(ctx)?.authority.to_ascii_lowercase(),
            "@path" => require_ctx(ctx)?.path.to_string(),
            "@query" => match require_ctx(ctx)?.query {
                Some(query) => format!("?{}", query),
                None => "?".to_string(),
            },
            "content-digest" => {
                let ctx = require_ctx(ctx)?;
                let digest = ctx.content_digest.ok_or_else(|| {
                    "Signature covers 'content-digest' but no Content-Digest header was provided."
                        .to_string()
                })?;
                if let Some(body) = ctx.body {
                    verify_content_digest(digest, body)?;
                }
                digest.trim().to_string()
            }
            other => {
                return Err(format!(
                    "Unsupported covered component '{}'.",
                    other
                ))
            }
        };
        lines.push(format!("\"{}\": {}", component, value));
    }

    lines.push(format!("\"@signature-params\": {}", params_raw));
    Ok(lines.join("\n"))
}

/// Recompute the SHA-256 `Content-Digest` (RFC 9530) over the body and compare.
fn verify_content_digest(header_value: &str, body: &[u8]) -> Result<(), String> {
    // Header value form: sha-256=:<base64>:  (a structured-field dictionary).
    let wanted = header_value
        .split(',')
        .filter_map(|entry| entry.trim().strip_prefix("sha-256="))
        .next()
        .ok_or_else(|| "Content-Digest does not contain a sha-256 entry.".to_string())?;
    let wanted_b64 = strip_byte_sequence(wanted.trim())?;

    let computed = general_purpose::STANDARD.encode(Sha256::digest(body));
    if computed != wanted_b64 {
        return Err("Content-Digest does not match the request body.".to_string());
    }
    Ok(())
}

fn require_ctx<'a>(ctx: Option<&'a RequestContext>) -> Result<&'a RequestContext<'a>, String> {
    ctx.ok_or_else(|| {
        "Signature covers request components but no request context was provided.".to_string()
    })
}

/// Split a single-member structured-field dictionary `label=value` into its
/// label and raw value.
fn split_label(input: &str) -> Result<(String, String), String> {
    let input = input.trim();
    let (label, value) = input
        .split_once('=')
        .ok_or_else(|| "Missing '=' in signature header.".to_string())?;
    Ok((label.trim().to_string(), value.trim().to_string()))
}

/// Strip the surrounding `:` of an sf byte-sequence, e.g. `:AbC=:` -> `AbC=`.
fn strip_byte_sequence(value: &str) -> Result<String, String> {
    let value = value.trim();
    value
        .strip_prefix(':')
        .and_then(|v| v.strip_suffix(':'))
        .map(|v| v.to_string())
        .ok_or_else(|| "Expected a byte sequence delimited by ':'.".to_string())
}

fn unquote(value: &str) -> Result<String, String> {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .map(|v| v.to_string())
        .ok_or_else(|| format!("Expected a quoted string, got '{}'.", value))
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn test_keys() -> (SigningKey, String) {
        let seed: [u8; 32] = [7u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let public_b64 = general_purpose::STANDARD.encode(signing_key.verifying_key().to_bytes());
        (signing_key, public_b64)
    }

    /// Sign `base` and return `(signature_input, signature)` header values.
    fn sign(signing_key: &SigningKey, components: &str, params_tail: &str, base_body: &str) -> (String, String) {
        let params_raw = format!("({}){}", components, params_tail);
        let base = if base_body.is_empty() {
            format!("\"@signature-params\": {}", params_raw)
        } else {
            format!("{}\n\"@signature-params\": {}", base_body, params_raw)
        };
        let signature = signing_key.sign(base.as_bytes());
        let sig_b64 = general_purpose::STANDARD.encode(signature.to_bytes());
        (
            format!("sig1={}", params_raw),
            format!("sig1=:{}:", sig_b64),
        )
    }

    fn digest_of(body: &[u8]) -> String {
        format!("sha-256=:{}:", general_purpose::STANDARD.encode(Sha256::digest(body)))
    }

    #[test]
    fn verifies_per_request_signature() {
        let (signing_key, public_b64) = test_keys();
        let body = b"{\"hello\":\"world\"}";
        let digest = digest_of(body);
        let created = now_secs();
        let base_body = format!(
            "\"@method\": POST\n\"@authority\": app.example.com\n\"@path\": /api/thing\n\"@query\": ?a=1\n\"content-digest\": {}",
            digest
        );
        let (input, sig) = sign(
            &signing_key,
            "\"@method\" \"@authority\" \"@path\" \"@query\" \"content-digest\"",
            &format!(";created={};keyid=\"dev123\";alg=\"ed25519\"", created),
            &base_body,
        );

        let parsed = parse(&input, &sig).expect("parse");
        assert_eq!(parsed.keyid, "dev123");
        let ctx = RequestContext {
            method: "POST",
            authority: "app.example.com",
            path: "/api/thing",
            query: Some("a=1"),
            content_digest: Some(&digest),
            body: Some(body),
        };
        verify_parsed(&parsed, &public_b64, Some(&ctx), Some(300)).expect("verify");
    }

    #[test]
    fn verifies_empty_component_cookie_credential() {
        let (signing_key, public_b64) = test_keys();
        let created = now_secs();
        let (input, sig) = sign(
            &signing_key,
            "",
            &format!(";created={};keyid=\"devCookie\";alg=\"ed25519\"", created),
            "",
        );
        let parsed = parse(&input, &sig).expect("parse");
        assert_eq!(parsed.keyid, "devCookie");
        assert!(parsed.components.is_empty());
        verify_parsed(&parsed, &public_b64, None, None).expect("verify cookie credential");
    }

    #[test]
    fn rejects_tampered_body() {
        let (signing_key, public_b64) = test_keys();
        let body = b"original";
        let digest = digest_of(body);
        let created = now_secs();
        let base_body = format!("\"content-digest\": {}", digest);
        let (input, sig) = sign(
            &signing_key,
            "\"content-digest\"",
            &format!(";created={};keyid=\"d\";alg=\"ed25519\"", created),
            &base_body,
        );
        let parsed = parse(&input, &sig).expect("parse");
        let ctx = RequestContext {
            method: "POST",
            authority: "app.example.com",
            path: "/",
            query: None,
            content_digest: Some(&digest),
            body: Some(b"tampered"),
        };
        let result = verify_parsed(&parsed, &public_b64, Some(&ctx), Some(300));
        assert!(result.is_err(), "tampered body must fail");
    }

    #[test]
    fn rejects_tampered_covered_component() {
        let (signing_key, public_b64) = test_keys();
        let created = now_secs();
        let base_body = "\"@path\": /allowed";
        let (input, sig) = sign(
            &signing_key,
            "\"@path\"",
            &format!(";created={};keyid=\"d\";alg=\"ed25519\"", created),
            base_body,
        );
        let parsed = parse(&input, &sig).expect("parse");
        let ctx = RequestContext {
            method: "GET",
            authority: "app.example.com",
            path: "/evil", // different path than what was signed
            query: None,
            content_digest: None,
            body: None,
        };
        assert!(verify_parsed(&parsed, &public_b64, Some(&ctx), Some(300)).is_err());
    }

    #[test]
    fn rejects_wrong_key() {
        let (signing_key, _public_b64) = test_keys();
        let other_public = general_purpose::STANDARD.encode(SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_bytes());
        let created = now_secs();
        let (input, sig) = sign(
            &signing_key,
            "",
            &format!(";created={};keyid=\"d\";alg=\"ed25519\"", created),
            "",
        );
        let parsed = parse(&input, &sig).expect("parse");
        assert!(verify_parsed(&parsed, &other_public, None, None).is_err());
    }

    /// Golden vector produced by the guard-npm JS signer
    /// (`http_signature.js::signRequestHeaders`). Locks in byte-for-byte
    /// agreement of the RFC 9421 signature base across the JS and Rust
    /// implementations. Freshness is disabled so the vector never expires.
    #[test]
    fn verifies_js_generated_vector() {
        let public_key = "Hsf20k+wDjudoE+wpyvaOy2th4r/w4iu2s6c9WuG3BI=";
        let input = r#"sig1=("@method" "@authority" "@path" "@query" "content-digest");created=1785916979;keyid="devXYZ";alg="ed25519""#;
        let signature = "sig1=:ckP1oeoSjeyB5EVOWRWCUtC4JQ6nvLxeQYTp7mLQSNhPo5L9IpR/IHF5aQ6sedwmQ9QJIg5TXP1H5KanHR9DDQ==:";
        let digest = "sha-256=:k6I5cakU5erL8KjSUVTNownDwccvu5kU1Hxg88toFYg=:";
        let body = b"{\"hello\":\"world\"}";

        let parsed = parse(input, signature).expect("parse js vector");
        assert_eq!(parsed.keyid, "devXYZ");
        let ctx = RequestContext {
            method: "POST",
            authority: "app.example.com",
            path: "/api/thing",
            query: Some("a=1&b=2"),
            content_digest: Some(digest),
            body: Some(body),
        };
        verify_parsed(&parsed, public_key, Some(&ctx), None).expect("verify js vector");
    }

    #[test]
    fn rejects_stale_created() {
        let (signing_key, public_b64) = test_keys();
        let created = now_secs() - 10_000;
        let (input, sig) = sign(
            &signing_key,
            "",
            &format!(";created={};keyid=\"d\";alg=\"ed25519\"", created),
            "",
        );
        let parsed = parse(&input, &sig).expect("parse");
        assert!(verify_parsed(&parsed, &public_b64, None, Some(300)).is_err());
    }
}
