//! Guard instance discovery and device-authentication launch.
//!
//! Flow:
//!   1. The user enters their email. We derive candidate domains from it
//!      (the full mail domain and its registrable root) and probe DNS for a
//!      `guard.<domain>` record — that subdomain points at the org's Guard
//!      instance. See [`discover_guard_instance`].
//!   2. We open the system browser at the instance's device-authentication page
//!      with a random `state`. See [`start_device_authentication`].
//!   3. The web page finishes auth and hands a one-time setup token back — via
//!      the loopback callback server (preferred) or the `guard://` deep link —
//!      which [`enroll_device`] exchanges for a device enrollment.

use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::SigningKey;
use serde::Serialize;
use tauri::{AppHandle, Manager};
use tauri_plugin_opener::OpenerExt;

use crate::callback_server::CallbackServer;

/// The `guard.<domain>` label we probe for. Change this if your convention
/// differs (e.g. a TXT record or a different subdomain).
const GUARD_SUBDOMAIN: &str = "guard";

/// OS keychain coordinates for the device's ed25519 signing key.
pub(crate) const KEYCHAIN_SERVICE: &str = "com.guard.desktop-client";
const KEYCHAIN_ACCOUNT: &str = "device-signing-key";

/// Load the device's ed25519 signing key from the OS keychain, creating and
/// persisting a new one on first use. The private key never leaves the device;
/// only its public key is registered with Guard.
pub(crate) fn load_or_create_signing_key() -> Result<SigningKey, String> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
        .map_err(|e| format!("Keychain unavailable: {e}"))?;

    match entry.get_password() {
        Ok(seed_b64) => {
            let seed = general_purpose::STANDARD
                .decode(seed_b64.trim())
                .map_err(|e| format!("Stored device key is not valid base64: {e}"))?;
            let seed: [u8; 32] = seed
                .as_slice()
                .try_into()
                .map_err(|_| "Stored device key has an unexpected length.".to_string())?;
            Ok(SigningKey::from_bytes(&seed))
        }
        Err(keyring::Error::NoEntry) => {
            let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
            let seed_b64 = general_purpose::STANDARD.encode(signing_key.to_bytes());
            entry
                .set_password(&seed_b64)
                .map_err(|e| format!("Could not store device key in keychain: {e}"))?;
            Ok(signing_key)
        }
        Err(e) => Err(format!("Keychain error: {e}")),
    }
}

/// Sign out: remove the device signing key from the keychain. The next sign-in
/// generates a fresh key and enrolls a new device.
#[tauri::command]
pub fn logout() -> Result<(), String> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
        .map_err(|e| format!("Keychain unavailable: {e}"))?;

    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()), // already signed out
        Err(e) => Err(format!("Could not remove device key: {e}")),
    }
}

#[derive(Serialize, Clone)]
pub struct GuardInstance {
    /// Hostname that resolved, e.g. `guard.example.com`.
    pub host: String,
    /// The email's mail domain, e.g. `mail.example.com`.
    pub email_domain: String,
}

#[derive(Serialize, Clone)]
pub struct DeviceAuthStart {
    /// Opaque value echoed back on the deep-link callback to prevent
    /// cross-session mix-ups.
    pub state: String,
    /// The URL that was opened in the browser.
    pub url: String,
}

/// Candidate base domains to probe, most-specific first:
/// `mail.example.com` then its registrable root `example.com`.
fn candidate_domains(email: &str) -> Result<Vec<String>, String> {
    let domain = email
        .split('@')
        .nth(1)
        .map(|d| d.trim().to_lowercase())
        .filter(|d| !d.is_empty() && d.contains('.'))
        .ok_or_else(|| "Enter a valid email address.".to_string())?;

    let mut domains = vec![domain.clone()];
    // Registrable domain via the Public Suffix List (handles multi-part TLDs
    // like example.co.uk correctly).
    if let Some(root) = psl::domain_str(&domain) {
        if root != domain {
            domains.push(root.to_string());
        }
    }
    Ok(domains)
}

/// Resolve the org's Guard instance by probing `guard.<domain>` for each
/// candidate domain. A CNAME or A record (anything that resolves to an IP)
/// counts as a hit.
#[tauri::command]
pub async fn discover_guard_instance(email: String) -> Result<GuardInstance, String> {
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use hickory_resolver::TokioAsyncResolver;

    let domains = candidate_domains(&email)?;
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    for base in &domains {
        let host = format!("{GUARD_SUBDOMAIN}.{base}");
        if let Ok(lookup) = resolver.lookup_ip(host.clone()).await {
            if lookup.iter().next().is_some() {
                return Ok(GuardInstance {
                    host,
                    email_domain: domains[0].clone(),
                });
            }
        }
    }

    let probed = domains
        .iter()
        .map(|d| format!("{GUARD_SUBDOMAIN}.{d}"))
        .collect::<Vec<_>>()
        .join(", ");
    Err(format!(
        "No Guard instance found for {}. Checked: {probed}.",
        domains[0]
    ))
}

/// Open the browser at the instance's device-authentication page and return the
/// `state` the caller should expect on the deep-link callback.
///
/// The public key is deliberately NOT sent here: an attacker who preset it in a
/// phishing URL could get their device enrolled under the victim. Instead the
/// page deep-links a one-time setup token back, which we exchange (with our own
/// public key) in [`enroll_device`].
#[tauri::command]
pub async fn start_device_authentication(
    app: AppHandle,
    page_host: String,
    api_host: String,
) -> Result<DeviceAuthStart, String> {
    let state = uuid::Uuid::new_v4().to_string();

    // Normally page_host == api_host (the instance serves both). In dev the
    // frontend can run on a separate host (e.g. a Next dev server) while the API
    // is elsewhere, so we pass the API base explicitly for the page to use.
    let api_base = format!("https://{api_host}/guard/api");

    // Prefer the loopback callback (works everywhere, including `tauri dev`); the
    // page redirects here on success. The `guard://` deep link stays as a
    // fallback when no callback is available.
    let mut params = vec![
        ("state", state.clone()),
        ("api", api_base.clone()),
    ];
    if let Some(server) = app.try_state::<CallbackServer>() {
        params.push(("callback", format!("http://127.0.0.1:{}/callback", server.port)));
    }

    let url = url::Url::parse_with_params(
        &format!("https://{page_host}/guard/frontend/device-authentication"),
        &params,
    )
    .map_err(|e| format!("Could not build authentication URL: {e}"))?
    .to_string();

    app.opener()
        .open_url(url.clone(), None::<&str>)
        .map_err(|e| format!("Could not open browser: {e}"))?;

    Ok(DeviceAuthStart { state, url })
}

#[derive(serde::Deserialize)]
struct EnrollResponse {
    device_id: Option<String>,
}

/// Flatten an error's source chain — reqwest's top-level message ("error sending
/// request for url …") hides the real cause (TLS, connection refused, etc.).
pub(crate) fn error_chain(err: impl std::error::Error) -> String {
    let mut message = err.to_string();
    let mut source = err.source();
    while let Some(inner) = source {
        message.push_str(&format!(": {inner}"));
        source = inner.source();
    }
    message
}

/// Exchange a one-time setup token (received via the deep-link callback) for a
/// device enrollment. We post OUR public key over our own connection, so the
/// key is never exposed to (or presettable by) the browser. The private key
/// stays in the keychain; Guard stores/verifies the raw 32-byte public key as
/// standard base64.
#[tauri::command]
pub async fn enroll_device(host: String, setup_token: String) -> Result<String, String> {
    let signing_key = load_or_create_signing_key()?;
    let public_key = general_purpose::STANDARD.encode(signing_key.verifying_key().to_bytes());

    let client = reqwest::Client::builder()
        // Dev instances use self-signed certs; accept them only in debug builds.
        .danger_accept_invalid_certs(cfg!(debug_assertions))
        .build()
        .map_err(|e| format!("Could not build HTTP client: {e}"))?;

    let response = client
        .post(format!("https://{host}/guard/api/auth/device/enroll"))
        .json(&serde_json::json!({ "setup_token": setup_token, "public_key": public_key }))
        .send()
        .await
        .map_err(|e| format!("Enrollment request failed: {}", error_chain(e)))?;

    if response.status().is_success() == false {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Enrollment failed ({status}): {body}"));
    }

    let parsed: EnrollResponse = response
        .json()
        .await
        .map_err(|e| format!("Invalid enrollment response: {e}"))?;

    parsed
        .device_id
        .ok_or_else(|| "Enrollment response did not include a device_id.".to_string())
}
